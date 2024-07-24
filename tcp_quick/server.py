import socket,re,asyncio
from abc import ABC,abstractmethod

class Server(ABC):
    """
    快速TCP服务端抽象类
    请注意需要实现 `_handle(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter)` 方法

    @param ip:监听的ip(虽然可以将域名解析为ip,但这并不是推荐的做法)
    @param port:监听的端口
    @param backlog:最大连接数
    @param reject:是否拒绝超出最大连接数的连接
    @param listen_keywords:是否监听键盘输入
    """

    def __init__(self,ip:str='0.0.0.0',port:int=10901,backlog:int=5,reject:bool=False,listen_keywords:bool=False)->None:
        self._listen_ip=self._validate_ip(ip)
        self._listen_port=self._validate_port(port)
        if backlog<=0:
            raise ValueError('最大连接数必须大于0')
        self._backlog=backlog
        self._reject=reject
        self._connected_clients=0
        self._writers=set()
        self._server=None
        self._shutdown_event=asyncio.Event()
        self._is_shutdown=False
        self._loop=asyncio.get_event_loop()
        # 启动异步任务以监听键盘输入
        if listen_keywords:
            self._loop.create_task(self._listen_keyboard_input())
        # 启动异步任务以启动服务器
        self._loop.run_until_complete(self._start_server())

    def _validate_ip(self,ip:str)->str:
        if re.match(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$',ip):
            return ip
        if re.match(r'^[a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)+$',ip):
            return socket.gethostbyname(ip)
        raise ValueError('IP地址不合法')

    def _validate_port(self,port:int)->int:
        if 1<=port<=65535:
            return port
        raise ValueError('端口号不合法')

    async def _start_server(self)->None:
        self._server=await asyncio.start_server(
            self._handle_client,
            self._listen_ip,
            self._listen_port,
            backlog=self._backlog
        )
        async with self._server:
            await self._shutdown_event.wait()  # 等待关闭事件触发
        await self._server.wait_closed()

    async def _handle_client(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter)->None:
        addr=writer.get_extra_info('peername')
        if self._connected_clients>=self._backlog:
            if self._reject:
                writer.close()
                await writer.wait_closed()
                return
            else:
                while self._connected_clients>=self._backlog:
                    await asyncio.sleep(0.1)
        self._connected_clients+=1
        self._writers.add(writer)
        try:
            await self._handle(reader,writer)
        except Exception as e:
            print(f'处理来自 {addr} 的连接时发生错误:{e}')
        finally:
            self._connected_clients-=1
            self._writers.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionResetError:
                pass

    async def get_all_connections(self)->list:
        """获取所有连接"""
        return list(self._writers)

    async def close(self,writer:asyncio.StreamWriter)->None:
        """关闭连接"""
        writer.close()
        await writer.wait_closed()

    async def close_all(self)->None:
        """关闭所有连接"""
        self._is_shutdown=True
        for writer in list(self._writers):
            await self.close(writer)
        self._writers.clear()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._shutdown_event.set()
    
    async def is_shutdown(self)->bool:
        """判断服务器是否已关闭"""
        return self._is_shutdown

    async def recv(self,reader:asyncio.StreamReader,byte:int=1024,timeout:int=0)->bytes:
        """接收数据"""
        try:
            if timeout:
                data=await asyncio.wait_for(reader.read(byte),timeout)
            else:
                data=await reader.read(byte)
        except asyncio.TimeoutError:
            raise TimeoutError('接收数据超时')
        if await self.is_shutdown():
            raise ConnectionError('服务器已关闭')
        return data

    async def send(self,writer:asyncio.StreamWriter,data:bytes)->None:
        """发送数据"""
        if await self.is_shutdown():
            raise ConnectionError('服务器已关闭')
        writer.write(data)
        await writer.drain()

    async def _list_connections(self)->None:
        """列出所有连接"""
        print(f"当前连接数: {len(await self.get_all_connections())}/{self._backlog}")
        for writer in await self.get_all_connections():
            addr=writer.get_extra_info('peername')
            print(f"连接: {addr}")
    
    async def _listen_keyboard_input(self)->None:
        """监听键盘输入"""
        while True:
            command=await asyncio.to_thread(input,"> ")
            if command.lower()=='help':
                print("list:列出所有连接")
                print("exit/quit:关闭服务器")
                print("backlog:修改最大连接数")
                print("reject:切换“超出最大连接数”模式")
            elif command.lower() in ['exit','quit']:
                await self.close_all()
                break
            elif command.lower()=='list':
                await self._list_connections()
            elif command.lower()=='backlog':
                backlog=int(await asyncio.to_thread(input,"请输入新的最大连接数:"))
                if backlog>0:
                    self._backlog=backlog
                    print(f"已将最大连接数设置为{backlog}")
                else:
                    print("最大连接数必顋大于0")
            elif command.lower()=='reject':
                self._reject=not self._reject
                print(f"已将“超出最大连接数”模式设置为{'拒绝' if self._reject else '阻塞'}")
            else:
                print("未知命令")

    @abstractmethod
    async def _handle(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter)->None:
        pass