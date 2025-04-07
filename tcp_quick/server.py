import re,asyncio
from abc import ABC,abstractmethod
from typing import Set,Optional
from .connect import Connect

class Server(ABC):
    """
    快速TCP服务端抽象类\n
    请注意需要实现 `_handle(self,connect:Connect)->None` 方法\n
    有效的`configs`配置项如下:\n
    `use_line`:
        是否使用行模式传输数据(仅支持以“\\n”,“\\r”或“\\r\\n”结尾的数据,开启后将自动在行尾添加“\\n”)\n
        行模式会在接收和发送数据时自动解析和转义`data`中的换行符,使用send_raw和recv_raw_line方法以发送和接收原始行数据

    @param host:监听地址(监听所有地址请使用: 0.0.0.0)
    @param port:监听端口
    @param backlog:最大处理的连接数
    @param reject:是否拒绝超出最大处理连接数的连接
    @param listen_keywords:是否监听键盘输入
    @param configs:配置项
    @param ssl:SSL/TLS上下文(默认为None,即不使用SSL/TLS)
    @param use_mcp:是否使用MCP协议(默认为自动,即根据SSL/TLS上下文是否存在来决定是否使用MCP协议)
    @param limit:限制每个连接默认的缓冲区大小(默认为65536字节,即64KiB)
    """

    def __init__(
        self,
        host:str='0.0.0.0',
        port:int=10901,
        backlog:int=5,
        reject:bool=False,
        listen_keywords:bool=False,
        configs:dict={},
        ssl=None,
        use_mcp:Optional[bool]=None,
        limit:int=65536
    )->None:
        self._listen_ip=self._validate_ip(host)
        self._listen_port=self._validate_port(port)
        if backlog<=0:
            raise ValueError('最大连接数必须大于0')
        self._backlog=backlog
        self._limit=limit
        self._reject=reject
        # 在配置项中添加服务器标识
        configs['server']=True
        self._configs=configs
        self._ssl=ssl
        self._use_mcp=False if ssl else True if use_mcp is None else use_mcp
        self._connected_clients=0
        self._queue_clients=0
        self._connect:Set[Connect]=set()
        self._queue_connect:Set[Connect]=set()
        self._server:Optional[asyncio.Server]=None
        self._shutdown_event=asyncio.Event()
        self._listen_keyboard_event=asyncio.Event()
        self._is_shutdown=False
        self._listen_keyboard=listen_keywords
        self._backlog_condition=asyncio.Condition()

    async def _run_tasks(self):
        """运行并行任务"""
        tasks=[self._start_server()]
        if self._listen_keyboard:
            tasks.append(self._listen_keyboard_input())
        await asyncio.gather(*tasks)

    def run(self):
        """运行服务器"""
        try:
            asyncio.run(self._run_tasks())
        except Exception as e:
            self._server_error(e)

    def _validate_ip(self,ip:str)->str:
        if re.match(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$',ip):
            return ip
        if ip=='localhost' or re.match(r'^[a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)+$',ip):
            return ip
        raise ValueError('IP地址不合法')

    def _validate_port(self,port:int)->int:
        if 1<=port<=65535:
            return port
        raise ValueError('端口号不合法')

    async def _start_server(self)->None:
        """启动服务器"""
        # 监听连接
        self._server=await asyncio.start_server(
            self._handle_client,
            self._listen_ip,
            self._listen_port,
            limit=self._limit,
            ssl=self._ssl
        )
        self._listen_keyboard_event.set()
        async with self._server:
            await self._shutdown_event.wait()
        await self._server.wait_closed()

    async def _handle_client(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter)->None:
        addr=writer.get_extra_info('peername')
        connect=None
        try:
            connect=Connect(reader,writer,use_mcp=self._use_mcp,configs=self._configs.copy())
            # 排队逻辑
            if self._reject:
                async with self._backlog_condition:
                    if self._connected_clients>=self._backlog:
                        await self._reject_client(connect)
                        return
            else:
                async with self._backlog_condition:
                    if self._connected_clients>=self._backlog:
                        self._queue_clients+=1
                        self._queue_connect.add(connect)
                        try:
                            # 等待条件满足: 连接数小于 backlog 或服务器关闭
                            await self._backlog_condition.wait_for(
                                lambda: self._connected_clients<self._backlog or self._is_shutdown
                            )
                        finally:
                            self._queue_clients-=1
                            self._queue_connect.discard(connect)
                        if self._is_shutdown:
                            await connect.close()
                            return
            # 正式处理连接
            async with self._backlog_condition:
                if self._connected_clients>=self._backlog:
                    await self._reject_client(connect)
                    return
                self._connected_clients+=1
                self._connect.add(connect)
                await connect.initialize()
            await self._connection_made(addr,connect)
            await self._handle(connect)
        except Exception as e:
            await self._error(addr,e)
        finally:
            if connect:
                async with self._backlog_condition:
                    self._connected_clients-=1
                    self._connect.discard(connect)
                    # 通知等待的任务，连接已释放
                    self._backlog_condition.notify()
                await self._connection_closed(addr,connect)

    def get_all_connections(self)->list:
        """获取所有连接"""
        return list(self._connect)

    async def get_queue_connections(self)->list:
        """获取排队中的连接"""
        return list(self._queue_connect)

    async def close(self,connect:Connect)->None:
        """关闭连接"""
        await connect.close()
        self._connect.discard(connect)

    async def close_all(self)->None:
        """关闭所有连接"""
        self._is_shutdown=True
        async with self._backlog_condition:
            self._backlog_condition.notify_all()
        for connect in self.get_all_connections():
            await connect.close()
        for connect in await self.get_queue_connections():
            await connect.close()
        self._connect.clear()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._shutdown_event.set()

    async def is_shutdown(self)->bool:
        """判断服务器是否已关闭"""
        return self._is_shutdown

    async def recv(self,connect:Connect,timeout:int=0)->bytes:
        """接收数据"""
        data=await connect.recv(timeout)
        if await self.is_shutdown():
            raise ConnectionError('服务器已关闭')
        return data

    async def recv_raw(self,connect:Connect,size:int,timeout:int=0)->bytes:
        """接收原始数据"""
        data=await connect.recv_raw(size,timeout)
        if await self.is_shutdown():
            raise ConnectionError('服务器已关闭')
        return data

    async def recv_raw_line(self,connect:Connect,timeout:int=0)->bytes:
        """接收原始行数据"""
        data=await connect.recv_raw_line(timeout)
        if await self.is_shutdown():
            raise ConnectionError('服务器已关闭')
        return data

    async def send(self,connect:Connect,data:bytes,timeout:int=0)->None:
        """发送数据"""
        if await self.is_shutdown():
            raise ConnectionError('服务器已关闭')
        await connect.send(data,timeout)

    async def send_raw(self,connect:Connect,data:bytes,timeout:int=0)->None:
        """发送原始数据"""
        if await self.is_shutdown():
            raise ConnectionError('服务器已关闭')
        await connect.send_raw(data,timeout)

    async def sendall(self,data:bytes,timeout:int=0)->list:
        """
        向所有连接发送数据

        @param data:要发送的数据
        @param timeout:单个任务的超时时间
        @return:返回一个列表,列表中的元素为每个任务的返回结果和异常
        """
        tasks=[connect.send(data,timeout) for connect in self.get_all_connections()]
        return await asyncio.gather(*tasks,return_exceptions=True)

    async def sendall_raw(self,data:bytes,timeout:int=0)->list:
        """
        向所有连接发送原始数据

        @param data:要发送的数据
        @param timeout:单个任务的超时时间
        @return:返回一个列表,列表中的元素为每个任务的返回结果和异常
        """
        tasks=[connect.send_raw(data,timeout) for connect in self.get_all_connections()]
        return await asyncio.gather(*tasks,return_exceptions=True)

    async def _list_connections(self)->None:
        """列出所有连接"""
        print(f"当前连接数: {len(self.get_all_connections())}/{self._backlog}")
        for connect in self.get_all_connections():
            addr=connect.peername()
            print(f"连接: {addr}")
        if self._queue_clients>0:
            print(f"排队中的连接数: {self._queue_clients}")
            for connect in await self.get_queue_connections():
                addr=connect.peername()
                print(f"排队中的连接: {addr}")

    async def _listen_keyboard_input(self)->None:
        """监听键盘输入"""
        await self._listen_keyboard_event.wait()
        print("控制台已启动,请输入help查看帮助")
        while True:
            loop=asyncio.get_running_loop()
            command=await loop.run_in_executor(None,input,"> ")
            # 如果您的Python版本不低于3.9,可以考虑使用下面的代码
            # command=await asyncio.to_thread(input,"> ")
            if command.lower()=='help':
                print("list:列出所有连接")
                print("exit/quit/stop:关闭服务器")
                print("backlog:修改最大连接数")
                print("reject:切换“超出最大连接数”模式")
            elif command.lower() in ['exit','quit','stop']:
                await self.close_all()
                break
            elif command.lower()=='list':
                await self._list_connections()
            elif command.lower()=='backlog':
                backlog=int(await loop.run_in_executor(None,input,"请输入新的最大连接数:"))
                 # 如果您的Python版本不低于3.9,可以考虑使用下面的代码
                # backlog=int(await asyncio.to_thread(input,"请输入新的最大连接数:"))
                if backlog>0:
                    self._backlog=backlog
                    print(f"已将最大连接数设置为{backlog}")
                else:
                    print("最大连接数必须大于0")
            elif command.lower()=='reject':
                self._reject=not self._reject
                print(f"从下一次开始连接的“超出最大连接数”模式设置为{'拒绝' if self._reject else '阻塞'}")
            else:
                print("未知命令,请输入help查看帮助")

    async def _reject_client(self,connect:Connect)->None:
        """连接超出最大连接数被拒绝时的连接处理"""
        await connect.close()

    async def _connection_made(self,addr,connect:Connect)->None:
        """成功连接时的处理"""
        pass

    async def _connection_closed(self,addr,connect:Connect)->None:
        """成功连接的连接被关闭时的处理(无论是正常关闭还是异常关闭)"""
        await connect.close()

    async def _queue_error(self,connect:Connect,error:Exception)->None:
        """处理排队中的连接出现错误"""
        addr=connect.peername()
        print(f'排队中的连接 {addr} 出现错误: {error}')

    async def _error(self,addr,error:Exception)->None:
        """连接出现错误"""
        print(f'来自 {addr} 的连接出现错误: {error}')

    def _server_error(self,error:Exception)->None:
        """服务器出现错误"""
        print(f'服务器出现错误: {error}')

    @abstractmethod
    async def _handle(self,connect:Connect)->None:
        """处理连接"""
        pass