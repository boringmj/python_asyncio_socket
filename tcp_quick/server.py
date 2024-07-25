import socket,re,asyncio
from abc import ABC,abstractmethod
from .key import Key
from .connect import Connect
from Crypto.PublicKey import RSA

class Server(ABC):
    """
    快速TCP服务端抽象类
    请注意需要实现 `_handle(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter)` 方法

    @param ip:监听的ip(虽然可以将域名解析为ip,但这并不是推荐的做法)(监听所有ip请使用: 0.0.0.0)
    @param port:监听的端口
    @param backlog:最大连接数(超出两倍后将无视reject参数并拒绝后续连接,直到连接数小于backlog的两倍)
    @param reject:是否拒绝超出最大连接数的连接(该配置受到backlog的影响)
    @param listen_keywords:是否监听键盘输入
    """

    def __init__(self,ip:str='0.0.0.0',port:int=10901,backlog:int=5,reject:bool=False,listen_keywords:bool=False)->None:
        try: 
            self._listen_ip=self._validate_ip(ip)
            self._listen_port=self._validate_port(port)
            if backlog<=0:
                raise ValueError('最大连接数必须大于0')
            self._backlog=backlog
            self._reject=reject
            self._connected_clients=0
            self._connect=set()
            self._server=None
            self._public_key:RSA.RsaKey
            self._private_key:RSA.RsaKey
            self._shutdown_event=asyncio.Event()
            self._is_shutdown=False
            self._loop=asyncio.get_event_loop()
            # 启动异步任务以监听键盘输入
            if listen_keywords:
                self._loop.create_task(self._listen_keyboard_input())
            # 启动异步任务以启动服务器
            self._loop.run_until_complete(self._start_server())
        except Exception as e:
            self._server_error(e)

    def _validate_ip(self,ip:str)->str:
        if re.match(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$',ip):
            return ip
        if ip=='localhost' or re.match(r'^[a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)+$',ip):
            return socket.gethostbyname(ip)
        raise ValueError('IP地址不合法')

    def _validate_port(self,port:int)->int:
        if 1<=port<=65535:
            return port
        raise ValueError('端口号不合法')

    async def _start_server(self)->None:
        """启动服务器"""
        # 初始化密钥
        self._public_key:RSA.RsaKey=await self.get_public_key()
        self._private_key:RSA.RsaKey=await self.get_private_key()
        # 监听连接
        self._server=await asyncio.start_server(
            self._handle_client,
            self._listen_ip,
            self._listen_port,
            backlog=self._backlog
        )
        async with self._server:
            await self._shutdown_event.wait()
        await self._server.wait_closed()

    async def _handle_client(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter)->None:
        connect=Connect(reader,writer)
        if self._connected_clients>=self._backlog:
            if self._reject and self._connected_clients>=self._backlog*2:
                await self._reject_client(connect)
                return
            else:
                while self._connected_clients>=self._backlog:
                    await asyncio.sleep(0.1)
        addr=connect.peername()
        self._connected_clients+=1
        connect.key_exchange_to_client(self._public_key,self._private_key)
        self._connect.add(connect)
        try:
            await self._handle(connect)
        except Exception as e:
            await self._error(addr,e)
        finally:
            self._connected_clients-=1
            self._connect.discard(connect)
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionResetError:
                pass

    async def get_all_connections(self)->list:
        """获取所有连接"""
        return list(self._connect)

    async def close(self,connect:Connect)->None:
        """关闭连接"""
        await connect.close()
        self._connect.discard(connect)

    async def close_all(self)->None:
        """关闭所有连接"""
        self._is_shutdown=True
        for connect in list(self._connect):
            await self.close(connect)
        self._connect.clear()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._shutdown_event.set()
    
    async def is_shutdown(self)->bool:
        """判断服务器是否已关闭"""
        return self._is_shutdown

    async def recv(self,connect:Connect,byte:int=1024,timeout:int=0)->bytes:
        """接收数据"""
        data=await connect.recv(byte,timeout)
        if await self.is_shutdown():
            raise ConnectionError('服务器已关闭')
        return data

    async def send(self,connect:Connect,data:bytes)->None:
        """发送数据"""
        if await self.is_shutdown():
            raise ConnectionError('服务器已关闭')
        await connect.send(data)
    
    async def sendall(self,data:bytes)->None:
        """向所有连接发送数据"""
        for connect in await self.get_all_connections():
            await self.send(connect,data)

    async def _list_connections(self)->None:
        """列出所有连接"""
        print(f"当前连接数: {len(await self.get_all_connections())}/{self._backlog}")
        for connect in await self.get_all_connections():
            addr=connect.peername()
            print(f"连接: {addr}")
    
    async def _listen_keyboard_input(self)->None:
        """监听键盘输入"""
        print("控制台已启动,请输入help查看帮助")
        while True:
            command=await asyncio.to_thread(input,"> ")
            if command.lower()=='help':
                print("list:列出所有连接")
                print("exit/quit/stop:关闭服务器")
                print("backlog:修改最大连接数")
                print("reject:切换“超出最大连接数”模式")
                print("public_key:查看RSA公钥")
                print("private_key:查看RSA私钥")
            elif command.lower() in ['exit','quit','stop']:
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
                print(f"从下一次开始连接的“超出最大连接数”模式设置为{'拒绝' if self._reject else '阻塞'}")
            elif command.lower()=='public_key':
                print(self._public_key.export_key().decode())
            elif command.lower()=='private_key':
                print(self._private_key.export_key().decode())
            else:
                print("未知命令,请输入help查看帮助")
    
    async def _reject_client(self,connect:Connect)->None:
        """拒绝连接"""
        await self.send(connect,b'Connection refused')
        await self.close(connect)
    
    async def _error(self,addr,error:Exception)->None:
        """连接出现错误"""
        print(f'来自 {addr} 的连接出现错误:{error}')
    
    def _server_error(self,error:Exception)->None:
        """服务器出现错误"""
        print(f'服务器出现错误:{error}')
    
    async def get_public_key(self)->RSA.RsaKey:
        """获取RSA公钥"""
        key_public_path='key/public.pem'
        key_private_path='key/private.pem'
        # 判断公钥是否存在
        if not Key.exists_key(key_public_path):
            # 生成RSA密钥对
            Key.create_rsa_key(key_public_path,key_private_path)
        return Key.get_rsa_public_key(key_public_path)
    
    async def get_private_key(self)->RSA.RsaKey:
        """获取RSA私钥"""
        key_public_path='key/public.pem'
        key_private_path='key/private.pem'
        # 判断私钥是否存在
        if not Key.exists_key(key_private_path):
            # 生成RSA密钥对
            Key.create_rsa_key(key_public_path,key_private_path)
        return Key.get_rsa_private_key(key_private_path)

    @abstractmethod
    async def _handle(self,connect:Connect)->None:
        """处理连接"""
        pass