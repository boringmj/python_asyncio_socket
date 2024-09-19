import asyncio,re
from abc import ABC,abstractmethod
from .connect import Connect

class Client(ABC):
    """
    快速TCP客户端抽象类
    请注意需要实现 `_handle(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter)` 方法
    
    @param host:服务端地址(主机名称或ip地址)
    @param port:服务端端口
    @param use_line:是否使用行模式传输数据(仅支持以“\\n”,“\\r”或“\\r\\n”结尾的数据,开启后将自动在行尾添加“\\n”)
    @param ssl:SSL/TLS上下文(默认为None,即不使用SSL/TLS)
    @param use_aes:是否使用AES加密传输数据(默认为自动,即根据SSL/TLS上下文是否存在来决定是否使用AES加密)
    """

    def __init__(
            self,host:str='127.0.0.1',port:int=10901,use_line:bool=False,
            ssl=None,use_aes=None
        )->None:
        self._validate_ip(host)
        self._validate_port(port)
        self._ip=host
        self._port=port
        self._use_line=use_line
        self._ssl=ssl
        if use_aes is None:
            self._use_aes=False if ssl else True
        else:
            self._use_aes=use_aes
        self._connect:Connect
        self._is_shutdown=False

    def run(self)->None:
        """运行客户端"""
        try:
            asyncio.run(self._link())
        except KeyboardInterrupt:
            pass

    def _validate_ip(self,ip:str)->str:
        if re.match(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$',ip):
            return ip
        if ip=='localhost' or re.match(r'^[a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)+$',ip):
            # return socket.gethostbyname(ip)
            return ip
        raise ValueError('IP地址不合法')

    def _validate_port(self,port:int)->None:
        """校验端口号"""
        if not (1<=port<=65535):
            raise ValueError('端口号不合法')

    async def _link(self)->None:
        """连接服务端"""
        writer=None
        try:
            reader,writer=await asyncio.open_connection(self._ip,self._port,ssl=self._ssl)
            self._connect=Connect(reader,writer,self._use_aes)
            if self._use_line:
                self._connect.use_line()
            if self._use_aes:
                await self.key_exchange_to_server(self._connect)
            await self._handle(self.connect())
        except Exception as e:
            await self._error(e)
        finally:
            if self._is_shutdown:
                self._is_shutdown=True
                await self._connection_closed(self.connect())

    async def key_exchange_to_server(self,connect:Connect)->None:
        """与服务端进行密钥交换"""
        await connect.key_exchange_to_server()

    def connect(self)->Connect:
        """获取连接"""
        return self._connect

    async def recv(self,timeout:int=0)->bytes:
        """接收数据"""
        data=await self.connect().recv(timeout)
        if self.is_shutdown():
            raise ConnectionError('已关闭连接')
        return data

    async def send(self,data:bytes,timeout:int=0)->None:
        """发送数据"""
        if self.is_shutdown():
            raise ConnectionError('已关闭连接')
        await self.connect().send(data,timeout)

    def is_shutdown(self)->bool:
        """判断服务器是否已关闭"""
        return self._is_shutdown

    async def close(self)->None:
        """关闭连接"""
        self._is_shutdown=True
        await self.connect().close()

    async def _error(self,e:Exception)->None:
        """处理错误"""
        print(f'发生错误: {e}')

    async def _connection_closed(self,connect:Connect)->None:
        """连接被关闭"""
        await connect.close()

    @abstractmethod
    async def _handle(self,connect:Connect)->None:
        """处理连接"""
        pass