import asyncio,re
from abc import ABC,abstractmethod
from .connect import Connect

class Client(ABC):
    """
    快速TCP客户端抽象类\n
    请注意需要实现 `_handle(self,connect:Connect)->None` 方法\n
    有效的`configs`配置项如下:\n
    `use_line`:
        是否使用行模式传输数据(仅支持以“\\n”,“\\r”或“\\r\\n”结尾的数据,开启后将自动在行尾添加“\\n”)\n
        行模式会在接收和发送数据时自动解析和转义`data`中的换行符,使用send_raw和recv_raw_line方法以发送和接收原始行数据

    @param host:服务端地址(主机名称或ip地址)
    @param port:服务端端口
    @param ssl:SSL/TLS上下文(默认为None,即不使用SSL/TLS)
    @param configs:配置项
    @param use_mcp:是否使用MCP协议(默认为自动,即根据SSL/TLS上下文是否存在来决定是否使用MCP协议)
    """

    def __init__(
            self,host:str='127.0.0.1',port:int=10901,configs:dict={},ssl=None,use_mcp=None
        )->None:
        self._validate_ip(host)
        self._validate_port(port)
        self._ip=host
        self._port=port
        self._configs=configs
        self._ssl=ssl
        if use_mcp is None:
            self._use_mcp=False if ssl else True
        else:
            self._use_mcp=use_mcp
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
            self._connect=Connect(reader,writer,self._use_mcp,self._configs)
            await self._connection_made(self.connect())
            await self._connect.initialize()
            await self._handle(self.connect())
        except Exception as e:
            await self._error(e)
        finally:
            if self._is_shutdown:
                self._is_shutdown=True
            await self._connection_closed(self.connect())

    def connect(self)->Connect:
        """获取连接对象"""
        return self._connect

    async def recv(self,timeout:int=0)->bytes:
        """接收数据"""
        data=await self.connect().recv(timeout)
        if self.is_shutdown():
            raise ConnectionError('已关闭连接')
        return data

    async def recv_raw(self,size:int,timeout:int=0)->bytes:
        """接收原始数据"""
        data=await self.connect().recv_raw(size,timeout)
        if self.is_shutdown():
            raise ConnectionError('已关闭连接')
        return data

    async def send(self,data:bytes,timeout:int=0)->None:
        """发送数据"""
        if self.is_shutdown():
            raise ConnectionError('已关闭连接')
        await self.connect().send(data,timeout)

    async def send_raw(self,data:bytes,timeout:int=0)->None:
        """发送原始数据"""
        if self.is_shutdown():
            raise ConnectionError('已关闭连接')
        await self.connect().send_raw(data,timeout)

    def is_shutdown(self)->bool:
        """判断服务器是否已关闭"""
        return self._is_shutdown

    async def close(self)->None:
        """关闭连接"""
        self._is_shutdown=True
        await self.connect().close()

    async def _connection_made(self,connect:Connect)->None:
        """连接已建立"""
        pass

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