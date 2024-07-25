import asyncio,socket,re
from abc import ABC,abstractmethod

class Client(ABC):
    """
    快速TCP客户端抽象类
    请注意需要实现 `_handle(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter)` 方法
    
    @param ip:服务端ip(虽然可以将域名解析为ip,但这并不是推荐的做法)
    @param port:服务端端口
    """

    def __init__(self,ip:str='127.0.0.1',port:int=10901)->None:
        """
        @param ip:服务端ip
        @param port:服务端端口
        """
        self._validate_ip(ip)
        self._validate_port(port)
        self._ip=ip
        self._port=port
        self._writer:asyncio.StreamWriter
        self._reader:asyncio.StreamReader
        self._is_shutdown=False
        self._loop=asyncio.get_event_loop()
        self._loop.run_until_complete(self._link())

    def _validate_ip(self,ip:str)->str:
        if re.match(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$',ip):
            return ip
        if ip=='localhost' or re.match(r'^[a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)+$',ip):
            return socket.gethostbyname(ip)
        raise ValueError('IP地址不合法')

    def _validate_port(self,port:int)->None:
        """校验端口号"""
        if not (1<=port<=65535):
            raise ValueError('端口号不合法')

    async def _link(self)->None:
        """连接服务端"""
        writer=None
        try:
            reader,writer=await asyncio.open_connection(self._ip,self._port)
            self._reader=reader
            self._writer=writer
            await self._handle(reader,writer)
        except Exception as e:
            await self._error(e)
        finally:
            if self._is_shutdown:
                self._is_shutdown=True
            if writer:
                writer.close()
                await writer.wait_closed()
    
    async def recv(self,byte:int=1024,timeout:int=0)->bytes:
        """接收数据"""
        try:
            if timeout:
                data=await asyncio.wait_for(self._reader.read(byte),timeout)
            else:
                data=await self._reader.read(byte)
        except asyncio.TimeoutError:
            raise TimeoutError('接收数据超时')
        if self.is_shutdown():
            raise ConnectionError('已关闭连接')
        return data

    async def send(self,data:bytes)->None:
        """发送数据"""
        if self.is_shutdown():
            raise ConnectionError('已关闭连接')
        self._writer.write(data)
        await self._writer.drain()
    
    def is_shutdown(self)->bool:
        """判断服务器是否已关闭"""
        return self._is_shutdown

    def close(self)->None:
        """关闭连接"""
        self._is_shutdown=True
        self._loop.stop()
    
    async def _error(self,e:Exception)->None:
        """处理错误"""
        print(f'发生错误:{e}')

    @abstractmethod
    async def _handle(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter)->None:
        """处理数据"""
        pass