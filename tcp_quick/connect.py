import asyncio
from Crypto.PublicKey import RSA

class Connect:
    """
    连接管理类
    """

    def __init__(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter):
        self._reader=reader
        self._writer=writer
        self._peername=writer.get_extra_info('peername')
    
    def peername(self)->str:
        """获取对端地址"""
        return self._peername
    
    def reader(self)->asyncio.StreamReader:
        """获取StreamReader"""
        return self._reader
    
    def writer(self)->asyncio.StreamWriter:
        """获取StreamWriter"""
        return self._writer

    def key_exchange_to_client(self,public_key:RSA.RsaKey,private_key:RSA.RsaKey)->None:
        """
        与客户端进行密钥交换
        :param public_key:RSA公钥
        :param private_key:RSA私钥
        """
        pass

    def key_exchange_to_server(self,aes_key:bytes,aes_iv:bytes)->None:
        """
        与服务器进行密钥交换
        :param aes_key:AES密钥
        :param aes_iv:AES向量
        """
        pass

    async def recv(self,byte:int=1024,timeout:int=0)->bytes:
        """接收数据"""
        reader=self.reader()
        try:
            if timeout:
                data=await asyncio.wait_for(reader.read(byte),timeout)
            else:
                data=await reader.read(byte)
        except asyncio.TimeoutError:
            raise TimeoutError('接收数据超时')
        return data

    async def send(self,data:bytes)->None:
        """发送数据"""
        writer=self.writer()
        writer.write(data)
        await writer.drain()
    
    async def close(self)->None:
        """关闭连接"""
        writer=self.writer()
        writer.close()
        await writer.wait_closed()