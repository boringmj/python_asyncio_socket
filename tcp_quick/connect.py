import asyncio,socket,hashlib
from .key import Key
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES

class Connect:
    """
    连接管理类

    注意: 如果你不希望每次连接都生成新的RSA密钥对,请重写get_public_key和get_private_key方法
    """
    _public_key:RSA.RsaKey
    _private_key:RSA.RsaKey


    def __init__(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter):
        self._reader=reader
        self._writer=writer
        self._peername=writer.get_extra_info('peername')
        sock=writer.get_extra_info('socket')
        self._recv_buffer_size=sock.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
        self._send_buffer_size=sock.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF)
        self._aes_key:bytes=b''
        self._iv:bytes=b''
    
    def peername(self)->str:
        """获取对端地址"""
        return self._peername
    
    def reader(self)->asyncio.StreamReader:
        """获取StreamReader"""
        return self._reader
    
    def writer(self)->asyncio.StreamWriter:
        """获取StreamWriter"""
        return self._writer

    async def key_exchange_to_client(self)->None:
        """
        与客户端进行密钥交换
        """
        public_key=await Connect.get_public_key()
        public_key=public_key.export_key()
        await self._send(public_key)
        public_key_fingerprint=hashlib.sha256(public_key).hexdigest()
        print(f'向 {self.peername()} 发送公钥\n{public_key.decode()}\n指纹:{public_key_fingerprint}')
        data=await self._recv(120)
        private_key=await Connect.get_private_key()
        cipher=PKCS1_OAEP.new(private_key)
        data=cipher.decrypt(data)
        aes_key_length=int(data[:3].decode(),16)
        iv_length=int(data[3:6].decode(),16)
        aes_key=data[6:6+aes_key_length]
        iv=data[6+aes_key_length:6+aes_key_length+iv_length]
        self._aes_key=aes_key
        self._iv=iv
        # 将公钥通过AES加密后发送给客户端
        await self.send(public_key)

    async def key_exchange_to_server(self)->None:
        """
        与服务器进行密钥交换
        """
        data=await self._recv(120)
        public_key=RSA.import_key(data)
        public_key_fingerprint=hashlib.sha256(data).hexdigest()
        print(f'接收到服务器公钥\n{data.decode()}\n指纹:{public_key_fingerprint}')
        aes_key=Key.create_aes_key(16)
        iv=Key.rand_iv(16)
        cipher=PKCS1_OAEP.new(public_key)
        aes_key_length=hex(len(aes_key))[2:].zfill(3).encode()
        iv_length=hex(len(iv))[2:].zfill(3).encode()
        data=aes_key_length+iv_length+aes_key+iv
        data=cipher.encrypt(data)
        await self._send(data)
        self._aes_key=aes_key
        self._iv=iv
        data=await self._recv(120)
        cipher=AES.new(aes_key,AES.MODE_EAX,iv)
        public_key_aes=cipher.decrypt(data)
        if public_key_aes!=public_key.export_key():
            raise ValueError('密钥交换失败: 认证失败')

    async def recv(self,timeout:int=0)->bytes:
        """接收数据"""
        data=await self._recv(timeout)
        cipher=AES.new(self._aes_key,AES.MODE_EAX,self._iv)
        data=cipher.decrypt(data)
        return data

    async def _recv(self,timeout:int=0)->bytes:
        """底层接收数据"""
        reader=self.reader()
        try:
            if timeout:
                start_time=asyncio.get_event_loop().time()
                data=await asyncio.wait_for(reader.read(16),timeout)
                timeout-=int(asyncio.get_event_loop().time()-start_time)
                if timeout<=0:
                    raise asyncio.TimeoutError
            else:
                data=await reader.read(16)
            if data[:8]!=b'MCP-TCP0':
                raise ValueError('响应异常')
            data_len=int(data[8:16].decode(),16)
            if data_len<=0 or data_len>0x7fffffff:
                raise ValueError('数据长度不合法')
            data=await self.recv_raw(data_len,timeout)
            if len(data)!=data_len:
                raise ValueError('数据异常')
        except asyncio.TimeoutError:
            raise TimeoutError('接收数据超时')
        return data
    
    async def recv_raw(self,byte:int,timeout:int=0)->bytes:
        """接收原始数据"""
        reader=self.reader()
        fill_byte=False
        data=b''
        try:
            while byte>0:
                temp=b''
                read_size=max(min(byte,self._recv_buffer_size),0)
                if timeout:
                    start_time=asyncio.get_event_loop().time()
                    temp=await asyncio.wait_for(reader.read(read_size),max(0,timeout))
                    timeout-=int(asyncio.get_event_loop().time()-start_time)
                    if timeout<=0:
                        raise asyncio.TimeoutError
                else:
                    temp=await reader.read(read_size)
                data+=temp
                temp_len=len(temp)
                if temp_len<=read_size and not fill_byte:
                    byte+=read_size-temp_len
                    fill_byte=True
                byte-=read_size
        except asyncio.TimeoutError:
            raise TimeoutError('接收数据超时')
        return data

    async def send(self,data:bytes)->None:
        """发送数据"""
        cipher=AES.new(self._aes_key,AES.MODE_EAX,self._iv)
        data=cipher.encrypt(data)
        await self._send(data)
    
    async def _send(self,data:bytes)->None:
        """底层发送数据"""
        data_len=len(data)
        if data_len<=0 or data_len>0x7fffffff:
            raise ValueError('数据长度不合法')
        data_len=hex(data_len)[2:]
        data_len=data_len.zfill(8)
        data=b'MCP-TCP0'+data_len.encode()+data
        await self.send_raw(data)
    
    async def send_raw(self,data:bytes)->None:
        """发送原始数据"""
        writer=self.writer()
        while data:
            write_size=max(min(len(data),self._send_buffer_size),0)
            writer.write(data[:write_size])
            data=data[write_size:]
        await writer.drain()
    
    async def close(self)->None:
        """关闭连接"""
        writer=self.writer()
        writer.close()
        await writer.wait_closed()
    
    @staticmethod
    async def get_public_key()->RSA.RsaKey:
        """获取RSA公钥"""
        if hasattr(Connect,'_public_key'):
            return Connect._public_key
        public_key,private_key=Key.create_rsa_key(1024)
        Connect._public_key=public_key
        Connect._private_key=private_key
        return public_key
    
    @staticmethod
    async def get_private_key()->RSA.RsaKey:
        """获取RSA私钥"""
        if hasattr(Connect,'_private_key'):
            return Connect._private_key
        public_key,private_key=Key.create_rsa_key(1024)
        Connect._public_key=public_key
        Connect._private_key=private_key
        return private_key