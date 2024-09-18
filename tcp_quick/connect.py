import asyncio,socket,hashlib
# import ast
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
    _trust_public_key:list

    def __init__(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter,use_aes:bool=False):
        self._reader=reader
        self._writer=writer
        self._use_aes=use_aes
        self._peername=writer.get_extra_info('peername')
        sock:socket.socket=writer.get_extra_info('socket')
        self._recv_buffer_size=sock.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
        self._send_buffer_size=sock.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF)
        self._aes_key:bytes=b''
        self._use_line=False

    def use_line(self,use_line:bool=True)->'Connect':
        """设置是否使用行模式"""
        self._use_line=use_line
        return self

    def peername(self)->str:
        """获取对端地址"""
        return self._peername

    def reader(self)->asyncio.StreamReader:
        """获取StreamReader"""
        return self._reader

    def writer(self)->asyncio.StreamWriter:
        """获取StreamWriter"""
        return self._writer

    def set_aes_key(self,aes_key:bytes)->None:
        """设置AES密钥"""
        self._aes_key=aes_key

    async def key_exchange_to_client(self)->None:
        """
        与客户端进行密钥交换
        """
        public_key=await Connect.get_public_key()
        public_key=public_key.export_key()
        public_key_fingerprint=hashlib.sha256(public_key).hexdigest()
        print(f'向 {self.peername()} 发送公钥\n{public_key.decode()}\n指纹:{public_key_fingerprint}')
        await self._send(public_key,120)
        pack=await self._recv(120)
        sign=pack[:32]
        private_key=await Connect.get_private_key()
        cipher=PKCS1_OAEP.new(private_key)
        data=cipher.decrypt(pack[32:])
        aes_key_length_hex=data[:3]
        aes_key_length=int(aes_key_length_hex.decode(),16)
        aes_key=data[3:3+aes_key_length]
        random_bytes=data[3+aes_key_length:]
        pack=aes_key_length_hex+aes_key+random_bytes
        if hashlib.sha256(pack).digest()!=sign:
            raise ValueError('秘钥交换失败')
        self.set_aes_key(aes_key)
        await self.send(random_bytes,120)

    async def key_exchange_to_server(self,aes_key_length:int=16)->None:
        """
        与服务器进行密钥交换
        """
        public_key_text=(await self._recv(120)).decode()
        public_key=RSA.import_key(public_key_text)
        public_key_fingerprint=hashlib.sha256(public_key_text.encode()).hexdigest()
        print(f'接收到服务器公钥\n{public_key_text}\n指纹:{public_key_fingerprint}')
        if public_key_text not in await Connect.get_trust_public_key():
            input_data=input('该公钥来源未知,请确认是否信任该公钥(y/N):')
            if input_data.lower()=='y':
                await Connect.save_trust_public_key(public_key_text)
            else:
                raise ValueError('公钥认证失败')
        aes_key=Key.create_aes_key(aes_key_length)
        cipher=PKCS1_OAEP.new(public_key)
        aes_key_length_hex=hex(len(aes_key))[2:].zfill(3).encode()
        random_bytes=Key.rand_bytes(32)
        pack=aes_key_length_hex+aes_key+random_bytes
        sign=hashlib.sha256(pack).digest()
        pack=cipher.encrypt(pack)
        await self._send(sign+pack,120)
        self.set_aes_key(aes_key)
        try:
            server_random_bytes=await self.recv(120)
            if server_random_bytes!=random_bytes:
                raise ValueError('秘钥交换失败')
        except ValueError:
            raise ValueError('秘钥交换失败')

    async def recv(self,timeout:int=0)->bytes:
        """接收数据"""
        data=await self._recv(timeout)
        if not self._use_aes:
            return data
        if len(data)<32:
            raise ValueError('数据异常')
        iv=data[:16]
        tag=data[16:32]
        data=data[32:]
        cipher=AES.new(self._aes_key,AES.MODE_EAX,iv)
        try:
            data=cipher.decrypt_and_verify(data,tag)
        except ValueError:
            raise ValueError('数据异常')
        return data

    async def _recv(self,timeout:int=0)->bytes:
        """底层接收数据"""
        reader=self.reader()
        if self._use_line:
            data=await self.recv_raw_line(timeout)
            # 将data中的“-MCP0-EOL-”替换为换行符
            data=data.replace(b'-MCP0-EOL0-',b'\r\n').replace(b'-MCP0-EOL1-',b'\n').replace(b'-MCP0-EOL2-',b'\r')
            # 下面这种方法会大量替换字符,效率较低以及在某些情况下大幅度增加数据长度
            # data=ast.literal_eval(data.decode())
        else:
            try:
                if timeout:
                    start_time=asyncio.get_event_loop().time()
                    data=await asyncio.wait_for(reader.read(16),max(0,timeout))
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
        fill_byte=0
        data=b''
        try:
            while byte>0:
                temp=b''
                # read_size=min(byte,self._recv_buffer_size)
                # 下面的代码实测效率更高
                read_size=byte if byte<self._recv_buffer_size else self._recv_buffer_size
                if timeout:
                    start_time=asyncio.get_event_loop().time()
                    temp=await asyncio.wait_for(reader.read(read_size),max(0,timeout))
                    timeout-=int(asyncio.get_event_loop().time()-start_time)
                    if timeout<=0:
                        raise asyncio.TimeoutError
                else:
                    temp=await reader.read(read_size)
                if not temp:
                    break
                temp_len=len(temp)
                if temp_len<=read_size and fill_byte<16:
                    fill_byte+=1
                byte-=temp_len
                data+=temp
        except asyncio.TimeoutError:
            raise TimeoutError('接收数据超时')
        return data

    async def recv_raw_line(self,timeout:int=0)->bytes:
        """接收原始行数据"""
        reader=self.reader()
        try:
            if timeout:
                try:
                    data=await asyncio.wait_for(reader.readline(),max(0,timeout))
                except asyncio.TimeoutError:
                    raise TimeoutError('接收数据超时')
            else:
                data=await reader.readline()
        except ValueError as e:
            raise ValueError(f'行数据异常: {e}')
        if data.endswith(b'\r\n'):
            data=data.rstrip(b'\r\n')
        elif data.endswith(b'\n'):
            data=data.rstrip(b'\n')
        elif data.endswith(b'\r'):
            data=data.rstrip(b'\r')
        else:
            raise ValueError('行数据异常')
        return data

    async def send(self,data:bytes,timeout:int=0)->None:
        """发送数据"""
        if self._use_aes:
            iv=Key.rand_iv(16)
            cipher=AES.new(self._aes_key,AES.MODE_EAX,iv)
            ciphertext,tag=cipher.encrypt_and_digest(data)
            data=iv+tag+ciphertext
        await self._send(data,timeout)

    async def _send(self,data:bytes,timeout:int=0)->None:
        """底层发送数据"""
        if self._use_line:
            # 将data中的换行符替换为“-MCP0-EOL-”
            data=data.replace(b'\r\n',b'-MCP0-EOL0-').replace(b'\n',b'-MCP0-EOL1-').replace(b'\r',b'-MCP0-EOL2-')
            # 下面这种方法会大量替换字符,效率较低以及在某些情况下大幅度增加数据长度
            # data=repr(data).encode()
            data=data+b'\n'
            await self.send_raw(data,timeout)
        else:
            data_len=len(data)
            if data_len<=0 or data_len>0x7fffffff:
                raise ValueError('数据长度不合法')
            data_len=hex(data_len)[2:]
            data_len=data_len.zfill(8)
            data=b'MCP-TCP0'+data_len.encode()+data
            await self.send_raw(data,timeout)

    async def send_raw(self,data:bytes,timeout:int=0)->None:
        """发送原始数据"""
        writer=self.writer()
        while data:
            # write_size=min(len(data),self._send_buffer_size)
            # 下面的代码实测效率更高
            data_length=len(data)
            write_size=data_length if data_length<self._send_buffer_size else self._send_buffer_size
            writer.write(data[:write_size])
            data=data[write_size:]
        try:
            if timeout:
                await asyncio.wait_for(writer.drain(),timeout)
            else:
                await writer.drain()
        except asyncio.TimeoutError:
            raise TimeoutError('发送数据超时')

    async def close(self)->None:
        """关闭连接"""
        try:
            writer=self.writer()
            if writer.is_closing():
                return
            writer.close()
            await writer.wait_closed()
        except ConnectionResetError:
            pass

    @staticmethod
    async def get_trust_public_key()->list:
        """获取受到信任的公钥"""
        if hasattr(Connect,'_trust_public_key'):
            return Connect._trust_public_key
        # 判断是否存在文件
        import os,json
        if os.path.exists('test/trust_public_key.json'):
            with open('test/trust_public_key.json','r') as f:
                Connect._trust_public_key=json.load(f)
                return Connect._trust_public_key
        return []

    @staticmethod
    async def save_trust_public_key(public_key:str)->None:
        """保存新的受信任的公钥"""
        if not hasattr(Connect,'_trust_public_key'):
            Connect._trust_public_key=[]
        Connect._trust_public_key.append(public_key)
        import json
        with open('test/trust_public_key.json','w') as f:
            json.dump(Connect._trust_public_key,f)

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