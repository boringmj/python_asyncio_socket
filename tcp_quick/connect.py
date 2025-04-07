import asyncio,socket,ssl
# import ast
from .mcp import MCP
from .base_connect import BaseConnect
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES

class Connect(BaseConnect):
    """
    连接管理类
    """

    def __init__(
            self,
            reader:asyncio.StreamReader,
            writer:asyncio.StreamWriter,
            use_mcp:bool=False,
            configs:dict={}
        )->None:
        self._reader=reader
        self._writer=writer
        self._use_mcp=use_mcp
        self._peername=writer.get_extra_info('peername')
        self._sock:socket.socket=writer.get_extra_info('socket')
        self._recv_buffer_size=self._sock.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
        self._send_buffer_size=self._sock.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF)
        self._buffer_temp=b''
        self._configs=configs
        self._use_line=configs.get('use_line',False)
        self._is_server=bool(self._configs.pop('server',False)) # 是否为服务端

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

    def mcp(self)->MCP:
        """获取MCP协议对象"""
        # 判断是否存在MCP协议对象
        if not hasattr(self,'_mcp'):
            self._mcp=MCP(self._is_server,self,self._configs)
        return self._mcp
    
    async def initialize(self)->None:
        """初始化"""
        if self._use_mcp:
            await self.mcp().handshake()

    def set_recv_buffer_size(self,buffer_size:int)->None:
        """调整接收缓冲区大小"""
        if buffer_size<=0:
            raise ValueError('缓冲区大小不能小于等于0')
        self._sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,buffer_size)
        self._recv_buffer_size=buffer_size

    def set_send_buffer_size(self,buffer_size:int)->None:
        """调整发送缓冲区大小"""
        if buffer_size<=0:
            raise ValueError('缓冲区大小不能小于等于0')
        self._sock.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,buffer_size)
        self._send_buffer_size=buffer_size

    def get_recv_buffer_size(self)->int:
        """获取接收缓冲区大小"""
        return self._recv_buffer_size

    def get_send_buffer_size(self)->int:
        """获取发送缓冲区大小"""
        return self._send_buffer_size

    def set_aes_key(self,aes_key:bytes)->None:
        """设置AES密钥"""
        self._aes_key=aes_key

    async def recv(self,timeout:int=0,fill_byte:int=64,fill_byte_timeout:float=10,fill_byte_force:bool=False)->bytes:
        """
        接收数据\n
        fill_byte和fill_byte_timeout,fill_byte_force参数主要用于解决缓冲区数据不足时的问题\n
        fill_byte和fill_byte_timeout,fill_byte_force参数仅在非行模式下有,不合理的设置可能导致丢失数据,请谨慎配置参数\n
        fill_byte大于0时,总读取耗时可能会增加最大fill_byte*fill_byte_timeout秒(如果fill_byte_timeout>0)\n
        fill_byte_timeout不大于0时,将会持续等待直到读取到指定大小的数据或者总耗时超过timeout\n
        如果fill_byte_force为True,将会在没有读取到预期长度的数据时强制等待fill_byte次(等待超时后进入下一次等待)\n
        如果fill_byte_force为False,将会在等待超时时立即返回已有数据

        @param timeout:超时时间
        @param fill_byte:填充字节次数(当读取到的数据不足时,继续进行读取的次数,缓冲区没有数据时会尝试等待)
        @param fill_byte_timeout:填充超时时间(如果缓冲区没有数据时,等待的时间,超时不会抛出异常)
        """
        try:
            if timeout:
                data=await asyncio.wait_for(self._recv(fill_byte,fill_byte_timeout,fill_byte_force),timeout)
            else:
                data=await self._recv(fill_byte,fill_byte_timeout,fill_byte_force)
        except asyncio.TimeoutError:
            raise TimeoutError('接收数据超时')
        if self._use_mcp:
            return self.mcp().recv(data)
        return data

    async def _recv(self,fill_byte:int=0,fill_byte_timeout:float=0.1,fill_byte_force:bool=False)->bytes:
        """底层接收数据"""
        if self._use_line:
            data=await self.recv_raw_line()
            # 将data中的“-MCP0-EOL-”替换为换行符
            data=data.replace(b'-MCP0-EOL0-',b'\r\n').replace(b'-MCP0-EOL1-',b'\n').replace(b'-MCP0-EOL2-',b'\r')
            # 下面这种方法会大量替换字符,效率较低以及在某些情况下大幅度增加数据长度
            # data=ast.literal_eval(data.decode())
        else:
            data=await self.recv_raw(
                byte=10,
                fill_byte=fill_byte,
                fill_byte_timeout=fill_byte_timeout,
                fill_byte_force=fill_byte_force
            )
            header=self.mcp().parse_mcp_header(data)
            data=await self.recv_raw(
                byte=header['length'],
                fill_byte=fill_byte,
                fill_byte_timeout=fill_byte_timeout,
                fill_byte_force=fill_byte_force
            )
            if len(data)!=header['length']:
                raise ValueError('数据异常')
        return data

    async def recv_raw(
        self,byte:int,timeout:int=0,
        fill_byte:int=0,fill_byte_timeout:float=0.1,fill_byte_force:bool=False
    )->bytes:
        """
        接收原始数据\n
        fill_byte和fill_byte_timeout,fill_byte_force参数主要用于解决缓冲区数据不足时的问题\n
        fill_byte和fill_byte_timeout,fill_byte_force参数仅在非行模式下有,不合理的设置可能导致丢失数据,请谨慎配置参数\n
        fill_byte大于0时,总读取耗时可能会增加最大fill_byte*fill_byte_timeout秒(如果fill_byte_timeout>0)\n
        fill_byte_timeout不大于0时,将会持续等待直到读取到指定大小的数据或者总耗时超过timeout\n
        如果fill_byte_force为True,将会在没有读取到预期长度的数据时强制等待fill_byte次(等待超时后进入下一次等待)\n
        如果fill_byte_force为False,将会在等待超时时立即返回已有数据

        @param byte:指定的读取大小
        @param timeout:超时时间
        @param fill_byte:填充字节次数(当读取到的数据不足时,继续进行读取的次数,缓冲区没有数据时会尝试等待)
        @param fill_byte_timeout:填充超时时间(如果缓冲区没有数据时,等待的时间,超时不会抛出异常)
        """
        try:
            if timeout:
                data=await asyncio.wait_for(self._recv_raw(byte,fill_byte,fill_byte_timeout,fill_byte_force),timeout)
            else:
                data=await self._recv_raw(byte,fill_byte,fill_byte_timeout,fill_byte_force)
        except asyncio.TimeoutError:
            raise TimeoutError('接收数据超时')
        return data

    async def _recv_raw(self,byte:int,fill_byte:int=0,fill_byte_timeout:float=0.1,fill_byte_force:bool=False)->bytes:
        """底层接收原始数据"""
        reader=self.reader()
        data=bytearray()
        # 缓冲区处理逻辑
        if self._buffer_temp:
            buffer_view=memoryview(self._buffer_temp)
            buffer_len=len(buffer_view)
            if buffer_len>=byte:
                # 直接切割内存视图
                data.extend(buffer_view[:byte])
                self._buffer_temp=buffer_view[byte:].tobytes()
                return bytes(data)
            else:
                # 完全复用缓冲区内容
                data.extend(buffer_view)
                byte-=buffer_len
                self._buffer_temp=b''
        is_fill_byte=False
        while byte>0:
            temp=b''
            # read_size=min(byte,self._recv_buffer_size)
            # 下面的代码实测效率更高
            read_size=byte if byte<self._recv_buffer_size else self._recv_buffer_size
            # 使用 memoryview 接收读取内容
            try:
                if is_fill_byte and fill_byte_timeout>0:
                    temp=await asyncio.wait_for(reader.read(read_size),fill_byte_timeout)
                else:
                    temp=await reader.read(read_size)
            except asyncio.TimeoutError:
                if fill_byte_force and fill_byte>0:
                    fill_byte-=1
                    continue
                break
            if not temp:
                break
            # 通过内存视图操作数据
            temp_view=memoryview(temp)
            temp_len=len(temp_view)
            byte-=temp_len
            data.extend(temp_view)
            if temp_len<read_size:
                if fill_byte<=0:
                    break
                is_fill_byte=True
                fill_byte-=1
        return bytes(data)

    async def recv_raw_line(self,timeout:int=0,eol:bytes=b'',preserve:bool=False)->bytes:
        """
        接收原始行数据

        @param timeout:超时时间
        @param eol:指定的行结束符(为空时自动识别)
        @param preserve:是否保留行结束符
        """
        try:
            if timeout:
                data=await asyncio.wait_for(self._recv_raw_line(eol,preserve),timeout)
            else:
                data=await self._recv_raw_line(eol,preserve)
        except asyncio.TimeoutError:
            raise TimeoutError('接收数据超时')
        return data

    async def _recv_raw_line(self,eol:bytes=b'',preserve:bool=False)->bytes:
        """底层接收原始行数据"""
        reader=self.reader()
        data=bytearray()
        buffer=bytearray(self._buffer_temp) if self._buffer_temp else bytearray()
        while True:
            current_bytes=bytes(buffer)
            # 查找换行符逻辑
            candidates=[]
            search_targets=[eol] if eol else [b'\r\n',b'\n',b'\r']
            # 同时查找所有可能的换行符
            for target in search_targets:
                pos=current_bytes.find(target)
                if pos!=-1:
                    candidates.append((pos,len(target)))
            # 选择最早出现的换行符
            if candidates:
                earliest=min(candidates,key=lambda x:x[0])
                pos,term_len=earliest
                end_pos=pos+term_len
                buffer_view=memoryview(buffer)
                data.extend(buffer_view[:end_pos if preserve else pos])
                # 更新剩余缓冲区
                self._buffer_temp=buffer_view[end_pos:].tobytes()
                return bytes(data)
            # 未找到时继续读取
            temp=await reader.read(self._recv_buffer_size)
            if not temp:
                if buffer:
                    # 返回剩余数据作为最后一行
                    self._buffer_temp=b''
                    return bytes(buffer)
                raise ValueError('行数据异常')
            temp_view=memoryview(temp)
            buffer.extend(temp_view)

    async def send(self,data:bytes,timeout:int=0)->None:
        """发送数据"""
        try:
            if timeout:
                await asyncio.wait_for(self._send(data),timeout)
            else:
                await self._send(data)
        except asyncio.TimeoutError:
            raise TimeoutError('发送数据超时')

    async def _send(self,data:bytes)->None:
        """底层发送数据"""
        if self._use_mcp:
            data=self.mcp().send(data)
        if self._use_line:
            # 将data中的换行符替换为“-MCP0-EOL-”
            data=data.replace(b'\r\n',b'-MCP0-EOL0-').replace(b'\n',b'-MCP0-EOL1-').replace(b'\r',b'-MCP0-EOL2-')
            # 下面这种方法会大量替换字符,效率较低以及在某些情况下大幅度增加数据长度
            # data=repr(data).encode()
            data=data+b'\n'
            await self.send_raw(data)
        else:
            data_len=len(data)
            if data_len<=0 or data_len>0x7fffffff:
                raise ValueError('数据长度不合法')
            data_len=hex(data_len)[2:]
            data_len=data_len.zfill(8)
            data=self.mcp().build_mcp_pack('application_data',data)
            await self.send_raw(data)

    async def send_raw(self,data:bytes,timeout:int=0)->None:
        """发送原始数据"""
        try:
            if timeout:
                await asyncio.wait_for(self._send_raw(data),timeout)
            else:
                await self._send_raw(data)
        except asyncio.TimeoutError:
            raise TimeoutError('发送数据超时')

    async def _send_raw(self,data:bytes)->None:
        """底层发送原始数据"""
        writer=self.writer()
        while data:
            # write_size=min(len(data),self._send_buffer_size)
            # 下面的代码实测效率更高
            data_length=len(data)
            write_size=data_length if data_length<self._send_buffer_size else self._send_buffer_size
            writer.write(data[:write_size])
            data=data[write_size:]
            await writer.drain()

    async def close(self)->None:
        """关闭连接"""
        try:
            writer=self.writer()
            if writer.is_closing():
                return
            writer.close()
            await writer.wait_closed()
        except (ConnectionResetError,ssl.SSLError):
            pass