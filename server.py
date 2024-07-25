import asyncio
from tcp_quick.server import Server

class MyServer(Server):
    async def _handle(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter)->None:
        addr=writer.get_extra_info('peername')
        data=await self.recv(reader,1024,timeout=5)
        print(f'来自 {addr} 的数据:{data}')
        await self.send(writer,data)
    
    async def _reject_client(self, writer: asyncio.StreamWriter)->None:
        # 这里可以重写拒绝连接处理
        print(f'拒绝来自 {writer.get_extra_info("peername")} 的连接')
        return await super()._reject_client(writer)

    async def _error(self,addr,error:Exception)->None:
        # 这里可以重写连接错误处理
        return await super()._error(addr,error)

    async def _server_error(self,error:Exception)->None:
        # 这里可以重写服务器错误处理
        return await super()._server_error(error)

server=MyServer(ip='0.0.0.0',port=12345,backlog=1,reject=True,listen_keywords=True)