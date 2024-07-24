import asyncio
from tcp_quick.server import Server

class MyServer(Server):
    async def _handle(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter)->None:
        addr=writer.get_extra_info('peername')
        data=await self.recv(reader,1024,timeout=5)
        print(f'来自 {addr} 的数据:{data}')
        await self.send(writer,data)

server=MyServer(ip='127.0.0.1',port=12345,backlog=1,reject=True,listen_keywords=True)