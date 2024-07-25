from tcp_quick.client import Client
import asyncio

class MyClient(Client):
    async def _handle(self,reader: asyncio.StreamReader,writer: asyncio.StreamWriter)->None:
        message='Hello,World!'
        await self.send(message.encode())
        data=await self.recv(timeout=5)
        print(f'接收数据:{data.decode()}')

# 经过测试,直接使用ip地址能有效降低连接时间,如果你的连接时间较短且连接频繁,建议使用ip地址以提高效率
# client=MyClient(ip='localhost',port=12345)
client=MyClient(ip='127.0.0.1',port=12345)