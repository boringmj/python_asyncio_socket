from tcp_quick.client import Client,Connect
import asyncio

class MyClient(Client):
    async def _handle(self,connect:Connect)->None:
        message='Hello,World!'
        await connect.send(message.encode())
        data=await connect.recv(timeout=5)
        print(f'接收数据:{data.decode()}')
        await connect.close()

# 经过测试,直接使用ip地址能有效降低连接时间,如果你的连接时间较短且连接频繁,建议使用ip地址以提高效率
# client=MyClient(ip='localhost',port=12345)
client=MyClient(ip='127.0.0.1',port=12345)