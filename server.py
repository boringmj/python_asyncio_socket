import asyncio
from tcp_quick.server import Server,Connect

class MyServer(Server):
    async def _handle(self,connect:Connect)->None:
        addr=connect.peername()
        data=await connect.recv()
        print(f'来自 {addr} 的数据:{data}')
        await connect.send(data)
        await connect.close()
    
    async def _reject_client(self,connect:Connect)->None:
        # 这里可以重写拒绝连接处理
        print(f'拒绝来自 {connect.peername()} 的连接')
        return await super()._reject_client(connect)

    async def _error(self,addr,error:Exception)->None:
        # 这里可以重写连接错误处理
        return await super()._error(addr,error)

    def _server_error(self,error:Exception)->None:
        # 这里可以重写服务器错误处理
        return super()._server_error(error)

server=MyServer(ip='0.0.0.0',port=12345,backlog=1,reject=True,listen_keywords=True)