from tcp_quick.server import Server,Connect

class MyServer(Server):
    async def _handle(self,connect:Connect)->None:
        addr=connect.peername()
        data=await connect.recv(120)
        print(f'来自 {addr} 的数据:{data.decode()}')
        await connect.send(data)
        await connect.close()

# 服务端
MyServer(listen_keywords=True)

# 更多参数请参考Server类的__init__方法
# server=MyServer(ip='0.0.0.0',port=12345,backlog=1,reject=False,listen_keywords=True)