from tcp_quick.client import Client
import socket

class MyClient(Client):
    async def _handle(self,sock:socket.socket)->None:
        msg='Hello,world!'
        # sock.sendall(msg.encode())
        data=sock.recv(1024)
        print(f'收到消息:{data.decode()}')

client=MyClient(ip='127.0.0.1',port=12345)
client.close()