from tcp_quick.server import Server,Connect
import traceback

class MyServer(Server):
    async def _handle(self,connect:Connect)->None:
        addr=connect.peername()
        print(f'连接: {addr} 已建立')
        data=await connect.recv(120) # 注意,这里的120是指定的超时时间不是读取的大小,如果超时将会抛出异常
        print(f'来自 {addr} 的数据:{data.decode()}')
        message='Hello,Client!'
        await connect.send(message.encode())
        await connect.close()
    
    async def _error(self,addr,e:Exception)->None:
        print(f'来自 {addr} 的连接出现错误: {e}')
        # 如果你想要更详细的错误信息,可以使用traceback模块
        traceback_details=''.join(traceback.format_exception(type(e),e,e.__traceback__))
        print(traceback_details)
    
    async def _connection_closed(self,addr,connect:Connect)->None:
        # 请在这里重写连接成功的连接被关闭时的处理(无论是正常关闭还是异常关闭),如果不重写,可以删除这个方法
        await super()._connection_closed(addr,connect)

# 服务端
# 请注意,行模式(use_line)并不适合传输超过缓冲区大小的数据,如果在缓冲区没有读取到换行符,将会抛出异常
# 行模式使用的是StreamReader的readline方法
# 经过测试抛出的异常为`valueError: Separator is not found, and chunk exceed the limit`
# 被Connect捕获后为`ValueError: 行数据异常: Separator is not found, and chunk exceed the limit`
MyServer(listen_keywords=True,use_line=True)

# 更多参数请参考Server类的__init__方法
# server=MyServer(ip='0.0.0.0',port=12345,backlog=1,reject=False,listen_keywords=True,use_line=False)