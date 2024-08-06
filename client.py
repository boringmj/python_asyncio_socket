from tcp_quick.client import Client,Connect
import traceback

class MyClient(Client):
    async def _handle(self,connect:Connect)->None:
        message='Hi,Server!'
        await connect.send(message.encode())
        data=await connect.recv(120) # 注意,这里的120是指定的超时时间不是读取的大小,如果超时将会抛出异常
        print(f'接收数据:{data.decode()}')
        await connect.close()
    
    async def _error(self,e:Exception)->None:
        """处理错误"""
        print(f'发生错误:{e}') 
        # 如果你想要更详细的错误信息,可以使用traceback模块
        traceback_details=''.join(traceback.format_exception(type(e),e,e.__traceback__))
        print(traceback_details)

# 客户端
# 请注意,行模式(use_line)并不适合传输超过缓冲区大小的数据,如果在缓冲区没有读取到换行符,将会抛出异常
# 行模式使用的是StreamReader的readline方法
# 经过测试抛出的异常为`valueError: Separator is not found, and chunk exceed the limit`
# 被Connect捕获后为`ValueError: 行数据异常: Separator is not found, and chunk exceed the limit`
# 请注意,如果你的服务端使用了行模式,客户端也需要使用行模式,同理,如果服务端没有使用行模式,客户端也不需要使用行模式
MyClient()

# 经过测试,直接使用ip地址能有效降低连接时间,如果你的连接时间较短且连接频繁,建议使用ip地址以提高效率
# 值得一提,使用域名最终还是会转换为ip地址
# client=MyClient(ip='localhost',port=12345,use_line=True)