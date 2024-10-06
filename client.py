from tcp_quick.client import Client,Connect
import traceback
# 如果你想要使用ssl,请取消下面的注释
import ssl

class MyClient(Client):
    async def _handle(self,connect:Connect)->None:
        message='Hi,Server!'
        await connect.send(message.encode(),timeout=120)
        data=await connect.recv(120) # 注意,这里的120是指定的超时时间不是读取的大小,如果超时将会抛出异常
        print(f'接收数据:{data.decode()}')
        # 接收一个原始的数据包
        data=await connect.recv_raw(1024,120) # 第一个参数是指定的读取大小,第二个参数是指定的超时时间
        print(f'接收原始数据:{data.decode()}')
        await connect.close()

    async def _error(self,e:Exception)->None:
        """处理错误"""
        print(f'发生错误:{e}') 
        # 如果你想要更详细的错误信息,可以使用traceback模块
        traceback_details=''.join(traceback.format_exception(type(e),e,e.__traceback__))
        print(traceback_details)
    
    async def _connection_made(self,_:Connect)->None:
        """连接已建立"""
        print(f'连接已建立')
    
    async def _connection_closed(self,connect:Connect)->None:
        """连接已关闭"""
        print(f'连接已关闭')
        await super()._connection_closed(connect)

# 客户端
# 请注意,行模式(use_line)下send方法会转义换行符,recv方法会解析换行符
# 可以使用send_raw和recv_raw_line方法来发送和接收原始行数据
# 请注意,如果你的服务端使用了行模式,客户端也需要使用行模式,同理,如果服务端没有使用行模式,客户端也不需要使用行模式
# 客户端配置大部分情况下需要与服务端配置保持一致,未来可能会考虑自动配置(目前不支持)

# 这是一个简单的客户端实例
# MyClient(use_line=True,use_aes=False).run()

# 演示使用ssl
ssl_context=ssl.create_default_context()
# 设置具有前向保密的密码套件
ssl_context.set_ciphers(
    'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:'
    'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256'
)
# 跳过证书验证和主机名验证,不建议在生产环境中使用
ssl_context.check_hostname=False
ssl_context.verify_mode=ssl.CERT_NONE
client=MyClient(ssl=ssl_context,use_line=True)
client.run()
