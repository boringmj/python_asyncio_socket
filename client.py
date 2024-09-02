from tcp_quick.client import Client,Connect
import traceback
# 如果你想要使用ssl,请取消下面的注释
# import ssl

class MyClient(Client):
    async def _handle(self,connect:Connect)->None:
        message='Hi,Server!'
        await connect.send(message.encode(),timeout=120)
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
# 客户端配置大部分情况下需要与服务端配置保持一致,未来可能会考虑自动配置(目前不支持)
MyClient(use_line=True,use_aes=False)

# 演示使用ssl
# ssl_context=ssl.create_default_context()
# # 设置具有前向保密的密码套件
# ssl_context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256')
# # 跳过证书验证和主机名验证,不建议在生产环境中使用
# ssl_context.check_hostname=False
# ssl_context.verify_mode=ssl.CERT_NONE
# client=MyClient(ssl=ssl_context,use_line=True)

# 经过测试,直接使用ip地址能有效降低连接时间,如果你的连接时间较短且连接频繁,建议使用ip地址以提高效率
# 值得一提,使用域名最终还是会转换为ip地址
# client=MyClient(host='localhost',port=12345,use_line=True)