from tcp_quick.server import Server,Connect
import traceback
# 如果你想要使用ssl,请取消下面的注释
from tcp_quick.cert_manager import CertManager
import os,ssl

class MyServer(Server):
    async def _handle(self,connect:Connect)->None:
        addr=connect.peername()
        print(f'连接: {addr} 已建立')
        data=await connect.recv(120) # 注意,这里的120是指定的超时时间不是读取的大小,如果超时将会抛出异常
        print(f'来自 {addr} 的数据:{data.decode()}')
        message='Hello,Client!'
        await connect.send(message.encode(),timeout=120)
        # 发送一个原始的数据包
        message='This is a raw data packet.'
        await connect.send_raw(message.encode(),timeout=120)
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
# 是否使用aes加密(use_aes)默认情况下为自动选择,即启用ssl时自动关闭aes加密,关闭ssl时自动开启aes加密
# 开启aes加密时,服务器会与客户端进行简单的密钥交换,密钥交换使用的是RSA算法,RSA公钥需要客户端手动确认是否信任
# 如果有需求可以重写相关方法,他们的逻辑在Connect类中,但实际上你可以直接在Server类中重写秘钥交换的方法
# 如果不需要请手动关闭(这里更加推荐使用ssl)

# 这是一个简单的服务端实例
# MyServer(listen_keywords=True,use_line=True,use_aes=False)

# 演示使用ssl
private_key_path='test/private.key'
certificate_path='test/certificate.crt'
ssl_context=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
# 判断test目录是否存在
if not os.path.exists('test'):
    os.mkdir('test')
# 判断证书和私钥是否同时存在
if not os.path.exists(private_key_path) or not os.path.exists(certificate_path):
    # 生成证书和私钥
    private_key=CertManager.generate_private_key()
    certificate=CertManager.generate_certificate(
        private_key,
        CertManager.build_x509_name(common_name='localhost'),
        CertManager.build_x509_name(common_name='localhost'),
        valid_days=365,
        output_private_key_path=private_key_path,
        output_certificate_path=certificate_path
    )
# 校验证书是否有效
certificate=CertManager.load_certificate_from_pem_file(certificate_path)
if not CertManager.check_certificate_validity(certificate):
    raise ValueError('证书已过期')
# 加载私钥
private_key=CertManager.load_private_key_from_pem_file(private_key_path)
# 校验证书和私钥是否匹配
if not CertManager.check_certificate_private_key_match(certificate,private_key):
    raise ValueError('证书和私钥不匹配')
# 加载证书
ssl_context.load_cert_chain(certificate_path,private_key_path)
# 如果你有CA证书,可以使用下面的方法加载CA证书
# ssl_context.load_verify_locations(cafile='this_is_ca.crt')
server=MyServer(listen_keywords=True,ssl=ssl_context,use_line=True)

# 更多参数请参考Server类的__init__方法
# server=MyServer(host='0.0.0.0',port=12345,backlog=1,reject=False,listen_keywords=True,use_line=False)