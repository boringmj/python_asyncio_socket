import hashlib
from .key import Key
from .base_connect import BaseConnect
from .base_protocol import BaseProtocol
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES

class MCP(BaseProtocol):
    """
    MCP协议类
    """

    # 暂时还未实现的全部功能
    _mcp:dict={
        'version':'1.1',# 当前版本
        'header':{
            'mark':b'\xa1\x99\xce',# 标记
            'type':{ # 消息类型
                'none':b'\x00',# 无(向上兼容)
                'handshake':b'\x01',# 握手
                'application_data':b'\x02',# 应用数据
                'handshake_ack':b'\x03',# 握手确认
            },
            'version':{ # 支持的版本(越靠上使用的优先级越高)
                '1.1':b'\x01\x01',# 1.1版本
                '0.0':b'\x00\x00'# 占位版本(请放置在最后)
            }
        },
        'encryption':{ # 支持的加密方式(越靠上使用的优先级越高)
            'RSA-AES':b'\x01',# RSA-AES加密
        }
    }

    def __init__(self,is_server:bool,connect:BaseConnect,configs:dict={})->None:
        """
        初始化MCP协议类
        :param is_server:是否为server
        """
        # 选择的协议版本(正在使用的版本)
        self._mcp_version='0.0'
        # 选择的加密方式(正在使用的加密方式)
        self._encryption=None
        # 可以使用的加密方式
        if configs.get('encryption') is not None:
            self._encryption_list=configs['encryption']
        else:
            self._encryption_list=self._mcp['encryption'].keys()
        # 超时时间
        self._timeout=configs.get('timeout',15)
        # 是否为server
        self._is_server=is_server
        # 连接对象
        self._connect=connect
        # AES密钥
        self._aes_key=b'11111111111111111111111111111111'

    def build_mcp_pack(self,type,pack:bytes)->bytes:
        """构建MCP数据包"""
        if type not in self._mcp['header']['type']:
            raise ValueError('消息类型不支持')
        pacg_len=len(pack)
        if pacg_len<=0 or pacg_len>0x7fffffff:
            raise ValueError('数据长度不合法')
        if self._mcp_version not in self._mcp['header']['version']:
            raise ValueError('当前协议版本不支持')
        header=self._mcp['header']['mark']+self._mcp['header']['version'][self._mcp_version]
        message_header=self._mcp['header']['type'][type]+pacg_len.to_bytes(4,'big')
        message=header+message_header+pack
        return message

    def parse_mcp_header(self,pack:bytes)->dict:
        """解析MCP头部"""
        if len(pack)!=10:
            raise ValueError('数据头部异常')
        header=pack[:5]
        mark=header[:3]
        if mark!=self._mcp['header']['mark']:
            raise ValueError('数据异常')
        version=header[3:]
        if version not in self._mcp['header']['version'].values():
            raise ValueError('协议版本不支持')
        message_header=pack[5:]
        type=message_header[:1]
        if type not in self._mcp['header']['type'].values():
            raise ValueError('消息类型不支持')
        length=message_header[1:]
        if length[0]>0x7f or length==b'\x00\x00\x00\x00':
            raise ValueError('数据异常')
        length=int.from_bytes(length,'big')
        return {
            'mark':mark,
            'version':version,
            'type':type,
            'length':length
        }

    async def handshake(self)->None:
        """MCP握手"""
        if self._is_server:
            await self._handshake_server(self._connect)
        else:
            await self._handshake_client(self._connect)

    async def _handshake_server(self,connect:BaseConnect)->None:
        """MCP握手,服务端"""
        # 使用局部变量缓存字典查找结果
        mcp_header_type=self._mcp['header']['type']
        mcp_encryption=self._mcp['encryption']
        mcp_version=self._mcp['header']['version']
        # 接收并解析握手包
        data=await connect.recv_raw(10,timeout=self._timeout)
        header=self.parse_mcp_header(data)
        # 使用预定义的常量进行比较
        if header['type']!=mcp_header_type['handshake']:
            raise ValueError('握手包异常')
        # 接收剩余数据并分割
        data=await connect.recv_raw(header['length'],timeout=self._timeout)
        enc_data,ver_data=data.split(b'\n',1)  # 最多分割一次
        # 使用bytes迭代优化分割
        encryptions=[enc_data[i:i+1] for i in range(len(enc_data))]
        versions=[ver_data[i:i+2] for i in range(0,len(ver_data),2)]
        # 使用集合提高查找效率
        supported_encs=set(mcp_encryption.values())
        encryption=next((enc for enc in encryptions if enc in supported_encs),None)
        if not encryption:
            raise ValueError('加密方式不支持')
        # 使用反向字典直接查找key
        enc_reverse={v:k for k,v in mcp_encryption.items()}
        self._encryption=enc_reverse[encryption]
        # 版本处理
        supported_vers=set(mcp_version.values())
        version=next((ver for ver in versions if ver in supported_vers),None)
        if not version or version==b'\x00\x00':
            raise ValueError('协议版本不支持')
        ver_reverse={v:k for k,v in mcp_version.items()}
        self._mcp_version=ver_reverse[version]
        # 构建确认包
        handshake_ack=mcp_encryption[self._encryption]+mcp_version[self._mcp_version]
        handshake_ack_pack=self.build_mcp_pack('handshake_ack',handshake_ack)
        await connect.send_raw(handshake_ack_pack,timeout=self._timeout)

    async def _handshake_client(self,connect:BaseConnect)->None:
        """MCP握手,客户端"""
        # 缓存字典查找结果
        mcp_encryption=self._mcp['encryption']
        mcp_version=self._mcp['header']['version']
        try:
            support_encryption=b''.join(mcp_encryption[enc] for enc in self._encryption_list)
            support_version=b''.join(mcp_version[ver] for ver in mcp_version)
        except KeyError as e:
            raise ValueError(f'不支持的协议参数:{e}') from None
        # 构建握手包
        handshake_pack=self.build_mcp_pack('handshake',b'\n'.join([support_encryption,support_version]))
        await connect.send_raw(handshake_pack,timeout=self._timeout)
        # 接收并验证确认包
        data=await connect.recv_raw(10,timeout=self._timeout)
        header=self.parse_mcp_header(data)
        if header['type']!=self._mcp['header']['type']['handshake_ack']:
            raise ValueError('握手确认包异常')
        data=await connect.recv_raw(header['length'],timeout=self._timeout)
        # 使用反向字典直接查找
        enc_reverse={v:k for k,v in mcp_encryption.items()}
        ver_reverse={v:k for k,v in mcp_version.items()}
        encryption=data[:1]
        version=data[1:]
        if version==b'\x00\x00':
            raise ValueError('协议版本不支持')
        try:
            self._encryption=enc_reverse[encryption]
            self._mcp_version=ver_reverse[version]
        except KeyError as e:
            raise ValueError(f'不支持的协议参数:{e}') from None

    def send(self,data:bytes)->bytes:
        """发送数据包"""
        iv=Key.rand_iv(16)
        cipher=AES.new(self._aes_key,AES.MODE_EAX,iv)
        ciphertext,tag=cipher.encrypt_and_digest(data)
        data=iv+tag+ciphertext
        return data

    def recv(self,data)->bytes:
        """接收数据包"""
        if len(data)<32:
            raise ValueError('数据异常')
        iv=data[:16]
        tag=data[16:32]
        data=data[32:]
        cipher=AES.new(self._aes_key,AES.MODE_EAX,iv)
        try:
            data=cipher.decrypt_and_verify(data,tag)
        except ValueError:
            raise ValueError('数据异常')
        return data