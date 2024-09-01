from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from datetime import datetime,timedelta,timezone

class TLS:
    """
    TLS相关操作
    """

    @staticmethod
    def generate_private_key(bits:int=2048)->rsa.RSAPrivateKey:
        """
        生成RSA私钥

        @param bits:密钥长度
        """
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits
        )
    
    @staticmethod
    def build_x509_name(country:str='',state:str='',locality:str='',organization:str='',common_name:str='')->x509.Name:
        """
        构建X.509证书主题名

        @param country:国家
        @param state:省份
        @param locality:城市
        @param organization:组织
        @param common_name:通用名(通常为域名,且不应为空)
        """
        if not common_name:
            raise ValueError('common_name should not be empty')
        attributes=[]
        if country:
            attributes.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME,country))
        if state:
            attributes.append(x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME,state))
        if locality:
            attributes.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME,locality))
        if organization:
            attributes.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME,organization))
        attributes.append(x509.NameAttribute(x509.NameOID.COMMON_NAME,common_name))
        return x509.Name(attributes)

    @staticmethod
    def generate_certificate(
            private_key:rsa.RSAPrivateKey,subject:x509.Name,issuer:x509.Name,valid_days:int=365,
            output_private_key_path:str='',output_certificate_path:str=''
        )->x509.Certificate:
        """
        生成X.509证书

        @param private_key:私钥
        @param subject:证书持有者(证书主题名/证书使用者)
        @param issuer:证书颁发者
        @param valid_days:有效天数
        @param output_private_key_path:私钥输出路径(为空则不输出)
        @param output_certificate_path:证书输出路径(为空则不输出)
        """
        now=datetime.now(timezone.utc)
        certificate=x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + timedelta(days=valid_days)
        ).sign(private_key,hashes.SHA256())
        if output_private_key_path:
            with open(output_private_key_path,'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        if output_certificate_path:
            with open(output_certificate_path,'wb') as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
        return certificate
    
    @staticmethod
    def load_certificate_from_pem_file(file_path:str)->x509.Certificate:
        """
        从PEM文件加载证书(通常为.crt或.pem文件)

        @param file_path:PEM文件路径
        """
        with open(file_path,'rb') as f:
            return x509.load_pem_x509_certificate(f.read())
    
    @staticmethod
    def check_certificate_validity(certificate:x509.Certificate)->bool:
        """
        检查证书是否有效

        @param certificate:证书
        """
        now=datetime.now(timezone.utc)
        not_valid_before=certificate.not_valid_before_utc
        not_valid_after=certificate.not_valid_after_utc
        return now>=not_valid_before and now<=not_valid_after
    
    @staticmethod
    def check_certificate_private_key_match(certificate:x509.Certificate,private_key:rsa.RSAPrivateKey)->bool:
        """
        检查证书和私钥是否匹配

        @param certificate:X.509证书
        @param private_key:RSA私钥
        """
        public_key_from_private_key=private_key.public_key()
        public_key_from_certificate=certificate.public_key()
        public_key_bytes_from_private_key=public_key_from_private_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_bytes_from_certificate=public_key_from_certificate.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_bytes_from_private_key==public_key_bytes_from_certificate
    
    @staticmethod
    def load_private_key_from_pem_file(file_path:str)->rsa.RSAPrivateKey:
        """
        从PEM文件加载RSA私钥

        @param file_path:PEM文件路径
        @return: RSA私钥
        """
        with open(file_path,'rb') as f:
            private_key=serialization.load_pem_private_key(
                f.read(),
                password=None
            )
            if isinstance(private_key,rsa.RSAPrivateKey):
                return private_key
            else:
                raise ValueError("Invalid RSA private key")