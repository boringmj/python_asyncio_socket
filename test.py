from tcp_quick.cert_manager import CertManager

root_name = CertManager.build_x509_name(common_name='Borinmj')
root_private_key = CertManager.generate_private_key()

# 生成根证书
root_certificate = CertManager.generate_certificate(
    root_private_key,
    root_name,
    root_name,
    valid_days=365,
    is_ca=True,
    output_certificate_path='test/root_certificate.crt',
    output_private_key_path='test/root_private_key.key'
)

# 生成中间证书
intermediate_name = CertManager.build_x509_name(common_name='Wuliaomj')
intermediate_private_key = CertManager.generate_private_key()
intermediate_certificate = CertManager.generate_certificate(
    intermediate_private_key,
    intermediate_name,
    root_name,  # 中间证书的发行者是根证书
    valid_days=365,
    is_ca=True,
    issuer_private_key=root_private_key,  # 由根证书的私钥签名
    output_certificate_path='test/intermediate_certificate.crt',
    output_private_key_path='test/intermediate_private_key.key'
)

# 生成终端证书
terminal_name = CertManager.build_x509_name(common_name='localhost')
terminal_private_key = CertManager.generate_private_key()
terminal_certificate = CertManager.generate_certificate(
    terminal_private_key,
    terminal_name,
    intermediate_name,  # 终端证书的发行者是中间证书
    valid_days=0,
    is_ca=False,
    issuer_private_key=intermediate_private_key,  # 由中间证书的私钥签名
    output_certificate_path='test/terminal_certificate.crt',
    output_private_key_path='test/terminal_private_key.key'
)
