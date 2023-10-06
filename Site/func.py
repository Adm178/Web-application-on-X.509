from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import requests
from datetime import datetime

def generate_key_pair():
    # Генерация приватного ключа
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def CSR(username, email, private_key):
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"RF, Moscow"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"OOO 'Invest Company'")
    ]))

    csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)  # Сериализация CSR в формат PEM

    return csr_pem

def server_cert(uc_url):
    private_key = generate_key_pair()  # Генерация ключевой пары
    key_pem(private_key)
    csr = CSR('investCompany', 'investCompany@ic.ru', private_key)
    s_responce = requests.post(f'{uc_url}/issue_certificate', verify=False,
                               headers={'Content-Type': 'application/x-pem-file'}, data=csr)
    CA_cent = requests.post(f'{uc_url}/CA_certificate', verify=False).content
    if s_responce.status_code == 200:
        with open(f'investCompany_cert.pem', 'wb') as file:
            file.write(s_responce.content)
        with open(f'CA_cert.pem', 'wb') as file:
            file.write(CA_cent)

def key_pem(private_key):
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f'investCompany_key.pem', "wb") as f:
        f.write(private_key_pem)


def parse_client_certificate(client_cert):
    cert_data = client_cert.encode('utf-8')  # Предполагается, что клиентский сертификат представлен в виде строки
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    expiry_date = cert.not_valid_after
    expiry_datetime = datetime.combine(expiry_date.date(), datetime.min.time())

    current_datetime = datetime.now()
    remaining_days = (expiry_datetime - current_datetime).days

    return {'email':cert.subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)[0].value,
            'date': remaining_days }