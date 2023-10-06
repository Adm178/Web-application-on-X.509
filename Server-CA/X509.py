from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import datetime

# Генерация клиентского сертификата
def generate_certificate(csr):
    certificate = x509.CertificateBuilder()\
        .subject_name(csr.subject)\
        .issuer_name(issuer)\
        .public_key(csr.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.utcnow())\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True,) \
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(CA_private_key.public_key()), critical=False)\
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False) \
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False) \
        .sign(CA_private_key, hashes.SHA256(), default_backend())

    # Поиск расширения с информацией о электронной почте
    email = csr.subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)[0].value

    # Сохранение сертификата в файл в формате PEM
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    with open(f'cert/{email}_cert.pem', "wb") as file:
        file.write(cert_pem)

    return cert_pem

# Генерация корневого сертификата
def CA():
    global CA_private_key
    CA_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())
    public_key = CA_private_key.public_key()

    global issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "CA"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CA RF")])

    cert = x509.CertificateBuilder().\
        subject_name(subject).\
        issuer_name(issuer).\
        public_key(public_key).\
        serial_number(x509.random_serial_number()).\
        not_valid_before(datetime.datetime.utcnow()).\
        not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)). \
        add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True). \
        add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False). \
        sign(CA_private_key, hashes.SHA256(), default_backend())

    CA_cert = cert.public_bytes(serialization.Encoding.PEM)
    with open(f'CA_cert.pem', "wb") as file:
        file.write(CA_cert)
    private_key_pem = CA_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("CA_key.pem", "wb") as f:
        f.write(private_key_pem)

    return CA_cert
