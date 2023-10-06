from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from database import add_user, create_users_table, get_db
import requests
import sqlite3
import hashlib

def generate_key_pair():
    # Генерация приватного ключа
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def CSR(email, private_key):
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, email),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"RF, Moscow"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"OOO 'Invest Company'")
    ]))

    csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)  # Сериализация CSR в формат PEM

    return csr_pem

def generate_p12(certificate, private_key, email, password):
    # Создание файла PKCS#12
    cert = x509.load_pem_x509_certificate(certificate)
    p12 = serialization.pkcs12.serialize_key_and_certificates(
        f"{email}".encode('utf-8'), private_key, cert, None, BestAvailableEncryption(password.encode()))

    return p12

def key_pem(private_key):
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f'register_key.pem', "wb") as f:
        f.write(private_key_pem)

def register_cert(uc_url):
    private_key = generate_key_pair()  # Генерация ключевой пары
    key_pem(private_key)
    csr = CSR('register@ic.ru', private_key)
    s_responce = requests.post(f'{uc_url}/issue_certificate', verify=False,
                               headers={'Content-Type': 'application/x-pem-file'}, data=csr)
    CA_cent = requests.post(f'{uc_url}/CA_certificate', verify=False).content
    if s_responce.status_code == 200:
        with open(f'register_cert.pem', 'wb') as file:
            file.write(s_responce.content)
        with open(f'CA_cert.pem', 'wb') as file:
            file.write(CA_cent)

    try:  # Чтобы БД не создавалась каждый раз, то просто поставим условия проверки
        conn = get_db()  # Пытаемся получить соединение с базой данных
        conn.execute('SELECT * FROM users LIMIT 1')  # Пытаемся создать таблицу users
    except sqlite3.OperationalError:
        create_users_table()  # Если таблица не существует, создаем ее
        add_user('admin@ic.ru', 'admin', hash_string("admin") , 1)  # Добавляем администратора
    finally:
        if 'conn' in locals():  # Закрываем соединение с базой данных
            conn.close()

def hash_string(string):
    sha256_hash = hashlib.sha256()
    encoded_string = string.encode('utf-8')
    sha256_hash.update(encoded_string)
    hashed_string = sha256_hash.hexdigest()
    return hashed_string
