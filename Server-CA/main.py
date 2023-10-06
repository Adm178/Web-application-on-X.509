from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask import Flask, request
from X509 import generate_certificate, CA
from cryptography import x509
import ssl

app = Flask(__name__)

@app.route('/recovery_certificate', methods=['POST'])
def recovery():
    email = request.data.decode('utf-8')
    try:
        with open(f'cert/{email}_cert.pem', "rb") as cert_file:
            cert_data = cert_file.read()
            certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
            cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
            return cert_pem
    except FileNotFoundError:
        return None

@app.route('/issue_certificate', methods=['POST'])
def issue_certificate():
    # Получение CSR-запроса от клиента
    csr_data = request.data
    csr_request = x509.load_pem_x509_csr(csr_data, default_backend())

    cert_pem = generate_certificate(csr_request)  # Генерация сертификата
    return cert_pem  # Возвращаем подписанный сертификат клиенту

@app.route('/CA_certificate', methods=['POST'])
def CA_certificate():
    return CA_cert

CA_cert = CA()  # Генерация корневого сертификата
if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain('CA_cert.pem', 'CA_key.pem')
    app.run(host='localhost', debug=True, ssl_context=context, port=5000)
