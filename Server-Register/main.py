from flask import Flask, request, render_template, url_for
from flask import redirect, Response, send_file, flash
import requests
import os
from database import add_user, get_user
from func import generate_key_pair, generate_p12, register_cert, CSR, hash_string
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import tempfile
import ssl
import urllib3

app = Flask(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Отключение предупреждений о безопасности SSL
ac_url = 'https://localhost:5000'  # URL УЦ
main_url = 'https://localhost:5000'  # URL УЦ
app.secret_key = os.urandom(24)  # Генерация секретного ключа

@app.route('/', methods=['GET'])
def index():
    return render_template("index.html"), 200

@app.route('/register', methods=['GET','POST']) # Регистрация
def register():
    if request.method == 'GET':
        return render_template("register.html"), 200
    if request.method == 'POST':
        email = str(request.form['email'])
        if not get_user(email, None):
            username = str(request.form['name'])
            password = str(request.form['password'])  # Хэшируем полученный пароль
            private_key = generate_key_pair()  # Генерация ключевой пары
            csr = CSR(email, private_key)  # Создание запроса на выпуск сертификата
            response = requests.post(f'{ac_url}/issue_certificate', verify=False,
                        headers={'Content-Type': 'application/x-pem-file'}, data=csr)  # Отправка CSR запроса УЦ
            if response.status_code == 200:
                add_user(email, username, hash_string(password), 3)
                p12 = generate_p12(response.content, private_key, email, password)
                certificate = Response(p12, mimetype='application/x-pkcs12')
                certificate.headers.set('Content-Disposition', 'attachment', filename=f'{email}_cert.p12')
                return certificate, 200
            else:
                flash('Ошибка получения сертификата со стороны УЦ', 'error')
                return redirect(url_for("register"))
        else:
            flash('Данный email уже зарегистрирован', 'error')
            return redirect(url_for("register"))

@app.route('/register_end', methods=['GET'])
def register_end():
    return redirect(url_for("index"))

@app.route('/download_CA_cert', methods=['POST'])
def download_ca_cert():
    CA_cert = requests.post(f'{ac_url}/CA_certificate', verify=False)

    if CA_cert.status_code == 200:
        cert = x509.load_pem_x509_certificate(CA_cert.content, default_backend())
        crt_data = cert.public_bytes(encoding=serialization.Encoding.DER)

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(crt_data)

        return send_file(temp_file.name, mimetype='application/x-x509-ca-cert',
                         as_attachment=True, download_name='CA_cert.crt')
    else:
        return 'Ошибка получения корневого сертификата', 401

@app.route('/recovery', methods=['GET','POST'])  # Вход
def recovery():
    if request.method == 'GET':
        return render_template("recovery.html"), 200
    if request.method == 'POST':
        email = str(request.form['email'])
        password = str(request.form['password'])
        username = get_user(email, hash_string(password))
        if username:
            private_key = generate_key_pair()  # Генерация ключевой пары
            csr = CSR(email, private_key)  # Создание запроса на выпуск сертификата
            response = requests.post(f'{ac_url}/issue_certificate', verify=False,
                                     headers={'Content-Type': 'application/x-pem-file'}, data=csr)

            if response.status_code == 200:
                p12 = generate_p12(response.content, private_key, email, password)
                certificate = Response(p12, mimetype='application/x-pkcs12')
                certificate.headers.set('Content-Disposition', 'attachment', filename=f'{email}_cert.p12')
                return certificate, 200
            else:
                flash('Ошибка получения сертификата со стороны УЦ', 'error')
                return redirect(url_for("recovery"))
        else:
            flash('Пользователь не найден или неверный пароль', 'error')
            return redirect(url_for("recovery"))


@app.route('/data', methods=['GET'])
def data():
    email = request.args.get('email')
    username = get_user(email, None)
    if username:
        return username
    else:
        return None

@app.route('/login', methods=['GET'])  # Вход
def login():
    return redirect("https://localhost:443/")

register_cert(ac_url)
if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain('register_cert.pem', 'register_key.pem')
    context.load_verify_locations('CA_cert.pem')
    context.options |= ssl.OP_SINGLE_ECDH_USE
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    app.run(host='localhost', threaded=True, debug=True, ssl_context=context, port=8080)  # Запускаем с учетом настроек
