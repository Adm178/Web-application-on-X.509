from flask import Flask, render_template, redirect, request, flash
from flask_session import Session
import os
from func import server_cert, parse_client_certificate
import urllib3
import ssl
import requests

app = Flask(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Отключение предупреждений о безопасности SSL
ac_url = 'https://localhost:5000'  # URL УЦ
register_url = 'https://localhost:8080'  # URL УЦ
app.secret_key = os.urandom(24)  # Генерация секретного ключа
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_PERMANENT'] = True
Session(app)

@app.route("/")  # Домашняя страница
def home():
    condition = False
    client_cert = request.environ.get('SSL_CLIENT_CERT')
    # Парсим информацию из клиентского сертификата
    cert_info = parse_client_certificate(client_cert)
    date = cert_info['date']
    if date < 14:
        condition = True

    email = cert_info['email']
    response = requests.get(f'{register_url}/data', verify=False, params=cert_info)
    if response.status_code == 200:
        user_dict = {'name': response.content.decode('utf-8') + " [" + email + "]"}
        return render_template("home.html", user=user_dict, condition=condition, variable=date), 200
    else:
        return render_template("home.html", user={'name': "пользователь"}, condition=condition, variable=date), 200


@app.route("/logout")  # выход
def logout():
    return redirect(register_url)

server_cert(ac_url)
if __name__ == '__main__':  # Команды, которые будут исполняться при каждом запуске сервера
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # Настраиваем TLS
    context.load_cert_chain('investCompany_cert.pem', 'investCompany_key.pem')
    context.load_verify_locations('CA_cert.pem')
    context.options |= ssl.OP_SINGLE_ECDH_USE
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    context.verify_mode = ssl.CERT_REQUIRED
    app.run(host='localhost', threaded=True, debug=True, ssl_context=context, port=443)  # Запускаем с учетом настроек
