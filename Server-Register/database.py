import sqlite3

def get_db():  # Подключение к базе данных SQLite через файл
    conn = sqlite3.connect('database.db')
    #conn.row_factory = sqlite3.Row
    return conn

def create_users_table():  # Создание таблицы пользователей
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                access_level INTEGER NOT NULL)
        ''')

def add_user(email, username, password, access_level):  # Добавление нового пользователя в таблицу
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (email, username, password, access_level)
            VALUES (?, ?, ?, ?)
        ''', (email, username, password, access_level))
        conn.commit()

def get_user(email, password):
    with get_db() as conn:
        cursor = conn.cursor()
        if password is None:
            cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        else:
            cursor.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
        user = cursor.fetchone()
        if user:
            return user[2]
        else:
            return None
