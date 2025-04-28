import os
import mysql.connector
from mysql.connector import Error
from form_app.validators import UserFormModel
from dotenv import load_dotenv
import secrets
import hashlib
from datetime import date

# Загрузка переменных окружения
load_dotenv()

DB_CONFIG = {
    #'host': os.getenv('MYSQL_HOST', 'db'),
    'database': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USERNAME'),
    'password': os.getenv('DB_PASSWORD'),
    'port': 3306,
}

def get_db_connection():
    try:
        print("Attempting to connect with config:", {k: v for k, v in DB_CONFIG.items() if k != 'password'})
        connection = mysql.connector.connect(**DB_CONFIG)
        print("Database connection successful")
        return connection
    except Error as e:
        print(f"Error connecting to MySQL Platform: {e}")
        raise

def database_connection(function):
    def wrapper(*args, **kwargs):
        connection = None
        try:
            connection = get_db_connection()
            return function(*args, connection=connection, **kwargs)
        except Exception as e:
            print(f"Database connection error in wrapper: {e}")
            raise
        finally:
            if connection and connection.is_connected():
                connection.close()
    return wrapper

def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = secrets.token_bytes(16)
    # Используем pbkdf2_hmac для хеширования пароля
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hashed.hex(), salt.hex()

def check_password(plain_password: str, password_hash: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    hashed = hashlib.pbkdf2_hmac('sha256', plain_password.encode(), salt, 100000)
    return hashed.hex() == password_hash

@database_connection
def save_user_form(form_data: UserFormModel, **kwargs):
    conn = kwargs["connection"]
    cursor = conn.cursor()

    # Генерируем логин и пароль
    login = secrets.token_hex(4)  # 8 символов hex
    password = secrets.token_urlsafe(8)  # примерно 8 символов

    password_hash, salt = hash_password(password)

    # Вставляем данные формы с новыми полями
    INSERT_FORM_SQL = (
        "INSERT INTO user_forms "
        "(full_name, phone_number, email, birth_date, gender, bio, "
        "login, password_hash, salt) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
    )

    insert_form_data = (
        form_data.full_name,
        form_data.phone,
        form_data.email,
        form_data.birth_date,
        form_data.gender,
        form_data.bio,
        login,
        password_hash,
        salt,
    )

    cursor.execute(INSERT_FORM_SQL, insert_form_data)
    form_id = cursor.lastrowid

    # Обработка языков программирования (если есть)
    prog_languages_values = form_data.prog_languages
    if prog_languages_values:
        SELECT_PROG_LANGS_SQL = (
            "SELECT lang_id FROM programming_languages WHERE name IN ({})".format(
                ','.join(['%s'] * len(prog_languages_values))
            )
        )

        cursor.execute(SELECT_PROG_LANGS_SQL, prog_languages_values)
        lang_ids = [row[0] for row in cursor.fetchall()]

        INSERT_USER_LANGS_SQL = (
            "INSERT INTO user_prog_languages (lang_id, form_id) "
            "VALUES (%s, %s)"
        )
        for lang_id in lang_ids:
            cursor.execute(INSERT_USER_LANGS_SQL, (lang_id, form_id))

    conn.commit()
    print(f"Form saved successfully with login: {login}")

    return login, password

@database_connection
def find_user_by_login(login: str, **kwargs):
    conn = kwargs["connection"]
    cursor = conn.cursor(dictionary=True)

    QUERY = "SELECT * FROM user_forms WHERE login = %s LIMIT 1"
    cursor.execute(QUERY, (login,))
    user = cursor.fetchone()
    return user

@database_connection
def update_user_data(login: str, form_data: UserFormModel, **kwargs):
    conn = kwargs["connection"]
    cursor = conn.cursor()

    UPDATE_SQL = (
        "UPDATE user_forms SET "
        "full_name = %s, "
        "phone_number = %s, "
        "email = %s, "
        "birth_date = %s, "
        "gender = %s, "
        "bio = %s "
        "WHERE login = %s"
    )

    update_data = (
        form_data.full_name,
        form_data.phone,
        form_data.email,
        form_data.birth_date,
        form_data.gender,
        form_data.bio,
        login,
    )

    cursor.execute(UPDATE_SQL, update_data)

    # Обновляем языки программирования:

    # Сначала удаляем старые связи
    DELETE_LANGS_SQL = "DELETE FROM user_prog_languages WHERE form_id = (SELECT form_id FROM user_forms WHERE login = %s)"
    cursor.execute(DELETE_LANGS_SQL, (login,))

    # Вставляем новые
    prog_languages_values = form_data.prog_languages
    if prog_languages_values:
        SELECT_PROG_LANGS_SQL = (
            "SELECT lang_id FROM programming_languages WHERE name IN ({})".format(
                ','.join(['%s'] * len(prog_languages_values))
            )
        )
        cursor.execute(SELECT_PROG_LANGS_SQL, prog_languages_values)
        lang_ids = [row[0] for row in cursor.fetchall()]

        # Получаем form_id
        cursor.execute("SELECT form_id FROM user_forms WHERE login = %s", (login,))
        form_id = cursor.fetchone()[0]

        INSERT_USER_LANGS_SQL = (
            "INSERT INTO user_prog_languages (lang_id, form_id) "
            "VALUES (%s, %s)"
        )
        for lang_id in lang_ids:
            cursor.execute(INSERT_USER_LANGS_SQL, (lang_id, form_id))

    conn.commit()
    print(f"User data updated for login: {login}")



