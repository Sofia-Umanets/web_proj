import os
import mysql.connector
from mysql.connector import Error
from form_app.validators import UserFormModel
from dotenv import load_dotenv

# Загрузка переменных окружения
load_dotenv()

# Параметры подключения к базе данных
DB_CONFIG = {
    'host': os.getenv('MYSQL_HOST', 'db'),
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

@database_connection
def save_user_form(form_data: UserFormModel, **kwargs):
    conn = kwargs["connection"]
    cursor = conn.cursor()
    
    try:
        INSERT_FORM_SQL = (
            "INSERT INTO user_forms (full_name, phone_number, email, birth_date, gender, bio) "
            "VALUES (%s, %s, %s, %s, %s, %s)"
        )
        insert_form_data = (
            form_data.full_name, form_data.phone, form_data.email,
            form_data.birth_date, form_data.gender, form_data.bio,
        )

        cursor.execute(INSERT_FORM_SQL, insert_form_data)
        form_id = cursor.lastrowid
        
        # Обработка языков программирования
        if form_data.prog_languages:
            SELECT_PROG_LANGS_SQL = (
                "SELECT lang_id FROM programming_languages WHERE name IN ({})".format(
                    ','.join(['%s'] * len(form_data.prog_languages))
                )
            )

            INSERT_USER_LANGS_SQL = (
                "INSERT INTO user_prog_languages (lang_id, form_id) "
                "VALUES (%s, %s)"
            )

            cursor.execute(SELECT_PROG_LANGS_SQL, list(form_data.prog_languages))
            lang_ids = [row[0] for row in cursor.fetchall()]

            for lang_id in lang_ids:
                cursor.execute(INSERT_USER_LANGS_SQL, (lang_id, form_id))
        
        conn.commit()
        print("Form saved successfully")
    except mysql.connector.Error as err:
        conn.rollback()
        print(f"Database error: {err}")
        raise
    finally:
        cursor.close()