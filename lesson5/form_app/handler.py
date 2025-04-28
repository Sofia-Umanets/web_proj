from datetime import datetime, timedelta
from email.utils import formatdate, parsedate_to_datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
import re
from urllib.parse import parse_qs, quote, unquote
import mimetypes
import os
import secrets
import hashlib

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import ValidationError

from form_app.database import get_user_programming_languages, save_user_form, find_user_by_login, update_user_data, check_password, update_user_form_by_id
from form_app.exceptions import InvalidRequestError
from form_app.models import Request, Response
from form_app.validators import UserFormModel

APPLICATION_URLENCODED = "application/x-www-form-urlencoded"
EPOCH = formatdate(0, usegmt=True)

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape()
)

sessions = {}  # session_id (str) -> login (str)


def get_urlencoded_data(request: Request, rfile) -> dict:
    if request.headers.get("Content-Type", "") != APPLICATION_URLENCODED:
        raise InvalidRequestError("invalid Content-Type")

    content_length = int(request.headers.get("Content-Length", 0))
    if content_length == 0:
        raise InvalidRequestError("invalid Content-Length")

    content = rfile.read(content_length).decode()
    query = {}
    for name, value in parse_qs(content).items():
        if name.endswith("[]"):
            query[name[:-2]] = value
        else:
            query[name] = value[0]
    return query

class HTTPHandler(BaseHTTPRequestHandler):
    # routes["GET"] = [ (pattern, handler), … ]
    # routes["POST"] = [ (pattern, handler), … ]
    routes = {"GET": [], "POST": []}

    @property
    def req(self) -> Request:
        headers = dict(self.headers)
        cookies = SimpleCookie(headers.get("Cookie", ""))
        return Request(headers=headers, cookies=cookies)

    def resp(self, response: Response):
        # статус + обычные заголовки
        self.send_response(response.status)
        for k, v in response.headers.items():
            self.send_header(k, v)
        # cookies
        for morsel in response.cookies.values():
            self.send_header("Set-Cookie", morsel.OutputString())
        self.end_headers()
        # тело
        if response.content:
            body = (
                response.content.encode()
                if isinstance(response.content, str)
                else response.content
            )
            self.wfile.write(body)

    @classmethod
    def get(cls, path_pattern: str):
        """
        Декоратор GET.
        path_pattern — строка-ре регулярка без ^ и $, можно с (?P<name>…).
        """
        pattern = re.compile(rf"^{path_pattern}$")
        def decorator(func):
            def handler(self, **kwargs):
                resp = func(self.req, **kwargs)
                self.resp(resp)
            cls.routes["GET"].append((pattern, handler))
            return func
        return decorator

    @classmethod
    def post(cls, path_pattern: str, *, urlencoded: bool = False):
        """
        Декоратор POST.
        urlencoded=True — парсим тело через get_urlencoded_data.
        """
        pattern = re.compile(rf"^{path_pattern}$")
        def decorator(func):
            def handler(self, **kwargs):
                request = self.req
                data = None
                if urlencoded:
                    data = get_urlencoded_data(request, self.rfile)
                    resp = func(request, data, **kwargs)
                else:
                    resp = func(request, **kwargs)
                self.resp(resp)
            cls.routes["POST"].append((pattern, handler))
            return func
        return decorator

    def serve_static(self):
        """Отдаём /static/... из папки form_app/static/..."""
        rel = self.path.lstrip("/")
        full = os.path.join("form_app", rel)
        if not os.path.isfile(full):
            self.send_error(404, explain="File not found")
            return
        try:
            with open(full, "rb") as f:
                data = f.read()
            ctype, _ = mimetypes.guess_type(full)
            self.send_response(200)
            self.send_header("Content-Type", ctype or "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except PermissionError:
            self.send_error(403, explain="Access denied")
        except Exception:
            self.send_error(500, explain="Error reading file")

    def do_GET(self):
        try:
            # 1) Статика
            if self.path.startswith("/static/"):
                return self.serve_static()

            # 2) Пробуем все GET-роуты
            for pattern, handler in self.routes["GET"]:
                m = pattern.match(self.path)
                if not m:
                    continue
                kwargs = m.groupdict()
                # авто-кастинг цифр
                for k, v in kwargs.items():
                    if v.isdigit():
                        kwargs[k] = int(v)
                return handler(self, **kwargs)

            # 3) Ничего не подошло
            self.send_error(404, explain=f"Page {self.path} not found")

        except Exception as e:
            import traceback; traceback.print_exc()
            self.send_error(500, explain=f"Server error: {e}")

    def do_POST(self):
        try:
            for pattern, handler in self.routes["POST"]:
                m = pattern.match(self.path)
                if not m:
                    continue
                kwargs = m.groupdict()
                for k, v in kwargs.items():
                    if v.isdigit():
                        kwargs[k] = int(v)
                return handler(self, **kwargs)

            self.send_error(404, explain=f"Page {self.path} not found")

        except InvalidRequestError as e:
            self.send_error(400, explain=str(e))
        except Exception as e:
            import traceback; traceback.print_exc()
            self.send_error(500, explain=f"Server error: {e}")

# Основные обработчики маршрутов
@HTTPHandler.get("/")
def root(request: Request) -> Response:
    """Главная страница"""
    headers = {"Content-Type": "text/html"}
    cookies = SimpleCookie()
    
    for name in request.cookies:
        if name.endswith("_err") or name == "success":
            cookies[name] = request.cookies[name]
            cookies[name]["expires"] = EPOCH

    data = {}
    for name in request.cookies:
        data[name] = unquote(request.cookies[name].value)
    data["prog_languages"] = data.get("prog_languages", "").split("|")

    content = env.get_template("index.html").render(**data)
    return Response(
        status=200, headers=headers, cookies=cookies, content=content
    )


@HTTPHandler.post("/submit", urlencoded=True)
def form(_: Request, content: dict) -> Response:
    cookies = SimpleCookie()

    try:
        form_data = UserFormModel(**content)
    except ValidationError as e:
        for err in e.errors():
            location, msg = err["loc"][0], err["msg"]
            
            # Обработка различных форматов ошибок от Pydantic
            if msg.startswith("Value error, "):
                msg = msg[len("Value error, "):]
            elif "at most 500 characters" in msg:
                msg = "Биография не должна превышать 500 символов"
            elif "not a valid email address" in msg:
                msg = "Электронная почта имеет неверный формат"
            elif "invalid datetime format" in msg or "Invalid date format" in msg:
                msg = "Некорректная дата рождения"
            
            cookies[f"{location}_err"] = quote(msg.capitalize())

        # При ошибке сохраняем значения для повторного отображения
        for field in UserFormModel.model_fields:
            value = content.get(field, "")
            if isinstance(value, list):
                value = "|".join(value)
            cookies[field] = quote(value)

        return Response(
            status=303, headers={"Location": "/"}, cookies=cookies, content=""
        )

    login, password = save_user_form(form_data)

    # Очищаем все куки с данными формы
    for field in UserFormModel.model_fields:
        cookies[field] = ""
        cookies[field]["expires"] = EPOCH
        cookies[f"{field}_err"] = ""
        cookies[f"{field}_err"]["expires"] = EPOCH

    # Устанавливаем только логин и пароль для отображения на странице успеха
    cookies["success"] = "1"
    cookies["login"] = login
    cookies["password"] = password

    return Response(
        status=303, headers={"Location": "/success"}, cookies=cookies, content=""
    )


@HTTPHandler.get("/success")
def success(request: Request) -> Response:
    headers = {"Content-Type": "text/html"}

    login = request.cookies.get("login")
    password = request.cookies.get("password")

    data = {}
    if login and password:
        data["login"] = unquote(login.value)
        data["password"] = unquote(password.value)

    cookies = SimpleCookie()
    # Удаляем пароль из cookie после показа
    cookies["password"] = ""
    cookies["password"]["expires"] = EPOCH

    content = env.get_template("success.html").render(**data)

    return Response(
        status=200, headers=headers, cookies=cookies, content=content
    )


@HTTPHandler.get("/login")
def login_form(request: Request) -> Response:
    cookies = SimpleCookie()
    error = request.cookies.get("login_err")
    error_msg = unquote(error.value) if error else ""
    cookies["login_err"] = ""
    cookies["login_err"]["expires"] = EPOCH

    content = env.get_template("login.html").render(error=error_msg)
    return Response(
        status=200, headers={"Content-Type": "text/html"}, cookies=cookies, content=content
    )


@HTTPHandler.post("/login", urlencoded=True)
def login_post(request: Request, content: dict) -> Response:
    login = content.get("login", "")
    password = content.get("password", "")
    cookies = SimpleCookie()

    user = find_user_by_login(login)
    if not user:
        cookies["login_err"] = quote("Пользователь не найден.")
        return Response(
            status=303, headers={"Location": "/login"}, cookies=cookies, content=""
        )

    salt = user["salt"]
    if isinstance(salt, bytes):
        salt = salt.hex()

    if not check_password(password, user["password_hash"], salt):
        cookies["login_err"] = quote("Неверный пароль.")
        return Response(
            status=303, headers={"Location": "/login"}, cookies=cookies, content=""
        )

    # Успешный логин
    session_id = secrets.token_hex(16)
    sessions[session_id] = login
    expires = (datetime.now() + timedelta(hours=1)).timestamp()

    cookies["session_id"] = session_id
    cookies["session_id"]["expires"] = formatdate(expires, usegmt=True)

    return Response(
        status=303, headers={"Location": "/edit"}, cookies=cookies, content=""
    )


@HTTPHandler.get("/edit")
def edit_form(request: Request) -> Response:
    cookies = SimpleCookie()
    session_cookie = request.cookies.get("session_id")

    if not session_cookie or session_cookie.value not in sessions:
        return Response(
            status=303, headers={"Location": "/login"}, cookies=cookies, content=""
        )
    login = sessions[session_cookie.value]

    user = find_user_by_login(login)
    if not user:
        del sessions[session_cookie.value]
        return Response(
            status=303, headers={"Location": "/login"}, cookies=cookies, content=""
        )

    # Проверяем, есть ли ошибки валидации
    has_validation_errors = any(name.endswith("_err") for name in request.cookies)
    
    # Формируем данные для отображения
    data = {}
    
    # Если есть ошибки валидации, используем данные из кук
    if has_validation_errors:
        for field in UserFormModel.model_fields:
            cookie_val = request.cookies.get(field)
            if cookie_val:
                if field == "prog_languages":
                    val = unquote(cookie_val.value)
                    data[field] = val.split("|") if val else []
                else:
                    data[field] = unquote(cookie_val.value)
            else:
                data[field] = ""
                
        # Проверяем, есть ли поле phone, если нет, берем из phone_number
        if 'phone' not in data or not data['phone']:
            data['phone'] = user.get('phone_number', '')
    else:
        # Если ошибок нет, берем данные из БД
        data = {
            'full_name': user.get('full_name', ''),
            'phone': user.get('phone_number', ''),
            'email': user.get('email', ''),
            'birth_date': user.get('birth_date', ''),
            'gender': user.get('gender', ''),
            'bio': user.get('bio', ''),
            'prog_languages': user.get('prog_languages', [])
        }
    
    # Обрабатываем ошибки из кук
    errors = {}
    for name in request.cookies:
        if name.endswith("_err"):
            errors[name] = unquote(request.cookies[name].value)
            cookies[name] = ""
            cookies[name]["expires"] = EPOCH

    success_edit = request.cookies.get("success_edit")
    if success_edit:
        cookies["success_edit"] = ""
        cookies["success_edit"]["expires"] = EPOCH
        
        # При успешном редактировании очищаем все куки с данными формы
        if not has_validation_errors:
            for field in UserFormModel.model_fields:
                if field in request.cookies:
                    cookies[field] = ""
                    cookies[field]["expires"] = EPOCH

    context = data.copy()
    context.update(errors)
    context["success_edit"] = bool(success_edit)

    content = env.get_template("edit.html").render(**context)

    return Response(
        status=200,
        headers={"Content-Type": "text/html"},
        cookies=cookies,
        content=content,
    )

@HTTPHandler.post("/edit", urlencoded=True)
def edit_post(request: Request, content: dict) -> Response:
    cookies = SimpleCookie()
    session_cookie = request.cookies.get("session_id")

    if not session_cookie or session_cookie.value not in sessions:
        return Response(
            status=303, headers={"Location": "/login"}, cookies=cookies, content=""
        )

    login = sessions[session_cookie.value]

    try:
        form_data = UserFormModel(**content)
    except ValidationError as e:
        for err in e.errors():
            location, msg = err["loc"][0], err["msg"]
            
            # Обработка различных форматов ошибок от Pydantic
            if msg.startswith("Value error, "):
                msg = msg[len("Value error, "):]
            elif "at most 500 characters" in msg:
                msg = "Биография не должна превышать 500 символов"
            elif "not a valid email address" in msg:
                msg = "Электронная почта имеет неверный формат"
            elif "invalid datetime format" in msg or "Invalid date format" in msg:
                msg = "Некорректная дата рождения"
            
            cookies[f"{location}_err"] = quote(msg.capitalize())

        # При ошибке сохраняем значения для повторного отображения
        for field in UserFormModel.model_fields:
            value = content.get(field, "")
            if isinstance(value, list):
                value = "|".join(value)
            cookies[field] = quote(value)

        return Response(
            status=303, headers={"Location": "/edit"}, cookies=cookies, content=""
        )

    # Обновляем данные пользователя в БД
    update_user_data(login, form_data)

    # Очищаем все куки с данными формы только при успешном обновлении
    for field in UserFormModel.model_fields:
        cookies[field] = ""
        cookies[field]["expires"] = EPOCH
        cookies[f"{field}_err"] = ""
        cookies[f"{field}_err"]["expires"] = EPOCH

    # Устанавливаем флаг успешного обновления
    cookies["success_edit"] = "1"
    cookies["success_edit"]["expires"] = formatdate((datetime.now() + timedelta(days=1)).timestamp(), usegmt=True)

    return Response(
        status=303, headers={"Location": "/edit"}, cookies=cookies, content=""
    )