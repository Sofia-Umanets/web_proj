from datetime import datetime, timedelta
from email.utils import formatdate, parsedate_to_datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote, unquote
import mimetypes
import os
import secrets
import hashlib

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import ValidationError

from form_app.database import save_user_form, find_user_by_login, update_user_data, check_password
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
    paths = {"get": {}, "post": {}}

    @property
    def req(self) -> Request:
        headers = dict(self.headers)
        cookies = SimpleCookie(headers.get("Cookie", ""))
        return Request(headers=headers, cookies=cookies)

    def resp(self, response: Response):
        self.send_response(response.status)

        for name, value in response.headers.items():
            self.send_header(name, value)
        for name in response.cookies:
            self.send_header(
                "Set-Cookie", response.cookies[name].OutputString()
            )
        self.end_headers()

        if response.content:
            if isinstance(response.content, str):
                self.wfile.write(response.content.encode())
            else:
                self.wfile.write(response.content)

    @classmethod
    def get(cls, path: str):
        def decorator(function):
            def inner(self):
                self.resp(function(self.req))
            cls.paths["get"][path] = inner
            return inner
        return decorator

    def do_GET(self):
        try:
            if self.path.startswith("/static/"):
                self.serve_static()
            else:
                self.paths["get"][self.path](self)
        except KeyError:
            self.send_error(404, explain=f"Page {self.path} not found")

    def serve_static(self):
        file_path = os.path.join("form_app", self.path.lstrip("/"))

        if not os.path.isfile(file_path):
            self.send_error(404, explain="File not found")
            return

        try:
            with open(file_path, "rb") as f:
                content = f.read()

            content_type, _ = mimetypes.guess_type(file_path)

            self.send_response(200)
            self.send_header("Content-Type", content_type or "application/octet-stream")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        except PermissionError:
            self.send_error(403, explain="Access denied")
        except IOError:
            self.send_error(500, explain="Error reading file")

    @classmethod
    def post(cls, path: str, *, urlencoded: bool = False):
        def decorator(function):
            def inner(self):
                request = self.req
                content = None
                if urlencoded:
                    content = get_urlencoded_data(request, self.rfile)
                self.resp(function(request, content))
            cls.paths["post"][path] = inner
            return inner
        return decorator

    def do_POST(self):
        try:
            self.paths["post"][self.path](self)
        except InvalidRequestError as e:
            self.send_error(400, explain=str(e))
        except KeyError:
            self.send_error(400, explain="invalid URL")


@HTTPHandler.get("/")
def root(request: Request) -> Response:
    headers = {"Content-Type": "text/html"}
    cookies = SimpleCookie()
    # Удаляем устаревшие ошибки и success
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
    expires = None
    cookies = SimpleCookie()

    try:
        form_data = UserFormModel(**content)
    except ValidationError as e:
        for err in e.errors():
            location, msg = err["loc"][0], err["msg"]
            if msg.startswith("Value error, "):
                msg = msg[len("Value error, ") :]
            cookies[f"{location}_err"] = quote(msg.capitalize())

        for field in UserFormModel.model_fields:
            value = content.get(field, "")
            if isinstance(value, list):
                value = "|".join(value)
            cookies[field] = quote(value)

        return Response(
            status=303, headers={"Location": "/"}, cookies=cookies, content=""
        )

    login, password = save_user_form(form_data)

    expires = (datetime.now() + timedelta(days=365)).timestamp()
    cookies["success"] = "1"
    cookies["login"] = login
    cookies["password"] = password  # Для отображения при успехе

    for field in UserFormModel.model_fields:
        value = content.get(field, "")
        if isinstance(value, list):
            value = "|".join(value)
        cookies[field] = quote(value)
        cookies[field]["expires"] = formatdate(expires, usegmt=True)

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

    data = {}
    for field in UserFormModel.model_fields:
        cookie_val = request.cookies.get(field)
        if cookie_val:
            if field == "prog_languages":
                val = unquote(cookie_val.value)
                data[field] = val.split("|") if val else []
            else:
                data[field] = unquote(cookie_val.value)
        else:
            val = user.get(field)
            if val is None:
                data[field] = ""
            elif field == "prog_languages":
                if isinstance(val, str):
                    data[field] = val.split("|") if val else []
                elif isinstance(val, list):
                    data[field] = val
                else:
                    data[field] = []
            else:
                data[field] = val

    # Коррекция phone
    if "phone" not in data or not data["phone"]:
        data["phone"] = user.get("phone_number", "")

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
            if msg.startswith("Value error, "):
                msg = msg[len("Value error, ") :]
            cookies[f"{location}_err"] = quote(msg.capitalize())

        # сохранение значений, включая список языков программирования
        for field in UserFormModel.model_fields:
            value = content.get(field, "")
            if isinstance(value, list):
                value = "|".join(value)
            cookies[field] = quote(value)

        return Response(
            status=303, headers={"Location": "/edit"}, cookies=cookies, content=""
        )

    update_user_data(login, form_data)

    expires = (datetime.now() + timedelta(days=365)).timestamp()

    # Очищаем все поля кроме prog_languages
    for field in UserFormModel.model_fields:
        if field != "prog_languages":
            cookies[field] = ""
            cookies[field]["expires"] = EPOCH
            cookies[f"{field}_err"] = ""
            cookies[f"{field}_err"]["expires"] = EPOCH

    # Сохраняем выбранные языки программирования в куку
    prog_langs_str = "|".join(form_data.prog_languages) if form_data.prog_languages else ""
    cookies["prog_languages"] = quote(prog_langs_str)
    cookies["prog_languages"]["expires"] = formatdate(expires, usegmt=True)

    cookies["success_edit"] = "1"
    cookies["success_edit"]["expires"] = formatdate(expires, usegmt=True)

    return Response(
        status=303, headers={"Location": "/edit"}, cookies=cookies, content=""
    )


@HTTPHandler.get("/logout")
def logout(request: Request) -> Response:
    cookies = SimpleCookie()
    session_cookie = request.cookies.get("session_id")
    if session_cookie and session_cookie.value in sessions:
        del sessions[session_cookie.value]

    cookies["session_id"] = ""
    cookies["session_id"]["expires"] = EPOCH

    return Response(
        status=303, headers={"Location": "/"}, cookies=cookies, content=""
    )