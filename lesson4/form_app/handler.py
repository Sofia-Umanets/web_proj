from datetime import datetime, timedelta
from email.utils import formatdate
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote, unquote
import mimetypes
import os

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import ValidationError

from form_app.database import save_user_form
from form_app.exceptions import InvalidRequestError
from form_app.models import Request, Response
from form_app.validators import UserFormModel

APPLICATION_URLENCODED = "application/x-www-form-urlencoded"
EPOCH = formatdate(0, usegmt=True)

env = Environment(
    loader=FileSystemLoader("/app/lesson4/form_app/templates"),
    autoescape=select_autoescape()
)

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
            if self.path.startswith('/static/'):
                self.serve_static()
            else:
                self.paths["get"][self.path](self)
        except KeyError:
            self.send_error(404, explain=f"Page {self.path} not found")

    def serve_static(self):
        file_path = os.path.join('form_app', self.path.lstrip('/'))
        
        if not os.path.isfile(file_path):
            self.send_error(404, explain="File not found")
            return

        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            content_type, _ = mimetypes.guess_type(file_path)
            
            self.send_response(200)
            self.send_header('Content-Type', content_type or 'application/octet-stream')
            self.send_header('Content-Length', str(len(content)))
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
    for name in request.cookies:
        if name.endswith("_err") or name == "success":
            cookies[name] = request.cookies[name]
            cookies[name]["expires"] = EPOCH

    data = {}
    for name in request.cookies:
        data[name] = unquote(request.cookies[name].value)
    data["prog_languages"] = data.get("prog_languages", "").split("|")

    # Получаем шаблон через объект Environment
    content = env.get_template("index.html").render(**data)
    return Response(
        status=200,
        headers=headers,
        cookies=cookies,
        content=content,
    )

@HTTPHandler.post("/submit", urlencoded=True)
def form(_: Request, content: dict) -> Response:
    print("Received data:", content)
    expires = None
    cookies = SimpleCookie()

    # Сохраняем состояние галочки "С контрактом ознакомлен" сразу после получения данных
    cookies["contract_agreed"] = "1" if content.get("contract_agreed", False) else "0"
    if expires is not None:
        cookies["contract_agreed"]["expires"] = formatdate(expires, usegmt=True)

    try:
        save_user_form(UserFormModel(**content))
        expires = (datetime.now() + timedelta(days=365)).timestamp()
        cookies["success"] = "1"

        # Сохраняем все поля в куки после успешной отправки
        for field in UserFormModel.model_fields:
            value = content.get(field, "")
            if isinstance(value, list):
                value = "|".join(value)
            cookies[field] = quote(value)
            if expires is not None:
                cookies[field]["expires"] = formatdate(expires, usegmt=True)

        # Перенаправляем на страницу success.html после успешной отправки
        return Response(
            status=303,
            headers={"Location": "/success"},
            cookies=cookies,
            content="",
        )
    except ValidationError as e:
        for err in e.errors():
            location, msg = err["loc"][0], err["msg"]
            if msg.startswith("Value error, "):
                msg = msg[len("Value error, "):]
            cookies[f"{location}_err"] = quote(msg.capitalize())

        # Сохраняем все поля в куки
        for field in UserFormModel.model_fields:
            value = content.get(field, "")
            if isinstance(value, list):
                value = "|".join(value)
            cookies[field] = quote(value)
            if expires is not None:
                cookies[field]["expires"] = formatdate(expires, usegmt=True)

        # Если есть ошибки, перенаправляем обратно на главную страницу
        return Response(
            status=303,
            headers={"Location": "/"},
            cookies=cookies,
            content="",
        )
    
@HTTPHandler.get("/success")
def success(request: Request) -> Response:
    headers = {"Content-Type": "text/html"}
    # Получаем шаблон через объект Environment
    content = env.get_template("success.html").render()
    return Response(
        status=200,
        headers=headers,
        cookies=SimpleCookie(),  
        content=content,
    )