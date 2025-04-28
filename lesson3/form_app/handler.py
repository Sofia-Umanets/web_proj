from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs
import os

from pydantic import ValidationError

from form_app.database import save_user_form
from form_app.exceptions import InvalidRequestError
from form_app.validators import UserFormModel

CONTENT_TYPE_FORM = "application/x-www-form-urlencoded"
ERROR_HTML_TEMPLATE = r"""
<!DOCTYPE HTML>
<html lang="ru">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Форма</title>
        <link
          href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH"
          rel="stylesheet" crossorigin="anonymous" />
        <link rel="stylesheet" href="../style.css" />
    </head>
    <body class="d-flex flex-column min-vh-100">
      <header class="bg-custom">
        <nav class="navbar navbar-expand-sm">
          <div class="container-fluid">
            <a class="navbar-brand" href="/">
              <h1 class="text-center fw-bold d-inline-block align-middle">Форма</h1>
            </a>

            <div class="collapse navbar-collapse show" id="navbarNav">
              <ul class="navbar-nav ms-auto">
                <li class="nav-item">
                  <a class="nav-link" title="Форма" href="/#form">Форма</a>
                </li>
              </ul>
            </div>
          </div>
        </nav>
      </header>

      <main class="container">
        <div class="alert alert-danger" role="alert">{error_message}</div>
      </main>

      <footer class="bg-custom mt-auto p-3">
        <div class="text-center">
          Уманец Софья
        </div>
      </footer>
    </body>
</html>
"""

def form_data_parser(function):
    def inner(self, *args, **kwargs):
        if self.headers["Content-Type"] != CONTENT_TYPE_FORM:
            raise InvalidRequestError("Неверный тип данных (Content-Type)")

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            raise InvalidRequestError("Отсутствуют данные формы")

        content = self.rfile.read(content_length).decode('utf-8')
        parsed_data = {}
        for key, value in parse_qs(content).items():
            parsed_data[key] = value if len(value) > 1 else value[0]

        return function(self, *args, data=parsed_data, **kwargs)

    return inner


class FormHandler(BaseHTTPRequestHandler):
    @form_data_parser
    def process_form(self, **kwargs):
        data = kwargs["data"]

        # Обработка множественного выбора языков программирования
        prog_langs = data.get("prog_languages")
        if isinstance(prog_langs, str):
            data["prog_languages"] = [prog_langs]

        # Проверяем наличие согласия с контрактом
        if "contract_agreed" not in data:
            raise InvalidRequestError("Необходимо согласиться с контрактом")

        save_user_form(UserFormModel(**data))

        self.send_response(303)
        self.send_header("Location", r"/success.html")
        self.end_headers()

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.path = "/index.html"
        elif self.path == "/style.css":
            self.path = "/style.css"
        elif self.path == "/success.html":
            self.path = "/success.html"
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write("404 - Страница не найдена".encode('utf-8'))
            return

        try:
            file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", self.path.lstrip('/'))
            with open(file_path, 'rb') as file:
                self.send_response(200)
                if self.path.endswith('.css'):
                    self.send_header('Content-type', 'text/css')
                else:
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(file.read())
        except FileNotFoundError:
            self.send_response(404)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write("404 - Страница не найдена".encode('utf-8'))

    def post(self):
        if self.path == r"/submit":
            return self.process_form()
        raise InvalidRequestError("Неверный URL")

    def do_POST(self):
        try:
            self.post()
        except InvalidRequestError as e:
            self.send_response(400)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            content = ERROR_HTML_TEMPLATE.format(error_message=str(e)).encode('utf-8')
            self.wfile.write(content)
        except ValidationError as e:
            error_messages = [error["msg"] for error in e.errors()]
            cleaned_error_messages = [msg.replace("Value error, ", "") for msg in error_messages]
            formatted_error_messages = [f"Ошибка заполнения: {msg}" for msg in cleaned_error_messages]
            error_message = "<br>".join(formatted_error_messages)
            self.send_response(400)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            content = ERROR_HTML_TEMPLATE.format(error_message=error_message).encode('utf-8')
            self.wfile.write(content)

        except Exception as e:
            self.send_response(500)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"500 - Внутренняя ошибка сервера: {str(e)}".encode('utf-8'))