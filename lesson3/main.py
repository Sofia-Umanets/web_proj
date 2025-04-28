from http.server import HTTPServer

from form_app.handler import FormHandler


def main():
    host = "0.0.0.0"  # Это позволит принимать подключения извне контейнера
    port = 8000  # Соответствует порту, указанному в docker-compose.yml

    httpd = HTTPServer((host, port), FormHandler)
    print(f"Сервер запущен на http://{host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()