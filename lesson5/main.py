from http.server import HTTPServer

from form_app.handler import HTTPHandler


def main():
    host = "localhost"
    port = 8080

    httpd = HTTPServer((host, port), HTTPHandler)
    print(f"Сервер запущен на http://{host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()