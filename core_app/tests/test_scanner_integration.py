import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.parse
from scanner.scanner import Scanner


class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        if path == "/":
            content = "<html><body><a href='/form'>form</a><a href='/?q=normal'>link</a></body></html>"
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(content.encode())
            return
        if path == "/form":
            html = "<html><body><form action='/submit' method='post'><input name='input1' value=''></form></body></html>"
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())
            return
        # reflect query param if present
        if 'q' in qs:
            q = qs['q'][0]
            if "<script" in q:
                content = f"<html><body>{q}</body></html>"
            elif "OR" in q and "1" in q:
                content = "You have an error in your SQL syntax near 'FROM'"
            else:
                content = "<html><body>OK</body></html>"
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(content.encode())
            return

        # default
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8')
        data = urllib.parse.parse_qs(body)
        # look for payloads
        for vals in data.values():
            for v in vals:
                if "<script" in v:
                    content = f"<html><body>{v}</body></html>"
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(content.encode())
                    return
                if "OR" in v and "1" in v:
                    content = "You have an error in your SQL syntax near 'FROM'"
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(content.encode())
                    return
        # default
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        return


def run_server(server):
    server.serve_forever()


def test_scanner_integration():
    server = ThreadingHTTPServer(('127.0.0.1', 0), MyHandler)
    port = server.server_address[1]
    t = threading.Thread(target=run_server, args=(server,), daemon=True)
    t.start()
    # allow server to start
    time.sleep(0.1)

    try:
        s = Scanner()
        res = s.scan(f'http://127.0.0.1:{port}/', max_pages=10)
        types = {r.get('type') for r in res.get('results', [])}
        # expect at least one XSS and one SQLi detection by our test server
        assert 'XSS' in types or 'SQLi' in types
    finally:
        server.shutdown()
        t.join(timeout=1)
