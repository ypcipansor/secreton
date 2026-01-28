import http.server
import socketserver
import os

PORT = 8000
DIRECTORY = "crates/ui/dist"

class SPAHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        # Check if file exists
        path = self.translate_path(self.path)
        if not os.path.exists(path):
            # Fallback to index.html for SPA
            self.path = "/index.html"
        super().do_GET()

with socketserver.TCPServer(("", PORT), SPAHandler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()
