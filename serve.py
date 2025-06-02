# Simple Python HTTP server for local LLM-CTF app dev
import http.server
import socketserver
import sys
import os

PORT = 8000
if len(sys.argv) > 1:
    PORT = int(sys.argv[1])

# Serve the current folder
web_dir = os.path.abspath(os.path.dirname(__file__))
os.chdir(web_dir)

# Handler for SPA fallback (index.html on 404 for pretty URLs)
class SPARequestHandler(http.server.SimpleHTTPRequestHandler):
    def send_head(self):
        path = self.translate_path(self.path)
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.end_headers()
                return None
            for index in ("index.html", "index.htm"):
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
        ctype = self.guess_type(path)
        try:
            f = open(path, 'rb')
        except OSError:
            # fallback for SPA routes
            if path.endswith('.html') or self.path.count('.') == 0:
                self.path = '/index.html'
                return http.server.SimpleHTTPRequestHandler.send_head(self)
            self.send_error(404, "File not found")
            return None
        self.send_response(200)
        self.send_header("Content-type", ctype)
        fs = os.fstat(f.fileno())
        self.send_header("Content-Length", str(fs[6]))
        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f

Handler = SPARequestHandler
with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
    print(f"Serving at http://localhost:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
