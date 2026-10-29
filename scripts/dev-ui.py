#!/usr/bin/env python3
"""Serve ui/ in a browser with a mocked Tauri backend and live reload.

    python3 scripts/dev-ui.py [port]      # then open http://127.0.0.1:5173/

The real pages are served unchanged; the mock (scripts/dev-mock.js) and a
reload poller are injected into every HTML response only.
"""
import http.server
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
UI = ROOT / "ui"
MOCK = ROOT / "scripts" / "dev-mock.js"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5173

RELOAD = """<script>(()=>{let last=null;setInterval(async()=>{try{const t=await (await fetch('/__dev/mtime',{cache:'no-store'})).text();
if(last!==null&&t!==last)location.reload();last=t;}catch(e){}},700);})();</script>"""
INJECT = '<script src="/__dev/mock.js"></script>' + RELOAD


def newest_mtime():
    files = list(UI.rglob("*")) + [MOCK]
    return max((f.stat().st_mtime_ns for f in files if f.is_file()), default=0)


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(UI), **kw)

    def _send(self, body: bytes, ctype: str):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/__dev/mtime":
            return self._send(str(newest_mtime()).encode(), "text/plain")
        if path == "/__dev/mock.js":
            return self._send(MOCK.read_bytes(), "text/javascript; charset=utf-8")
        if path == "/":
            path = "/index.html"
        if path.endswith(".html"):
            target = (UI / path.lstrip("/")).resolve()
            if UI in target.parents and target.is_file():
                html = target.read_text(encoding="utf-8")
                html = html.replace("</head>", INJECT + "</head>", 1) if "</head>" in html else INJECT + html
                return self._send(html.encode(), "text/html; charset=utf-8")
        return super().do_GET()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    print(f"UI dev server: http://127.0.0.1:{PORT}/  (mock backend, live reload)")
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
