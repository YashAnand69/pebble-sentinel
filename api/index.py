from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json

from sentinel.web_service import dispatch


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond('GET')

    def do_POST(self):
        self.respond('POST')

    def respond(self, method):
        try:
            url = urlparse(self.path)
            fallback = 'workspace-check' if url.path == '/api/workspace/check' else url.path.rsplit('/', 1)[-1]
            route = parse_qs(url.query).get('route', [fallback])[0]
            payload = None
            if method == 'POST':
                length = int(self.headers.get('Content-Length', '0'))
                if length < 0 or length > 16384:
                    self.write_json(413, {'error': 'Request is too large.'})
                    return
                payload = json.loads(self.rfile.read(length) or b'{}')
            status, result = dispatch(route, method, payload)
        except (ValueError, TypeError, json.JSONDecodeError):
            status, result = 400, {'error': 'Invalid JSON request.'}
        except Exception:
            status, result = 503, {'error': 'The guard could not complete analysis. No actions were executed.', 'decision': 'hold'}
        self.write_json(status, result)

    def write_json(self, status, result):
        data = json.dumps(result, allow_nan=False, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
