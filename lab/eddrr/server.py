from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
from threading import Lock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from engine import VulnerableEDR
from models import Event
from storage import Store


class App:
    def __init__(self, db: str):
        self.engine = VulnerableEDR()
        self.store = Store(db)
        self.lock = Lock()

    def ingest(self, payload: dict) -> list[dict]:
        event = Event(**payload)
        with self.lock:
            event_id = self.store.add_event(event)
            alerts = self.engine.detect(event)
            result = []
            for alert in alerts:
                self.store.add_alert(alert, event_id)
                result.append({
                    "rule_id": alert.rule_id,
                    "severity": alert.severity,
                    "title": alert.title,
                })
            return result

    def close(self) -> None:
        self.store.close()


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, status: int, body: dict) -> None:
            encoded = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._json(200, {"status": "ok", "name": "EDDRR-training-edr"})
                return
            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path != "/events":
                self._json(404, {"error": "not found"})
                return

            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length))
                alerts = app.ingest(payload)
                self._json(200, {"alerts": alerts})
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._json(400, {"error": str(exc)})

        def log_message(self, format: str, *args) -> None:
            return

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default="out/eddrr.db")
    args = parser.parse_args()

    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    app = App(args.db)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(app))

    print(f"EDDRR training EDR listening on http://{args.host}:{args.port}")
    print("POST JSON Event objects to /events. GET /health for a liveness check.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
