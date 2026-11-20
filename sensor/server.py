#!/usr/bin/env python3
"""
Sensor Telemetry Webhook Receiver Service
Receives sensor JSON via POST with token authentication,
persists data to /opt/monitor/data/sensor.json,
and serves telemetry via GET with CORS support.
"""
import json
import os
import secrets
import shutil
import sys
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

def resolve_path(path):
    if not os.path.isabs(path):
        return os.path.normpath(os.path.join(BASE_DIR, path))
    return path

def get_or_create_token(token_file_path):
    """
    Read token from file, or generate a cryptographically secure random token
    and write it to the file if it does not exist.
    """
    token_file_path = resolve_path(token_file_path)
    if os.path.exists(token_file_path):
        try:
            with open(token_file_path, "r", encoding="utf-8") as f:
                token = f.read().strip()
                if token:
                    return token
        except Exception as e:
            print(f"Error reading token from {token_file_path}: {e}", file=sys.stderr)

    # Generate a 32-character random hex token
    new_token = secrets.token_hex(16)
    try:
        os.makedirs(os.path.dirname(token_file_path), exist_ok=True)
        with open(token_file_path, "w", encoding="utf-8") as f:
            f.write(new_token + "\n")
        os.chmod(token_file_path, 0o600)
        print(f"Generated new random token and saved to {token_file_path}")
    except Exception as e:
        print(f"Warning: could not write random token file to {token_file_path}: {e}", file=sys.stderr)
    return new_token

def load_config():
    default_config = {
        "host": "0.0.0.0",
        "port": 28088,
        "token_file": "token.txt",
        "data_file": "/opt/monitor/data/sensor.json"
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                default_config.update(cfg)
        except Exception as e:
            print(f"Error loading {CONFIG_PATH}: {e}", file=sys.stderr)

    # If no explicit token provided, load or generate from token_file
    token_file = default_config.get("token_file", "token.txt")
    default_config["token_file_resolved"] = resolve_path(token_file)
    if not default_config.get("token"):
        default_config["token"] = get_or_create_token(default_config["token_file_resolved"])

    return default_config

config = load_config()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class SensorHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stdout.write(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}\n")
        sys.stdout.flush()

    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def verify_token(self, parsed_url):
        expected_token = config.get("token", "")
        if not expected_token:
            return True

        qs = parse_qs(parsed_url.query)
        if "token" in qs and qs["token"][0] == expected_token:
            return True

        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") and auth_header[7:].strip() == expected_token:
            return True

        if self.headers.get("X-Token", "").strip() == expected_token:
            return True

        return False

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path not in ("", "/sensor", "/sensor.json"):
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not Found"})
            return

        data_file = config.get("data_file", "/opt/monitor/data/sensor.json")
        if os.path.exists(data_file):
            try:
                with open(data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.send_json(HTTPStatus.OK, data)
                return
            except Exception as e:
                self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"Failed to read data: {str(e)}"})
                return

        self.send_json(HTTPStatus.OK, {})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path not in ("", "/sensor", "/sensor.json"):
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not Found"})
            return

        if not self.verify_token(parsed):
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized: Invalid or missing token"})
            return

        content_length = self.headers.get("Content-Length")
        if not content_length:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length header required"})
            return

        try:
            length = int(content_length)
            raw_data = self.rfile.read(length)
            payload = json.loads(raw_data.decode("utf-8"))
        except Exception as e:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON payload: {str(e)}"})
            return

        if not isinstance(payload, dict):
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Payload must be a JSON object"})
            return

        data_file = config.get("data_file", "/opt/monitor/data/sensor.json")
        try:
            target_dir = os.path.dirname(data_file)
            if target_dir:
                os.makedirs(target_dir, exist_ok=True)

            tmp_file = f"{data_file}.tmp.{os.getpid()}"
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            os.chmod(tmp_file, 0o644)
            shutil.move(tmp_file, data_file)

            # Try to fix ownership if monitor user/group exists
            try:
                import pwd
                p = pwd.getpwnam("monitor")
                os.chown(data_file, p.pw_uid, p.pw_gid)
            except Exception:
                pass

            self.send_json(HTTPStatus.OK, {"status": "ok", "message": "Sensor data saved", "data": payload})
        except Exception as e:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"Failed to save data: {str(e)}"})

def run():
    global config
    config = load_config()
    server_address = (config.get("host", "0.0.0.0"), int(config.get("port", 28088)))
    httpd = ThreadedHTTPServer(server_address, SensorHandler)
    print(f"Sensor Receiver listening on {server_address[0]}:{server_address[1]}")
    print(f"Token file: {config.get('token_file_resolved')}")
    print(f"Data file: {config.get('data_file')}")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

if __name__ == "__main__":
    run()
