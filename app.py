import os
import json
import time
import hmac
import base64
import hashlib
import secrets
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(ROOT, "gateway.db")
KEYFILE = os.path.join(ROOT, ".gateway-key")
DEMO_USER = "demo"
DEMO_PASSWORD = os.environ.get("VSG_DEMO_PASSWORD")

if not os.path.exists(KEYFILE):
    fd = os.open(KEYFILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(secrets.token_bytes(32))

with open(KEYFILE, "rb") as f:
    MASTER_KEY = f.read()

if len(MASTER_KEY) != 32:
    raise RuntimeError("Invalid gateway key")

def connect():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


from contextlib import contextmanager

@contextmanager
def db_connection():
    db = connect()
    try:
        with db:
            yield db
    finally:
        db.close()

def password_hash(password, salt):
    return hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1
    )

def init_db():
    with db_connection() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS entitlements (
                username TEXT NOT NULL,
                video_id TEXT NOT NULL,
                PRIMARY KEY(username, video_id)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS seasons (
                season_id TEXT PRIMARY KEY,
                title TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS video_catalog (
                video_id TEXT PRIMARY KEY,
                season_id TEXT NOT NULL REFERENCES seasons(season_id)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                subscription_id TEXT PRIMARY KEY,
                username TEXT NOT NULL REFERENCES users(username),
                plan_type TEXT NOT NULL CHECK(plan_type IN ('monthly', 'season')),
                scope TEXT NOT NULL CHECK(scope IN ('library', 'season')),
                season_id TEXT REFERENCES seasons(season_id),
                starts_at INTEGER NOT NULL,
                ends_at INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('active', 'cancelled', 'expired')),
                CHECK(ends_at > starts_at),
                CHECK(
                    (scope = 'library' AND plan_type = 'monthly' AND season_id IS NULL)
                    OR
                    (scope = 'season' AND plan_type = 'season' AND season_id IS NOT NULL)
                )
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS security_audit (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                username TEXT,
                video_id TEXT,
                outcome TEXT NOT NULL CHECK(
                    outcome IN ('success', 'denied', 'error')
                ),
                created_at INTEGER NOT NULL
            )
        """)
        db.execute(
            "INSERT OR IGNORE INTO seasons (season_id, title) VALUES (?, ?)",
            ("demo-season", "Demo Season")
        )
        db.execute(
            "INSERT OR IGNORE INTO video_catalog (video_id, season_id) VALUES (?, ?)",
            ("demo-video", "demo-season")
        )
        row = db.execute(
            "SELECT username FROM users WHERE username = ?", (DEMO_USER,)
        ).fetchone()
        if row is None and DEMO_PASSWORD:
            salt = secrets.token_bytes(16)
            db.execute(
                "INSERT INTO users VALUES (?, ?, ?)",
                (DEMO_USER, salt, password_hash(DEMO_PASSWORD, salt))
            )
        db.execute(
            "INSERT OR IGNORE INTO entitlements VALUES (?, ?)",
            (DEMO_USER, "demo-video")
        )


def audit_event(event_type, outcome, username=None, video_id=None):
    allowed_outcomes = {"success", "denied", "error"}
    if outcome not in allowed_outcomes:
        raise ValueError("Invalid audit outcome")

    with db_connection() as db:
        db.execute(
            """
            INSERT INTO security_audit
                (event_type, username, video_id, outcome, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(event_type)[:80],
                str(username)[:100] if username else None,
                str(video_id)[:100] if video_id else None,
                outcome,
                int(time.time()),
            ),
        )


def has_subscription_access(db, username, video_id, now=None):
    now = int(time.time()) if now is None else int(now)
    row = db.execute(
        """
        SELECT 1
        FROM video_catalog AS v
        JOIN subscriptions AS s ON s.username = ?
        WHERE v.video_id = ?
          AND s.status = 'active'
          AND s.starts_at <= ?
          AND s.ends_at > ?
          AND (
              (s.scope = 'library' AND s.plan_type = 'monthly')
              OR
              (s.scope = 'season' AND s.plan_type = 'season'
               AND s.season_id = v.season_id)
          )
        LIMIT 1
        """,
        (username, video_id, now, now)
    ).fetchone()
    return row is not None


def sign_token(username, video_id, expiry, nonce):
    payload = json.dumps(
        {"sub": username, "vid": video_id, "exp": expiry, "jti": nonce},
        separators=(",", ":"), sort_keys=True
    ).encode()
    body = base64.urlsafe_b64encode(payload).rstrip(b"=")
    sig = hmac.new(MASTER_KEY, body, hashlib.sha256).digest()
    return (body + b"." + base64.urlsafe_b64encode(sig).rstrip(b"=")).decode()

def verify_token(token):
    try:
        body, signature = token.encode().split(b".", 1)
        expected = hmac.new(MASTER_KEY, body, hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(
            signature + b"=" * (-len(signature) % 4)
        )
        if not hmac.compare_digest(expected, supplied):
            return None
        payload = json.loads(base64.urlsafe_b64decode(
            body + b"=" * (-len(body) % 4)
        ))
        if not isinstance(payload.get("exp"), int) or payload["exp"] <= int(time.time()):
            return None
        if not all(isinstance(payload.get(k), str) for k in ("sub", "vid", "jti")):
            return None
        return payload
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None

# Encrypted educational sample, not a real video or DRM license.
NONCE = secrets.token_bytes(12)
SAMPLE_CIPHERTEXT = AESGCM(MASTER_KEY).encrypt(
    NONCE, b"Protected demo video payload", b"demo-video"
)

class Handler(BaseHTTPRequestHandler):
    def respond(self, status, data):
        raw = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > 4096:
            raise ValueError("Invalid body size")
        data = json.loads(self.rfile.read(length))
        if not isinstance(data, dict):
            raise ValueError("JSON object required")
        return data

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            return self.respond(200, {"status": "ok"})
        if path == "/videos/demo-video":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                audit_event("playback", "denied", video_id="demo-video")
                return self.respond(401, {"error": "token_required"})
            payload = verify_token(auth[7:])
            if not payload or payload["vid"] != "demo-video":
                audit_event("playback", "denied", video_id="demo-video")
                return self.respond(403, {"error": "invalid_or_expired_token"})
            with db_connection() as db:
                entitled = has_subscription_access(
                    db, payload["sub"], payload["vid"]
                )
            if not entitled:
                audit_event(
                    "playback", "denied",
                    username=payload["sub"], video_id=payload["vid"]
                )
                return self.respond(403, {"error": "subscription_required"})
            try:
                audit_event(
                    "playback", "success",
                    username=payload["sub"], video_id=payload["vid"],
                )
            except Exception:
                return self.respond(
                    503,
                    {"error": "playback_temporarily_unavailable"},
                )

            # Demo only: decrypts a text payload, not a video stream.
            sample = AESGCM(MASTER_KEY).decrypt(
                NONCE, SAMPLE_CIPHERTEXT, b"demo-video"
            ).decode()
            return self.respond(200, {
                "video_id": "demo-video",
                "payload": sample,
                "note": "Educational simulation; not production DRM."
            })
        return self.respond(404, {"error": "not_found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/login":
            try:
                data = self.body()
            except (ValueError, json.JSONDecodeError):
                return self.respond(400, {"error": "invalid_json"})
            username, password = data.get("username"), data.get("password")
            if not isinstance(username, str) or not isinstance(password, str):
                return self.respond(400, {"error": "credentials_required"})
            if len(password) > 256 or len(username) > 100:
                return self.respond(400, {"error": "invalid_credentials"})
            with db_connection() as db:
                row = db.execute(
                    "SELECT salt, password_hash FROM users WHERE username=?",
                    (username,)
                ).fetchone()
            if not row or not hmac.compare_digest(
                password_hash(password, row["salt"]),
                row["password_hash"]
            ):
                audit_event("login", "denied", username=username)
                return self.respond(401, {"error": "invalid_credentials"})
            audit_event("login", "success", username=username)
            return self.respond(200, {"message": "login_ok"})
        if path == "/authorize":
            try:
                data = self.body()
            except (ValueError, json.JSONDecodeError):
                return self.respond(400, {"error": "invalid_json"})
            username, password = data.get("username"), data.get("password")
            video_id = data.get("video_id")
            if not all(isinstance(v, str) for v in (username, password, video_id)):
                return self.respond(400, {"error": "credentials_and_video_required"})
            with db_connection() as db:
                row = db.execute(
                    "SELECT salt, password_hash FROM users WHERE username=?",
                    (username,)
                ).fetchone()

                credentials_valid = bool(
                    row and hmac.compare_digest(
                        password_hash(password, row["salt"]),
                        row["password_hash"],
                    )
                )

                entitled = (
                    has_subscription_access(db, username, video_id)
                    if credentials_valid else False
                )

            if not credentials_valid:
                audit_event(
                    "authorize", "denied",
                    username=username, video_id=video_id,
                )
                return self.respond(401, {"error": "invalid_credentials"})
            if not entitled:
                audit_event("authorize", "denied", username=username,
                            video_id=video_id)
                return self.respond(403, {"error": "subscription_required"})
            token = sign_token(username, video_id, int(time.time()) + 120,
                               secrets.token_urlsafe(12))
            try:
                audit_event(
                    "authorize", "success",
                    username=username, video_id=video_id,
                )
            except Exception:
                return self.respond(
                    503,
                    {"error": "authorization_temporarily_unavailable"},
                )

            return self.respond(
                200, {"access_token": token, "expires_in": 120}
            )
        return self.respond(404, {"error": "not_found"})

    def log_message(self, fmt, *args):
        pass

init_db()

if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8765), Handler)
    print("Video Security Gateway listening on 0.0.0.0:8765")
    print("Local educational prototype only. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nGateway stopped.")
    finally:
        server.server_close()
