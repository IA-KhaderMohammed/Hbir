import os
import json
import secrets
import sqlite3
import threading
import time
import unittest
from unittest.mock import patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer

os.environ.setdefault("VSG_DEMO_PASSWORD", "DemoOnly-Change-2026!")

from app import (
    Handler,
    DB,
    verify_token,
    sign_token,
    password_hash,
)


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(
            target=cls.server.serve_forever,
            daemon=True,
        )
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, path, method="GET", data=None, token=None):
        headers = {}
        raw = None

        if data is not None:
            raw = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"

        if token:
            headers["Authorization"] = "Bearer " + token

        req = Request(
            self.base + path,
            data=raw,
            headers=headers,
            method=method,
        )

        try:
            with urlopen(req) as res:
                return res.status, json.loads(res.read())
        except HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read())
            finally:
                exc.close()

    def test_health(self):
        self.assertEqual(self.request("/health")[0], 200)

    def test_bad_login_rejected(self):
        username = "audit_login_" + secrets.token_hex(4)

        status, _ = self.request(
            "/login",
            "POST",
            {
                "username": username,
                "password": "wrong",
            },
        )
        self.assertEqual(status, 401)

        with sqlite3.connect(DB) as db:
            event = db.execute(
                """
                SELECT outcome
                FROM security_audit
                WHERE event_type = 'login' AND username = ?
                ORDER BY event_id DESC
                LIMIT 1
                """,
                (username,),
            ).fetchone()

        self.assertIsNotNone(event)
        self.assertEqual(event[0], "denied")

    def test_audit_failure_blocks_authorization(self):
        with patch(
            "app.audit_event",
            side_effect=OSError("simulated audit failure"),
        ):
            status, data = self.request(
                "/authorize",
                "POST",
                {
                    "username": "demo",
                    "password": "DemoOnly-Change-2026!",
                    "video_id": "demo-video",
                },
            )

        self.assertEqual(status, 503)
        self.assertEqual(
            data["error"],
            "authorization_temporarily_unavailable",
        )
        self.assertNotIn("access_token", data)

    def test_entitled_user_gets_token(self):
        status, data = self.request(
            "/authorize",
            "POST",
            {
                "username": "demo",
                "password": "DemoOnly-Change-2026!",
                "video_id": "demo-video",
            },
        )

        self.assertEqual(status, 200)
        self.assertTrue(verify_token(data["access_token"]))

        with sqlite3.connect(DB) as db:
            event = db.execute(
                """
                SELECT outcome
                FROM security_audit
                WHERE event_type = 'authorize'
                  AND username = 'demo'
                  AND video_id = 'demo-video'
                ORDER BY event_id DESC
                LIMIT 1
                """
            ).fetchone()

        self.assertIsNotNone(event)
        self.assertEqual(event[0], "success")

    def test_missing_token_rejected(self):
        self.assertEqual(
            self.request("/videos/demo-video")[0],
            401,
        )

    def test_missing_token_is_audited(self):
        status, _ = self.request("/videos/demo-video")
        self.assertEqual(status, 401)

        with sqlite3.connect(DB) as db:
            event = db.execute(
                """
                SELECT outcome, video_id
                FROM security_audit
                WHERE event_type = 'playback'
                  AND username IS NULL
                  AND video_id = 'demo-video'
                ORDER BY event_id DESC
                LIMIT 1
                """
            ).fetchone()

        self.assertIsNotNone(event)
        self.assertEqual(event, ("denied", "demo-video"))

    def test_unknown_video_denied(self):
        status, _ = self.request(
            "/authorize",
            "POST",
            {
                "username": "demo",
                "password": "DemoOnly-Change-2026!",
                "video_id": "other-video",
            },
        )
        self.assertEqual(status, 403)

    def test_unknown_video_denial_is_audited(self):
        status, _ = self.request(
            "/authorize",
            "POST",
            {
                "username": "demo",
                "password": "DemoOnly-Change-2026!",
                "video_id": "other-video",
            },
        )
        self.assertEqual(status, 403)

        with sqlite3.connect(DB) as db:
            event = db.execute(
                """
                SELECT outcome, video_id
                FROM security_audit
                WHERE event_type = 'authorize'
                  AND username = 'demo'
                  AND video_id = 'other-video'
                ORDER BY event_id DESC
                LIMIT 1
                """
            ).fetchone()

        self.assertEqual(event, ("denied", "other-video"))

    def test_tampered_token_rejected(self):
        token = sign_token(
            "demo",
            "demo-video",
            int(time.time()) + 120,
            "test",
        )
        self.assertIsNone(verify_token(token + "x"))

    def test_audit_failure_blocks_playback(self):
        _, data = self.request(
            "/authorize",
            "POST",
            {
                "username": "demo",
                "password": "DemoOnly-Change-2026!",
                "video_id": "demo-video",
            },
        )
        token = data["access_token"]

        with patch(
            "app.audit_event",
            side_effect=OSError("simulated audit failure"),
        ):
            status, result = self.request(
                "/videos/demo-video",
                token=token,
            )

        self.assertEqual(status, 503)
        self.assertNotIn("payload", result)

    def test_authorized_playback(self):
        _, data = self.request(
            "/authorize",
            "POST",
            {
                "username": "demo",
                "password": "DemoOnly-Change-2026!",
                "video_id": "demo-video",
            },
        )

        status, result = self.request(
            "/videos/demo-video",
            token=data["access_token"],
        )

        self.assertEqual(status, 200)
        self.assertEqual(result["video_id"], "demo-video")

        with sqlite3.connect(DB) as db:
            event = db.execute(
                """
                SELECT outcome
                FROM security_audit
                WHERE event_type = 'playback'
                  AND username = 'demo'
                  AND video_id = 'demo-video'
                ORDER BY event_id DESC
                LIMIT 1
                """
            ).fetchone()

        self.assertIsNotNone(event)
        self.assertEqual(event[0], "success")

    def test_revoked_subscription_denies_existing_token(self):
        username = "revoke_" + secrets.token_hex(4)
        password = "Temporary-Test-Password!"
        salt = secrets.token_bytes(16)
        now = int(time.time())
        subscription_id = "sub-" + username

        try:
            with sqlite3.connect(DB) as db:
                db.execute(
                    """
                    INSERT INTO users (username, salt, password_hash)
                    VALUES (?, ?, ?)
                    """,
                    (
                        username,
                        salt,
                        password_hash(password, salt),
                    ),
                )

                db.execute(
                    """
                    INSERT INTO subscriptions
                    (
                        subscription_id,
                        username,
                        plan_type,
                        scope,
                        season_id,
                        starts_at,
                        ends_at,
                        status
                    )
                    VALUES (?, ?, 'monthly', 'library', NULL, ?, ?, 'active')
                    """,
                    (
                        subscription_id,
                        username,
                        now - 10,
                        now + 300,
                    ),
                )

            status, data = self.request(
                "/authorize",
                "POST",
                {
                    "username": username,
                    "password": password,
                    "video_id": "demo-video",
                },
            )

            self.assertEqual(status, 200)
            token = data["access_token"]

            with sqlite3.connect(DB) as db:
                db.execute(
                    """
                    UPDATE subscriptions
                    SET status = 'cancelled'
                    WHERE subscription_id = ?
                    """,
                    (subscription_id,),
                )

            status, _ = self.request(
                "/videos/demo-video",
                token=token,
            )

            self.assertEqual(status, 403)

        finally:
            with sqlite3.connect(DB) as db:
                db.execute(
                    "DELETE FROM subscriptions WHERE subscription_id = ?",
                    (subscription_id,),
                )
                db.execute(
                    "DELETE FROM users WHERE username = ?",
                    (username,),
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
