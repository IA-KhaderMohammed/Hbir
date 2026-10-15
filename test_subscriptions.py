import sqlite3
import time
import unittest
from app import has_subscription_access

class SubscriptionLogicTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("""
            CREATE TABLE seasons (
                season_id TEXT PRIMARY KEY,
                title TEXT NOT NULL
            )
        """)
        self.db.execute("""
            CREATE TABLE video_catalog (
                video_id TEXT PRIMARY KEY,
                season_id TEXT NOT NULL
            )
        """)
        self.db.execute("""
            CREATE TABLE subscriptions (
                subscription_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                plan_type TEXT NOT NULL,
                scope TEXT NOT NULL,
                season_id TEXT,
                starts_at INTEGER NOT NULL,
                ends_at INTEGER NOT NULL,
                status TEXT NOT NULL
            )
        """)
        self.db.executemany(
            "INSERT INTO seasons VALUES (?, ?)",
            [("s1", "Season 1"), ("s2", "Season 2")]
        )
        self.db.executemany(
            "INSERT INTO video_catalog VALUES (?, ?)",
            [("v1", "s1"), ("v2", "s2")]
        )
        self.now = int(time.time())

    def tearDown(self):
        self.db.close()

    def add_subscription(self, plan, scope, season, start, end, status="active"):
        self.db.execute(
            """INSERT INTO subscriptions VALUES
               (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("sub-test", "alice", plan, scope, season, start, end, status)
        )

    def test_monthly_library_access(self):
        self.add_subscription(
            "monthly", "library", None,
            self.now - 10, self.now + 100
        )
        self.assertTrue(has_subscription_access(self.db, "alice", "v1", self.now))
        self.assertTrue(has_subscription_access(self.db, "alice", "v2", self.now))

    def test_season_subscription_only_matches_its_season(self):
        self.add_subscription(
            "season", "season", "s1",
            self.now - 10, self.now + 100
        )
        self.assertTrue(has_subscription_access(self.db, "alice", "v1", self.now))
        self.assertFalse(has_subscription_access(self.db, "alice", "v2", self.now))

    def test_expired_subscription_denied(self):
        self.add_subscription(
            "monthly", "library", None,
            self.now - 200, self.now - 1
        )
        self.assertFalse(has_subscription_access(self.db, "alice", "v1", self.now))

    def test_cancelled_subscription_denied(self):
        self.add_subscription(
            "monthly", "library", None,
            self.now - 10, self.now + 100, "cancelled"
        )
        self.assertFalse(has_subscription_access(self.db, "alice", "v1", self.now))

    def test_unknown_video_denied(self):
        self.add_subscription(
            "monthly", "library", None,
            self.now - 10, self.now + 100
        )
        self.assertFalse(has_subscription_access(self.db, "alice", "missing", self.now))

if __name__ == "__main__":
    unittest.main(verbosity=2)
