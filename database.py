# database.py
# Lightweight SQLite persistence layer for alerts. Unlike the in-memory list,
# this survives restarts so you keep a permanent history of every detection.
# SQLite ships with Python's standard library — no extra install needed.

import sqlite3
import threading


class AlertDatabase:
    """
    Thread-safe wrapper around a single SQLite file.

    Scapy/Flask touch this from several threads, and SQLite connections are not
    safe to share across threads, so every method opens a short-lived connection
    guarded by one lock. The traffic volume here (a few writes per alert) makes
    that perfectly fast enough.
    """

    def __init__(self, db_file="ids.db"):
        self.db_file = db_file
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self):
        return sqlite3.connect(self.db_file)

    def _init_schema(self):
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT    NOT NULL,
                    attacker_ip TEXT    NOT NULL,
                    attack_type TEXT    NOT NULL,
                    severity    TEXT    NOT NULL,
                    details     TEXT
                )
                """
            )
            # Index the columns the dashboard filters/sorts on most.
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)"
            )

    def insert(self, alert: dict):
        """Persist one alert dict (same shape AlertSystem builds)."""
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO alerts (timestamp, attacker_ip, attack_type, severity, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    alert["timestamp"],
                    alert["attacker_ip"],
                    alert["attack_type"],
                    alert["severity"],
                    alert.get("details", ""),
                ),
            )

    def recent(self, limit=500):
        """Return the most recent alerts, newest first, as a list of dicts."""
        with self._lock, self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def count(self):
        """Total number of alerts ever recorded."""
        with self._lock, self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
