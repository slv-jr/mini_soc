"""
storage/sqlite_db.py
Base SQLite pour les événements de sécurité et incidents.
Tout ce qu'on veut interroger par IP, type, date, statut.
"""
import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from config import loader
from pipeline.schema import NetworkEvent, Severity

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    src_ip      TEXT,
    dst_ip      TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    protocol    TEXT,
    severity    TEXT NOT NULL,
    source      TEXT,
    message     TEXT,
    tags        TEXT,
    metrics     TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_ip     ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity   ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);

CREATE TABLE IF NOT EXISTS incidents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT NOT NULL,
    description  TEXT,
    severity     TEXT NOT NULL,
    status       TEXT DEFAULT 'open',   -- open, investigating, resolved
    src_ip       TEXT,
    rule_name    TEXT,
    event_ids    TEXT,                  -- JSON array
    created_at   TEXT DEFAULT (datetime('now')),
    updated_at   TEXT DEFAULT (datetime('now')),
    resolved_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_src_ip   ON incidents(src_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip          TEXT PRIMARY KEY,
    reason      TEXT,
    blocked_at  TEXT DEFAULT (datetime('now')),
    expires_at  TEXT,
    active      INTEGER DEFAULT 1
);
"""


class SQLiteStorage:
    def __init__(self):
        db_path = loader.get("sqlite.path", "data/events.db")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._path = db_path
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA)
        logger.info(f"SQLite initialisé: {self._path}")

    def save_event(self, event: NetworkEvent) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO events
                   (id, timestamp, event_type, src_ip, dst_ip, src_port, dst_port,
                    protocol, severity, source, message, tags, metrics)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.event_type.value,
                    event.src_ip,
                    event.dst_ip,
                    event.src_port,
                    event.dst_port,
                    event.protocol,
                    event.severity.value,
                    event.source,
                    event.message,
                    json.dumps(event.tags),
                    json.dumps(event.metrics),
                ),
            )

    def create_incident(self, title: str, description: str, severity: Severity,
                        src_ip: str, rule_name: str,
                        event_ids: list[str] | None = None) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO incidents (title, description, severity, src_ip, rule_name, event_ids)
                   VALUES (?,?,?,?,?,?)""",
                (title, description, severity.value, src_ip, rule_name,
                 json.dumps(event_ids or [])),
            )
            incident_id = cur.lastrowid
            logger.info(f"Incident #{incident_id} créé: {title} [{severity.value}] src={src_ip}")
            return incident_id

    def resolve_incident(self, incident_id: int) -> None:
        with self._conn() as conn:
            conn.execute(
                """UPDATE incidents SET status='resolved',
                   resolved_at=datetime('now'), updated_at=datetime('now')
                   WHERE id=?""",
                (incident_id,),
            )

    def get_open_incidents(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE status != 'resolved' ORDER BY created_at DESC LIMIT 50"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_recent_alerts(self, limit: int = 100, severity: str | None = None) -> list[dict]:
        with self._conn() as conn:
            if severity:
                rows = conn.execute(
                    "SELECT * FROM events WHERE event_type='alert' AND severity=? ORDER BY timestamp DESC LIMIT ?",
                    (severity, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM events WHERE event_type='alert' ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]

    def block_ip(self, ip: str, reason: str, duration_seconds: int = 3600) -> None:
        from datetime import timedelta
        expires = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO blocked_ips (ip, reason, expires_at, active)
                   VALUES (?,?,?,1)""",
                (ip, reason, expires.isoformat()),
            )

    def is_blocked(self, ip: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT ip FROM blocked_ips WHERE ip=? AND active=1 AND expires_at > datetime('now')",
                (ip,),
            ).fetchone()
            return row is not None

    def get_stats(self) -> dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            alerts = conn.execute("SELECT COUNT(*) FROM events WHERE event_type='alert'").fetchone()[0]
            open_inc = conn.execute("SELECT COUNT(*) FROM incidents WHERE status='open'").fetchone()[0]
            blocked = conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE active=1").fetchone()[0]
        return {
            "total_events": total,
            "total_alerts": alerts,
            "open_incidents": open_inc,
            "blocked_ips": blocked,
        }


_db: SQLiteStorage | None = None


def get_db() -> SQLiteStorage:
    global _db
    if _db is None:
        _db = SQLiteStorage()
    return _db
