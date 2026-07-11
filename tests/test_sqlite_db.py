"""Tests du stockage SQLite (base temporaire, aucun service externe)."""
import pytest

import storage.sqlite_db as db_mod
from pipeline.schema import EventType, NetworkEvent, Severity
from storage.sqlite_db import SQLiteStorage


@pytest.fixture
def db(monkeypatch, tmp_path):
    path = tmp_path / "events.db"
    monkeypatch.setattr(db_mod.loader, "get", lambda key, default=None: str(path))
    return SQLiteStorage()


def test_save_event_is_idempotent(db):
    ev = NetworkEvent(event_type=EventType.ALERT, src_ip="1.2.3.4",
                      severity=Severity.HIGH, message="x", tags={"rule": "1"})
    db.save_event(ev)
    db.save_event(ev)  # même event_id -> INSERT OR IGNORE
    assert db.get_stats()["total_events"] == 1


def test_recent_alerts_filtered_by_severity(db):
    db.save_event(NetworkEvent(event_type=EventType.ALERT, src_ip="1.1.1.1",
                               severity=Severity.HIGH, message="h"))
    db.save_event(NetworkEvent(event_type=EventType.ALERT, src_ip="2.2.2.2",
                               severity=Severity.LOW, message="l"))
    highs = db.get_recent_alerts(severity="high")
    assert len(highs) == 1
    assert highs[0]["src_ip"] == "1.1.1.1"


def test_incident_lifecycle(db):
    inc_id = db.create_incident(title="t", description="d", severity=Severity.CRITICAL,
                                src_ip="9.9.9.9", rule_name="correlator", event_ids=["a"])
    assert db.get_stats()["open_incidents"] == 1
    db.resolve_incident(inc_id)
    assert db.get_open_incidents() == []


def test_block_and_is_blocked(db):
    db.block_ip("5.5.5.5", reason="test", duration_seconds=3600)
    assert db.is_blocked("5.5.5.5") is True
    assert db.is_blocked("6.6.6.6") is False


def test_expired_block_not_active(db):
    db.block_ip("7.7.7.7", reason="test", duration_seconds=-10)  # déjà expiré
    assert db.is_blocked("7.7.7.7") is False
