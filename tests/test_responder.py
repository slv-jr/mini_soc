"""Tests de la logique de décision du responder SOAR (sans nftables ni réseau)."""
import pytest

import alerting.responder as resp_mod
from alerting.responder import Responder, _sev_gte
from pipeline.schema import EventType, NetworkEvent, Severity


class _FakeDB:
    def __init__(self):
        self.blocked = {}

    def is_blocked(self, ip):
        return ip in self.blocked

    def block_ip(self, ip, reason, duration):
        self.blocked[ip] = reason


@pytest.fixture
def fake_db(monkeypatch):
    db = _FakeDB()
    monkeypatch.setattr(resp_mod, "get_db", lambda: db)
    return db


def _alert(ip, severity=Severity.HIGH):
    return NetworkEvent(event_type=EventType.ALERT, src_ip=ip,
                        severity=severity, message="x")


def test_sev_gte():
    assert _sev_gte(Severity.HIGH, "high") is True
    assert _sev_gte(Severity.MEDIUM, "high") is False


def test_whitelisted_ip_not_blocked(fake_db):
    r = Responder()
    r._whitelist = {"127.0.0.1"}
    assert r.handle_alert(_alert("127.0.0.1")) is False


def test_below_threshold_not_blocked(fake_db):
    r = Responder()
    r._auto_block = True
    r._min_sev = "high"
    assert r.handle_alert(_alert("8.8.8.8", Severity.LOW)) is False


def test_suggestion_mode_does_not_block(fake_db):
    r = Responder()
    r._auto_block = False
    assert r.handle_alert(_alert("8.8.8.8")) is False
    assert fake_db.blocked == {}


def test_auto_block_blocks_via_backend(fake_db, monkeypatch):
    r = Responder()
    r._auto_block = True
    r._min_sev = "high"
    r._prefer_wazuh = False
    r._whitelist = set()
    monkeypatch.setattr(r, "_block_via_nftables", lambda ip: True)
    monkeypatch.setattr(r, "_schedule_unblock", lambda ip, d: None)
    assert r.handle_alert(_alert("8.8.8.8")) is True
    assert "8.8.8.8" in fake_db.blocked
