"""Tests du corrélateur (chaînes MITRE)."""
import pytest

import detection.correlator as corr_mod
from detection.correlator import Correlator
from detection.mitre import get_mapper
from pipeline.schema import EventType, NetworkEvent, Severity


class _FakeDB:
    def __init__(self):
        self.incidents = []

    def create_incident(self, **kwargs):
        self.incidents.append(kwargs)
        return len(self.incidents)


@pytest.fixture(autouse=True)
def fake_db(monkeypatch):
    db = _FakeDB()
    monkeypatch.setattr(corr_mod, "get_db", lambda: db)
    return db


def _alert(ip, tags, severity=Severity.HIGH, mitre=None):
    ev = NetworkEvent(event_type=EventType.ALERT, src_ip=ip,
                      severity=severity, message="t", tags=tags)
    if mitre is not None:
        ev.mitre = mitre
    else:
        get_mapper().tag(ev)
    return ev


def test_single_alert_no_incident():
    c = Correlator()
    assert c.correlate(_alert("2.2.2.2", {"rule": "1000001"})) is None


def test_recon_then_bruteforce_creates_high_incident(fake_db):
    c = Correlator()
    assert c.correlate(_alert("3.3.3.3", {"rule": "1000001"})) is None  # T1046
    incident = c.correlate(_alert("3.3.3.3", {"rule": "1000003"}))      # T1110
    assert incident is not None
    assert incident.severity is Severity.HIGH
    assert incident.event_type is EventType.INCIDENT
    assert len(fake_db.incidents) == 1


def test_auth_success_after_brute_escalates_to_critical():
    c = Correlator()
    c.correlate(_alert("4.4.4.4", {"rule": "1000003"}))  # T1110
    crit = c.correlate(_alert("4.4.4.4", {"rule": "authentication_success"},
                              severity=Severity.CRITICAL, mitre=["T1110"]))
    assert crit is not None
    assert crit.severity is Severity.CRITICAL


def test_beacon_creates_incident():
    c = Correlator()
    incident = c.correlate(_alert("5.5.5.5", {"rule": "Possible_Beacon"}))
    assert incident is not None
    assert "T1071" in incident.mitre


def test_no_incident_for_non_alert_event():
    c = Correlator()
    pkt = NetworkEvent(event_type=EventType.PACKET, src_ip="6.6.6.6")
    assert c.correlate(pkt) is None
