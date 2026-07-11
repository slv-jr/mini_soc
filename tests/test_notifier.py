"""Tests de la logique de seuil de sévérité et du formatage threat-intel."""
from alerting.notifier import _geo_str, _mitre_str, _severity_gte
from pipeline.schema import EventType, NetworkEvent, Severity


def test_severity_gte_ordering():
    assert _severity_gte(Severity.HIGH, "medium") is True
    assert _severity_gte(Severity.LOW, "high") is False
    assert _severity_gte(Severity.CRITICAL, "critical") is True


def test_mitre_str_empty_and_filled():
    ev = NetworkEvent(event_type=EventType.ALERT)
    assert _mitre_str(ev) == "—"
    ev.mitre = ["T1046", "T1110"]
    assert _mitre_str(ev) == "T1046, T1110"


def test_geo_str_builds_from_enrichment():
    ev = NetworkEvent(event_type=EventType.ALERT)
    assert _geo_str(ev) == ""
    ev.enrichment = {"country": "RU", "abuse_confidence": 90, "malicious": True}
    out = _geo_str(ev)
    assert "RU" in out and "90%" in out and "malveillante" in out
