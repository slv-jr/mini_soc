"""Tests de la conversion alerte Wazuh -> NetworkEvent."""
from alerting.wazuh_ingest import _severity_from_level, wazuh_alert_to_event
from pipeline.schema import EventType, Severity


def test_level_to_severity():
    assert _severity_from_level(13) is Severity.CRITICAL
    assert _severity_from_level(10) is Severity.HIGH
    assert _severity_from_level(7) is Severity.MEDIUM
    assert _severity_from_level(4) is Severity.LOW
    assert _severity_from_level(1) is Severity.INFO


def test_convert_basic_alert():
    alert = {
        "rule": {"level": 10, "description": "SSH brute force", "id": "5712",
                 "mitre": {"id": ["T1110"]}, "groups": ["authentication_failures"]},
        "data": {"srcip": "10.0.0.5"},
        "agent": {"name": "host01"},
    }
    ev = wazuh_alert_to_event(alert)
    assert ev.event_type is EventType.ALERT
    assert ev.src_ip == "10.0.0.5"
    assert ev.severity is Severity.HIGH
    assert ev.mitre == ["T1110"]
    assert ev.source == "wazuh"


def test_auth_success_group_marks_rule():
    alert = {
        "rule": {"level": 12, "description": "auth success", "id": "100020",
                 "groups": ["authentication_success"]},
        "data": {"srcip": "10.0.0.6"},
    }
    ev = wazuh_alert_to_event(alert)
    assert ev.tags["rule"] == "authentication_success"
    assert ev.severity is Severity.CRITICAL


def test_mitre_id_as_scalar():
    alert = {"rule": {"level": 5, "description": "x", "mitre": {"id": "T1046"}}, "data": {}}
    ev = wazuh_alert_to_event(alert)
    assert ev.mitre == ["T1046"]
