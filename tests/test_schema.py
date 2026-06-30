"""Tests du schéma NetworkEvent (sérialisation + nouveaux champs)."""
from pipeline.schema import EventType, NetworkEvent, Severity


def test_roundtrip_preserves_fields():
    ev = NetworkEvent(
        event_type=EventType.ALERT, src_ip="1.2.3.4", dst_ip="5.6.7.8",
        dst_port=22, protocol="TCP", severity=Severity.HIGH,
        message="brute force", tags={"rule": "1000003"},
    )
    restored = NetworkEvent.from_json(ev.to_json())
    assert restored.src_ip == "1.2.3.4"
    assert restored.dst_port == 22
    assert restored.event_type is EventType.ALERT
    assert restored.severity is Severity.HIGH
    assert restored.tags["rule"] == "1000003"


def test_new_fields_have_defaults():
    ev = NetworkEvent(event_type=EventType.PACKET)
    assert ev.mitre == []
    assert ev.enrichment == {}


def test_from_json_accepts_vector_shape_without_new_fields():
    """Vector n'émet pas mitre/enrichment : from_json doit utiliser les défauts."""
    payload = (
        '{"event_type": "alert", "timestamp": "2026-01-01T00:00:00+00:00",'
        ' "event_id": "abcd1234", "src_ip": "9.9.9.9", "dst_ip": null,'
        ' "src_port": null, "dst_port": null, "protocol": "TCP", "interface": "eth0",'
        ' "message": "x", "raw": null, "severity": "high", "source": "suricata",'
        ' "tags": {"rule": "1000001"}, "metrics": {}}'
    )
    ev = NetworkEvent.from_json(payload)
    assert ev.src_ip == "9.9.9.9"
    assert ev.mitre == []
