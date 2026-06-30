"""Tests du mapping MITRE."""
from detection.mitre import MitreMapper, resolve
from pipeline.schema import EventType, NetworkEvent, Severity


def _alert(tags):
    return NetworkEvent(event_type=EventType.ALERT, src_ip="1.1.1.1",
                        severity=Severity.HIGH, message="t", tags=tags)


def test_resolve_known_technique():
    t = resolve("T1110")
    assert t.name == "Brute Force"
    assert t.tactic_id == "TA0006"


def test_resolve_unknown_is_safe():
    t = resolve("T9999")
    assert t.name == "Unknown Technique"


def test_tag_by_suricata_sid():
    m = MitreMapper()
    techs = m.tag(_alert({"rule": "1000003"}))
    assert "T1110" in [t.id for t in techs]


def test_tag_by_metadata_list():
    """Suricata émet les metadata en listes."""
    m = MitreMapper()
    ev = _alert({"mitre_technique_id": ["T1046", "T1190"]})
    techs = m.tag(ev)
    ids = [t.id for t in techs]
    assert "T1046" in ids and "T1190" in ids
    assert ev.mitre  # le champ event.mitre est rempli


def test_tag_by_rule_name():
    m = MitreMapper()
    techs = m.tag(_alert({"rule": "Possible_Beacon"}))
    assert "T1071" in [t.id for t in techs]


def test_techniques_sorted_by_kill_chain():
    m = MitreMapper()
    ev = _alert({"mitre_technique_id": ["T1110", "T1046"]})
    techs = m.tag(ev)
    # Discovery (T1046) doit précéder Credential Access (T1110)
    assert techs[0].id == "T1046"
