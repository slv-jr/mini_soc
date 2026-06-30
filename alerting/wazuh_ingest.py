"""
alerting/wazuh_ingest.py
Boucle de feedback : convertit une alerte Wazuh (JSON) en NetworkEvent et la
réinjecte dans la file Redis pour que le corrélateur Python la prenne en compte
au même titre que les alertes Suricata/Zeek.

Alimenté par le webhook Flask POST /api/wazuh-event (voir dashboard/topology.py),
lui-même nourri par l'intégration Wazuh docker/wazuh/integrations/custom-minisoc.py
"""
import logging

from pipeline.queue import get_queue
from pipeline.schema import EventType, NetworkEvent, Severity

logger = logging.getLogger(__name__)


def _severity_from_level(level: int) -> Severity:
    """Niveau de règle Wazuh (0-15) -> sévérité Mini-SOC."""
    if level >= 12:
        return Severity.CRITICAL
    if level >= 10:
        return Severity.HIGH
    if level >= 7:
        return Severity.MEDIUM
    if level >= 4:
        return Severity.LOW
    return Severity.INFO


def wazuh_alert_to_event(alert: dict) -> NetworkEvent:
    """Convertit le dict d'une alerte Wazuh en NetworkEvent normalisé."""
    rule = alert.get("rule", {}) or {}
    data = alert.get("data", {}) or {}
    agent = alert.get("agent", {}) or {}

    level = int(rule.get("level", 0) or 0)
    severity = _severity_from_level(level)

    src_ip = data.get("srcip") or data.get("src_ip") or alert.get("srcip")
    dst_ip = data.get("dstip") or data.get("dst_ip")

    mitre_ids = []
    mitre = rule.get("mitre") or {}
    if isinstance(mitre.get("id"), list):
        mitre_ids = [str(x) for x in mitre["id"]]
    elif mitre.get("id"):
        mitre_ids = [str(mitre["id"])]

    tags = {
        "rule": str(rule.get("id", "")),
        "rule_description": rule.get("description", ""),
        "rule_level": level,
        "wazuh_groups": rule.get("groups", []),
        "agent": agent.get("name", ""),
    }
    if "authentication_success" in (rule.get("groups") or []):
        tags["rule"] = "authentication_success"

    return NetworkEvent(
        event_type=EventType.ALERT,
        src_ip=src_ip,
        dst_ip=dst_ip,
        source="wazuh",
        severity=severity,
        message=rule.get("description", "Alerte Wazuh"),
        mitre=mitre_ids,
        tags=tags,
    )


def ingest_wazuh_alert(alert: dict) -> NetworkEvent:
    """Convertit et pousse l'alerte Wazuh dans la file Redis (pisoc:raw)."""
    event = wazuh_alert_to_event(alert)
    get_queue().push_event(event)
    logger.info(f"Alerte Wazuh réinjectée: {event.src_ip} L{alert.get('rule', {}).get('level')} "
                f"MITRE={event.mitre}")
    return event
