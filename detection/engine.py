"""
detection/engine.py
Cœur du Mini-SOC — consomme la file Redis (alimentée par Vector depuis
Suricata/Zeek), enrichit (MITRE + threat intel), corrèle en chaînes d'attaque,
persiste, notifie et déclenche la réponse SOAR.

La détection bas niveau (signatures, scans, brute force) est désormais assurée
par Suricata/Zeek/Wazuh ; le moteur Python se concentre sur l'enrichissement,
la corrélation multi-source et l'orchestration.
"""
import logging

from alerting.notifier import get_notifier
from alerting.responder import get_responder
from detection.correlator import Correlator
from detection.enricher import get_enricher
from detection.mitre import get_mapper
from pipeline.queue import get_queue
from pipeline.schema import EventType, NetworkEvent
from storage.influx import get_influx
from storage.sqlite_db import get_db

logger = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self):
        self._mitre = get_mapper()
        self._enricher = get_enricher()
        self._correlator = Correlator()
        self._queue = get_queue()
        self._influx = get_influx()
        self._db = get_db()
        self._notifier = get_notifier()
        self._responder = get_responder()
        self._processed = 0
        self._alerts_fired = 0

    def handle_event(self, event: NetworkEvent) -> None:
        """Point d'entrée unique pour chaque événement normalisé entrant."""
        self._processed += 1

        if event.event_type == EventType.PACKET:
            # Flux réseau (Suricata flow / Zeek conn) -> métriques time-series.
            self._influx.write_packet(
                src_ip=event.src_ip or "unknown",
                dst_ip=event.dst_ip or "unknown",
                protocol=event.protocol or "unknown",
                bytes_count=event.metrics.get("bytes", 0),
                interface=event.interface or "eth0",
            )
            return

        if event.event_type in (EventType.ALERT, EventType.ANOMALY):
            self._handle_alert(event)

    def _handle_alert(self, alert: NetworkEvent) -> None:
        self._alerts_fired += 1

        # 1. Tag MITRE ATT&CK (lit les metadata Suricata/Zeek ou mappe les SID).
        techniques = self._mitre.tag(alert)

        # 2. Enrichissement threat-intel de l'IP source (GeoIP + réputation).
        if alert.src_ip:
            alert.enrichment = self._enricher.enrich(alert.src_ip)

        # 3. Persistance + métriques.
        self._db.save_event(alert)
        self._influx.write_alert(
            rule_name=str(alert.tags.get("rule", alert.source or "alert")),
            src_ip=alert.src_ip or "unknown",
            severity=alert.severity.value,
        )

        # 4. Diffusion temps réel (dashboard) + notification multi-canal.
        self._queue.push_alert(alert)
        self._notifier.notify(alert)

        if techniques:
            logger.info(f"Alerte {alert.src_ip} -> MITRE {[t.id for t in techniques]}")

        # 5. Corrélation -> incident éventuel.
        incident = self._correlator.correlate(alert)
        if incident:
            self._handle_incident(incident)
        else:
            # Réponse possible même sans incident corrélé (selon seuil/config).
            self._responder.handle_alert(alert)

    def _handle_incident(self, incident: NetworkEvent) -> None:
        self._db.save_event(incident)
        self._queue.push_alert(incident)
        self._notifier.notify(incident)
        self._responder.handle_alert(incident)
        logger.critical(f"INCIDENT: {incident.message} | src={incident.src_ip}")

    def run(self) -> None:
        logger.info("Moteur de détection démarré (consommation de la file Redis)")
        self._queue.consume_loop(self.handle_event)

    def stats(self) -> dict:
        return {
            "processed": self._processed,
            "alerts_fired": self._alerts_fired,
            "queue": self._queue.stats(),
            "active_attack_contexts": len(self._correlator.get_active_contexts()),
        }
