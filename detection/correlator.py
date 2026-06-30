"""
detection/correlator.py
Corrélation multi-source orientée chaînes MITRE ATT&CK.

Au lieu d'une machine à états figée, on accumule par IP source les techniques
MITRE observées (issues de Suricata, Zeek, Wazuh) et on déclenche un incident
quand une CHAÎNE caractéristique d'attaque apparaît :

  recon (T1046/T1018) ─▶ brute force (T1110)            => HIGH
  brute force (T1110) ─▶ succès d'auth (sev critical)   => CRITICAL
  scan (T1046)        ─▶ exploit web (T1190)            => HIGH
  beacon C2 (T1071)                                     => HIGH
  >= 3 techniques sur >= 2 tactiques différentes         => HIGH
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from config import loader
from detection.mitre import resolve
from pipeline.schema import EventType, NetworkEvent, Severity
from storage.sqlite_db import get_db

logger = logging.getLogger(__name__)


@dataclass
class AttackContext:
    src_ip: str
    techniques: set[str] = field(default_factory=set)
    timeline: list[dict] = field(default_factory=list)   # [{technique, ts, event_id, message}]
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    max_severity: Severity = Severity.INFO
    incident_level: str | None = None    # None | "high" | "critical"

    def add(self, technique_ids: list[str], event: NetworkEvent) -> None:
        self.last_seen = datetime.now(timezone.utc)
        self.techniques.update(technique_ids)
        for tid in (technique_ids or ["_"]):
            self.timeline.append({
                "technique": tid,
                "ts": event.timestamp.isoformat(),
                "event_id": event.event_id,
                "message": event.message,
            })
        if _sev_rank(event.severity) > _sev_rank(self.max_severity):
            self.max_severity = event.severity

    def tactics(self) -> set[str]:
        return {resolve(t).tactic_id for t in self.techniques}


_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _sev_rank(sev: Severity) -> int:
    try:
        return _SEV_ORDER.index(sev)
    except ValueError:
        return 0


class Correlator:
    def __init__(self):
        self._ttl = loader.get("detection.correlation.context_ttl_seconds", 600)
        self._contexts: dict[str, AttackContext] = {}

    def _get_context(self, src_ip: str) -> AttackContext:
        ctx = self._contexts.get(src_ip)
        if ctx is None or self._is_expired(ctx):
            ctx = AttackContext(src_ip=src_ip)
            self._contexts[src_ip] = ctx
        return ctx

    def _is_expired(self, ctx: AttackContext) -> bool:
        return (datetime.now(timezone.utc) - ctx.last_seen).total_seconds() > self._ttl

    def _cleanup(self) -> None:
        for ip in [ip for ip, c in self._contexts.items() if self._is_expired(c)]:
            del self._contexts[ip]

    def correlate(self, alert: NetworkEvent) -> NetworkEvent | None:
        """Reçoit une alerte enrichie MITRE, retourne un incident si une chaîne matche."""
        if alert.event_type not in (EventType.ALERT, EventType.ANOMALY) or not alert.src_ip:
            return None

        ctx = self._get_context(alert.src_ip)
        ctx.add(list(alert.mitre or []), alert)

        incident = self._evaluate_chains(ctx, alert)

        if len(self._contexts) > 500:
            self._cleanup()
        return incident

    def _evaluate_chains(self, ctx: AttackContext, alert: NetworkEvent) -> NetworkEvent | None:
        t = ctx.techniques
        recon = bool(t & {"T1046", "T1018"})
        brute = "T1110" in t
        web = "T1190" in t
        c2 = "T1071" in t

        # Indice de "succès" d'authentification : Wazuh remonte la connexion
        # réussie après échecs en niveau critique (rule 100020).
        auth_success = (
            alert.severity == Severity.CRITICAL and "T1110" in (alert.mitre or [])
        ) or "authentication_success" in str(alert.tags.get("rule", ""))

        # ── CRITICAL : compromission probable (brute force suivi d'un succès) ──
        if brute and auth_success and ctx.incident_level != "critical":
            return self._make_incident(
                ctx, Severity.CRITICAL,
                f"Compromission probable de {alert.src_ip} : authentification réussie "
                f"après brute force (chaîne T1110).",
            )

        # ── HIGH : reconnaissance puis brute force ──
        if recon and brute and ctx.incident_level is None:
            return self._make_incident(
                ctx, Severity.HIGH,
                f"Attaque ciblée depuis {alert.src_ip} : scan de reconnaissance "
                f"suivi de brute force (T1046/T1018 -> T1110).",
            )

        # ── HIGH : scan puis exploitation web ──
        if recon and web and ctx.incident_level is None:
            return self._make_incident(
                ctx, Severity.HIGH,
                f"Exploitation applicative depuis {alert.src_ip} après reconnaissance "
                f"(T1046 -> T1190).",
            )

        # ── HIGH : beaconing C2 ──
        if c2 and ctx.incident_level is None:
            return self._make_incident(
                ctx, Severity.HIGH,
                f"Communication C2 probable impliquant {alert.src_ip} (T1071, beaconing).",
            )

        # ── HIGH : attaque multi-étapes (>=3 techniques, >=2 tactiques) ──
        if len(ctx.techniques) >= 3 and len(ctx.tactics()) >= 2 and ctx.incident_level is None:
            return self._make_incident(
                ctx, Severity.HIGH,
                f"Activité multi-étapes depuis {alert.src_ip} : "
                f"{len(ctx.techniques)} techniques sur {len(ctx.tactics())} tactiques.",
            )

        return None

    def _make_incident(self, ctx: AttackContext, severity: Severity, description: str) -> NetworkEvent:
        ctx.incident_level = severity.value
        duration = int((ctx.last_seen - ctx.first_seen).total_seconds())
        techniques = sorted(ctx.techniques, key=lambda x: resolve(x).tactic_rank)
        chain = " -> ".join(f"{tid}({resolve(tid).tactic})" for tid in techniques)
        event_ids = [e["event_id"] for e in ctx.timeline][-20:]

        db = get_db()
        incident_id = db.create_incident(
            title=f"Incident {severity.value.upper()} — {ctx.src_ip}",
            description=f"{description} Chaîne: {chain}. Durée: {duration}s.",
            severity=severity,
            src_ip=ctx.src_ip,
            rule_name="correlator:" + "+".join(techniques),
            event_ids=event_ids,
        )
        logger.critical(f"INCIDENT #{incident_id} [{severity.value.upper()}] {ctx.src_ip} — {chain}")

        return NetworkEvent(
            event_type=EventType.INCIDENT,
            src_ip=ctx.src_ip,
            source="correlator",
            severity=severity,
            message=description,
            mitre=techniques,
            tags={
                "incident_id": incident_id,
                "techniques": techniques,
                "tactics": sorted(ctx.tactics()),
                "duration_sec": duration,
                "event_count": len(ctx.timeline),
                "chain": chain,
            },
        )

    def get_active_contexts(self) -> list[dict]:
        return [
            {
                "src_ip": ctx.src_ip,
                "techniques": sorted(ctx.techniques),
                "tactics": sorted(ctx.tactics()),
                "max_severity": ctx.max_severity.value,
                "incident_level": ctx.incident_level,
                "event_count": len(ctx.timeline),
                "duration_sec": int((ctx.last_seen - ctx.first_seen).total_seconds()),
            }
            for ctx in self._contexts.values()
            if not self._is_expired(ctx)
        ]
