"""
pipeline/schema.py
Schéma normalisé commun à tous les collecteurs.
Tout événement qui entre dans le pipeline est converti en NetworkEvent.
"""
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    # Collecte
    PACKET = "packet"
    SYSLOG = "syslog"
    SNMP_METRIC = "snmp_metric"
    PROBE = "probe"
    ARP = "arp"
    # Détection
    ALERT = "alert"
    ANOMALY = "anomaly"
    INCIDENT = "incident"


@dataclass
class NetworkEvent:
    event_type: EventType
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    # Réseau
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    interface: str | None = None

    # Contenu
    message: str | None = None
    raw: str | None = None

    # Métadonnées
    severity: Severity = Severity.INFO
    source: str | None = None       # quel collecteur a généré l'événement
    tags: dict = field(default_factory=dict)
    metrics: dict = field(default_factory=dict)

    # Enrichissement (rempli par le pipeline de détection)
    mitre: list = field(default_factory=list)        # ex: ["T1110", "T1046"]
    enrichment: dict = field(default_factory=dict)   # geoip, abuseipdb, otx...

    def to_json(self) -> str:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["event_type"] = self.event_type.value
        d["severity"] = self.severity.value
        return json.dumps(d)

    @classmethod
    def from_json(cls, data: str | bytes) -> "NetworkEvent":
        d = json.loads(data)
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["event_type"] = EventType(d["event_type"])
        d["severity"] = Severity(d["severity"])
        return cls(**d)

    def __str__(self) -> str:
        ts = self.timestamp.strftime("%H:%M:%S")
        src = f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip or "-"
        dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip or "-"
        return f"[{ts}] {self.event_type.value:12s} {src:22s} → {dst:22s} [{self.severity.value}]"
