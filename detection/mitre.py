"""
detection/mitre.py
Mapping des alertes (Suricata / Zeek / Wazuh / règles legacy) vers des
techniques MITRE ATT&CK. Enrichit chaque NetworkEvent avec :
  - event.mitre        : liste d'identifiants de techniques (ex: ["T1110"])
  - event.tags["mitre"]: liste détaillée [{id, name, tactic, tactic_id}]

La détection produit déjà des metadata MITRE (custom.rules + ET Open) ; ce
module les normalise et complète via une table maintenue dans
config/mitre_map.yaml.
"""
import logging
from dataclasses import dataclass

import yaml

from config import loader
from pipeline.schema import NetworkEvent

logger = logging.getLogger(__name__)


# Référentiel minimal des techniques utilisées par le Mini-SOC.
# (id -> (nom, tactique lisible, identifiant de tactique))
TECHNIQUES: dict[str, tuple[str, str, str]] = {
    "T1018": ("Remote System Discovery", "Discovery", "TA0007"),
    "T1046": ("Network Service Scanning", "Discovery", "TA0007"),
    "T1071": ("Application Layer Protocol", "Command and Control", "TA0011"),
    "T1110": ("Brute Force", "Credential Access", "TA0006"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access", "TA0001"),
    "T1021": ("Remote Services", "Lateral Movement", "TA0008"),
    "T1059": ("Command and Scripting Interpreter", "Execution", "TA0002"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration", "TA0010"),
    "T1498": ("Network Denial of Service", "Impact", "TA0040"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access", "TA0006"),
    "T1562": ("Impair Defenses", "Defense Evasion", "TA0005"),
}

# Ordre des tactiques le long de la kill chain (pour ordonner les chaînes).
TACTIC_ORDER = [
    "TA0043",  # Reconnaissance
    "TA0007",  # Discovery
    "TA0001",  # Initial Access
    "TA0002",  # Execution
    "TA0006",  # Credential Access
    "TA0008",  # Lateral Movement
    "TA0011",  # Command and Control
    "TA0010",  # Exfiltration
    "TA0040",  # Impact
    "TA0005",  # Defense Evasion
]


@dataclass(frozen=True)
class MitreTechnique:
    id: str
    name: str
    tactic: str
    tactic_id: str

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name,
                "tactic": self.tactic, "tactic_id": self.tactic_id}

    @property
    def tactic_rank(self) -> int:
        try:
            return TACTIC_ORDER.index(self.tactic_id)
        except ValueError:
            return len(TACTIC_ORDER)


def resolve(technique_id: str) -> MitreTechnique:
    """Construit un MitreTechnique à partir d'un identifiant (T####)."""
    tid = technique_id.strip().upper()
    name, tactic, tactic_id = TECHNIQUES.get(tid, ("Unknown Technique", "Unknown", "TA0000"))
    return MitreTechnique(id=tid, name=name, tactic=tactic, tactic_id=tactic_id)


class MitreMapper:
    def __init__(self):
        self._sid_map: dict[str, str] = {}
        self._rule_map: dict[str, str] = {}
        self._enabled = loader.get("mitre.enabled", True)
        self._load_map()

    def _load_map(self) -> None:
        path = loader.get("mitre.mapping_file", "config/mitre_map.yaml")
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            self._sid_map = {str(k): v for k, v in (data.get("sid_to_technique") or {}).items()}
            self._rule_map = dict(data.get("rule_to_technique") or {})
            logger.info(f"MITRE map chargée: {len(self._sid_map)} SID, {len(self._rule_map)} règles")
        except FileNotFoundError:
            logger.warning(f"Fichier de mapping MITRE introuvable: {path} (table intégrée seule)")

    def _ids_from_event(self, event: NetworkEvent) -> set[str]:
        ids: set[str] = set()
        tags = event.tags or {}

        # 1. Metadata MITRE directe (Suricata/Zeek via Vector). Peut être str ou liste.
        raw = tags.get("mitre_technique_id")
        if isinstance(raw, str):
            ids.update(p.strip() for p in raw.replace(",", " ").split())
        elif isinstance(raw, (list, tuple)):
            ids.update(str(p).strip() for p in raw)

        # 2. Par SID Suricata (tags["rule"] contient le signature_id numérique).
        rule = tags.get("rule")
        if rule is not None:
            rule_str = str(rule)
            if rule_str in self._sid_map:
                ids.add(self._sid_map[rule_str])
            if rule_str in self._rule_map:
                ids.add(self._rule_map[rule_str])

        # 3. Par nom de note Zeek (tags["rule"] = "Horizontal_Scan", etc.)
        note = tags.get("note") or tags.get("rule")
        if note in self._rule_map:
            ids.add(self._rule_map[note])

        return {i for i in ids if i and i.upper().startswith("T")}

    def tag(self, event: NetworkEvent) -> list[MitreTechnique]:
        """Enrichit l'événement avec ses techniques MITRE et les retourne."""
        if not self._enabled:
            return []

        techniques = sorted(
            {resolve(tid) for tid in self._ids_from_event(event)},
            key=lambda t: t.tactic_rank,
        )
        if techniques:
            event.mitre = [t.id for t in techniques]
            event.tags["mitre"] = [t.to_dict() for t in techniques]
        return techniques


_mapper: MitreMapper | None = None


def get_mapper() -> MitreMapper:
    global _mapper
    if _mapper is None:
        _mapper = MitreMapper()
    return _mapper
