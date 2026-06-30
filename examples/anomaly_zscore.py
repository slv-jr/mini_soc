"""
examples/anomaly_zscore.py
[ARCHIVÉ — pédagogique] Détection d'anomalie par Z-score sur fenêtre glissante.

Ce module était la détection statistique "maison" de la v1 (Raspberry Pi).
Dans la v2, la détection est déléguée à Suricata/Zeek/Wazuh ; on conserve cet
exemple autonome car il illustre bien le principe d'une baseline glissante.

Désactivé par défaut (detection.anomaly.enabled = false dans settings.yaml).

Exécution standalone (démo, sans dépendance au reste du SOC) :
    python examples/anomaly_zscore.py
"""
from collections import deque

import numpy as np


class ZScoreDetector:
    """Baseline glissante : signale les valeurs qui s'écartent de > `threshold` σ."""

    def __init__(self, window_size: int = 100, threshold: float = 3.0):
        self.window_size = window_size
        self.threshold = threshold
        self._values: deque[float] = deque(maxlen=window_size)

    def add(self, value: float) -> tuple[float, bool]:
        """Ajoute une valeur, retourne (z_score, is_anomaly)."""
        self._values.append(value)
        if len(self._values) < max(10, self.window_size // 5):
            return 0.0, False
        arr = np.array(self._values)
        mean, std = float(np.mean(arr)), float(np.std(arr))
        if std < 1e-9:
            return 0.0, False
        z = abs((value - mean) / std)
        return round(z, 3), z > self.threshold


def _demo() -> None:
    import random
    det = ZScoreDetector(window_size=50, threshold=3.0)
    print("Flux normal (~100 ± 10) puis pic anormal à 500...")
    for i in range(60):
        value = random.gauss(100, 10) if i != 55 else 500
        z, anomaly = det.add(value)
        flag = "  <-- ANOMALIE" if anomaly else ""
        if anomaly or i % 10 == 0:
            print(f"t={i:3d}  valeur={value:7.1f}  z={z:5.2f}{flag}")


if __name__ == "__main__":
    _demo()
