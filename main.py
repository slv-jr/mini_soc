"""
main.py
Point d'entrée du Mini-SOC.

La capture réseau et la collecte de logs sont désormais assurées par la stack
conteneurisée (Suricata, Zeek, Wazuh) ; Vector normalise et publie sur Redis.
Ce processus Python lance :
  - le moteur de détection (consommateur Redis : MITRE + enrichissement + corrélation)
  - les sondes actives (ICMP/HTTP)
  - le dashboard Flask (topologie + alertes temps réel)

Usage :
  python main.py                      # tous les services
  python main.py --no-dashboard       # sans le dashboard Flask
  python main.py --only-engine        # moteur de détection seul
"""
import argparse
import asyncio
import logging
import logging.handlers
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from config import loader

loader.load()

# ── Logging ─────────────────────────────────────────────────────────────────
log_cfg = loader.get("logging") or {}
log_level = getattr(logging, log_cfg.get("level", "INFO").upper(), logging.INFO)
log_file = log_cfg.get("file", "logs/minisoc.log")
Path(log_file).parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=log_cfg.get("max_bytes", 10_485_760),
            backupCount=log_cfg.get("backup_count", 3),
        ),
    ],
)
logger = logging.getLogger("minisoc.main")

from collector.probe import run_probes
from dashboard.topology import start_dashboard
from detection.engine import DetectionEngine


def run_detection_engine() -> None:
    logger.info("Service: moteur de détection")
    DetectionEngine().run()


def run_async_services() -> None:
    """Sondes actives dans leur propre event loop asyncio."""
    async def _all():
        logger.info("Service: sondes actives (ICMP/HTTP)")
        await asyncio.gather(run_probes())
    asyncio.run(_all())


def main() -> None:
    parser = argparse.ArgumentParser(description="Mini-SOC — Network Security Monitor")
    parser.add_argument("--no-dashboard", action="store_true", help="Désactiver le dashboard Flask")
    parser.add_argument("--no-probes", action="store_true", help="Désactiver les sondes actives")
    parser.add_argument("--only-engine", action="store_true", help="Lancer uniquement le moteur de détection")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("  Mini-SOC démarrage")
    logger.info(f"  Interface surveillée : {loader.get('network.interface', 'eth0')}")
    logger.info(f"  Dashboard : {'NON' if (args.no_dashboard or args.only_engine) else 'OUI'}")
    logger.info(f"  Sondes    : {'NON' if (args.no_probes or args.only_engine) else 'OUI'}")
    logger.info("=" * 60)

    threads: list[threading.Thread] = []
    threads.append(threading.Thread(target=run_detection_engine, daemon=True, name="detection-engine"))

    if not args.no_probes and not args.only_engine:
        threads.append(threading.Thread(target=run_async_services, daemon=True, name="probes"))

    for t in threads:
        t.start()
        logger.info(f"Thread '{t.name}' démarré")

    try:
        if not args.no_dashboard and not args.only_engine:
            start_dashboard()  # bloquant (thread principal)
        else:
            for t in threads:
                t.join()
    except KeyboardInterrupt:
        logger.info("Arrêt demandé (Ctrl+C)")

    logger.info("Mini-SOC arrêté.")


if __name__ == "__main__":
    main()
