"""
collector/probe.py
Probe actif : ping ICMP + optionnellement HTTP check sur les cibles configurées.
Lance toutes les N secondes, envoie les résultats dans la queue et InfluxDB.
"""
import asyncio
import logging
import time
from datetime import datetime, timezone

import httpx
import icmplib

from config import loader
from pipeline.queue import get_queue
from pipeline.schema import EventType, NetworkEvent, Severity
from storage.influx import get_influx

logger = logging.getLogger(__name__)


async def ping_host(host: str, count: int = 3) -> dict:
    """Ping asynchrone — retourne latence moyenne, perte de paquets."""
    try:
        result = icmplib.ping(host, count=count, interval=0.5, timeout=2, privileged=False)
        return {
            "alive": result.is_alive,
            "avg_rtt": round(result.avg_rtt, 2),
            "min_rtt": round(result.min_rtt, 2),
            "max_rtt": round(result.max_rtt, 2),
            "packet_loss": round(result.packet_loss * 100, 1),
        }
    except Exception as e:
        logger.warning(f"Ping {host} échoué: {e}")
        return {"alive": False, "avg_rtt": 0, "min_rtt": 0, "max_rtt": 0, "packet_loss": 100}


async def check_http(url: str, timeout: int = 5) -> dict:
    """HTTP GET — retourne status code et temps de réponse."""
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)
            elapsed = round((time.monotonic() - start) * 1000, 2)
            return {"status": resp.status_code, "response_ms": elapsed, "ok": resp.is_success}
    except Exception as e:
        return {"status": 0, "response_ms": 0, "ok": False, "error": str(e)}


async def probe_target(target: dict) -> None:
    host = target["host"]
    name = target.get("name", host)
    queue = get_queue()
    influx = get_influx()
    now = datetime.now(timezone.utc)

    # --- Ping ---
    ping_result = await ping_host(host)
    severity = Severity.INFO if ping_result["alive"] else Severity.HIGH

    event = NetworkEvent(
        event_type=EventType.PROBE,
        src_ip=None,
        dst_ip=host,
        protocol="ICMP",
        source="probe",
        severity=severity,
        message=f"Probe {name} ({host}) — {'UP' if ping_result['alive'] else 'DOWN'} "
                f"avg={ping_result['avg_rtt']}ms loss={ping_result['packet_loss']}%",
        tags={"target_name": name, "probe_type": "ping"},
        metrics=ping_result,
        timestamp=now,
    )
    queue.push_event(event)

    # Écriture dans InfluxDB
    influx.write_probe(
        host=host,
        name=name,
        alive=ping_result["alive"],
        avg_rtt=ping_result["avg_rtt"],
        packet_loss=ping_result["packet_loss"],
    )

    if not ping_result["alive"]:
        logger.warning(f"ALERTE: {name} ({host}) est DOWN")

    # --- HTTP check optionnel ---
    if target.get("check_http"):
        url = target.get("url", f"http://{host}")
        http_result = await check_http(url)
        http_event = NetworkEvent(
            event_type=EventType.PROBE,
            dst_ip=host,
            protocol="HTTP",
            source="probe",
            severity=Severity.INFO if http_result["ok"] else Severity.MEDIUM,
            message=f"HTTP {name} — {http_result['status']} {http_result['response_ms']}ms",
            tags={"target_name": name, "probe_type": "http", "url": url},
            metrics=http_result,
            timestamp=now,
        )
        queue.push_event(http_event)


async def run_probes() -> None:
    targets = loader.get("probe.targets", [])
    interval = loader.get("probe.interval_seconds", 30)
    logger.info(f"Démarrage des probes sur {len(targets)} cibles, interval={interval}s")

    while True:
        start = time.monotonic()
        tasks = [probe_target(t) for t in targets]
        await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.monotonic() - start
        wait = max(0, interval - elapsed)
        logger.debug(f"Probes terminés en {elapsed:.1f}s, attente {wait:.1f}s")
        await asyncio.sleep(wait)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from config import loader as cfg_loader
    cfg_loader.load()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    asyncio.run(run_probes())
