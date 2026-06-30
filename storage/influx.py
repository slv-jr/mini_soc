"""
storage/influx.py
Abstraction InfluxDB 2.x — écriture des métriques réseau.
Toutes les métriques continues (trafic, latence, paquets/s) vont ici.
"""
import logging

from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.exceptions import InfluxDBError
from influxdb_client.client.write_api import SYNCHRONOUS

from config import loader

logger = logging.getLogger(__name__)


class InfluxStorage:
    def __init__(self):
        cfg = loader.all_config()["influxdb"]
        self._client = InfluxDBClient(
            url=cfg["url"],
            token=cfg["token"],
            org=cfg["org"],
        )
        self._write_api = self._client.write_api(write_options=SYNCHRONOUS)
        self._bucket = cfg["bucket"]
        self._org = cfg["org"]

    def _write(self, point: Point) -> None:
        try:
            self._write_api.write(bucket=self._bucket, org=self._org, record=point)
        except InfluxDBError as e:
            logger.error(f"Erreur écriture InfluxDB: {e}")

    def write_packet(self, src_ip: str, dst_ip: str, protocol: str,
                     bytes_count: int, interface: str = "wlan0") -> None:
        point = (
            Point("network_traffic")
            .tag("src_ip", src_ip or "unknown")
            .tag("dst_ip", dst_ip or "unknown")
            .tag("protocol", protocol or "unknown")
            .tag("interface", interface)
            .field("bytes", bytes_count)
            .field("packets", 1)
        )
        self._write(point)

    def write_probe(self, host: str, name: str, alive: bool,
                    avg_rtt: float, packet_loss: float) -> None:
        point = (
            Point("host_availability")
            .tag("host", host)
            .tag("name", name)
            .field("alive", int(alive))
            .field("avg_rtt_ms", avg_rtt)
            .field("packet_loss_pct", packet_loss)
        )
        self._write(point)

    def write_alert(self, rule_name: str, src_ip: str,
                    severity: str, count: int = 1) -> None:
        point = (
            Point("security_alerts")
            .tag("rule", rule_name)
            .tag("src_ip", src_ip or "unknown")
            .tag("severity", severity)
            .field("count", count)
        )
        self._write(point)

    def write_traffic_stats(self, interface: str, bytes_in: int,
                            bytes_out: int, packets_in: int, packets_out: int) -> None:
        point = (
            Point("interface_stats")
            .tag("interface", interface)
            .field("bytes_in", bytes_in)
            .field("bytes_out", bytes_out)
            .field("packets_in", packets_in)
            .field("packets_out", packets_out)
        )
        self._write(point)

    def write_anomaly_score(self, metric_name: str, value: float,
                            z_score: float, is_anomaly: bool) -> None:
        point = (
            Point("anomaly_scores")
            .tag("metric", metric_name)
            .field("value", value)
            .field("z_score", z_score)
            .field("is_anomaly", int(is_anomaly))
        )
        self._write(point)

    def close(self) -> None:
        self._client.close()


_influx: InfluxStorage | None = None


def get_influx() -> InfluxStorage:
    global _influx
    if _influx is None:
        _influx = InfluxStorage()
    return _influx
