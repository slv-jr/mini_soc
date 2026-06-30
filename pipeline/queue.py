"""
pipeline/queue.py
Abstraction de la file Redis.
Producteurs (collecteurs) → poussent dans la queue.
Consommateurs (détection) → lisent en boucle.
"""
import logging
import time
from collections.abc import Callable

import redis

from config import loader
from pipeline.schema import NetworkEvent

logger = logging.getLogger(__name__)


class EventQueue:
    def __init__(self):
        cfg = loader.get("redis")
        self._client = redis.Redis(
            host=cfg["host"],
            port=cfg["port"],
            db=cfg["db"],
            decode_responses=True,
            socket_connect_timeout=5,
            retry_on_timeout=True,
        )
        self._raw_queue = loader.get("redis.queues.raw_events")
        self._alert_queue = loader.get("redis.queues.alerts")
        self._max_len = 10_000  # évite que la queue explose la RAM du Pi

    def push_event(self, event: NetworkEvent) -> None:
        try:
            self._client.lpush(self._raw_queue, event.to_json())
            self._client.ltrim(self._raw_queue, 0, self._max_len)
        except redis.RedisError as e:
            logger.error(f"Erreur push Redis: {e}")

    def push_alert(self, event: NetworkEvent) -> None:
        try:
            self._client.lpush(self._alert_queue, event.to_json())
            self._client.ltrim(self._alert_queue, 0, 1_000)
            # Pub/sub pour les consommateurs temps réel (dashboard)
            self._client.publish("pisoc:alerts:live", event.to_json())
        except redis.RedisError as e:
            logger.error(f"Erreur push alert Redis: {e}")

    def pop_event(self, timeout: int = 5) -> NetworkEvent | None:
        """Bloquant — attend un événement jusqu'à timeout secondes."""
        try:
            result = self._client.brpop(self._raw_queue, timeout=timeout)
            if result:
                _, raw = result
                return NetworkEvent.from_json(raw)
        except redis.RedisError as e:
            logger.error(f"Erreur pop Redis: {e}")
        return None

    def consume_loop(self, handler: Callable[[NetworkEvent], None]) -> None:
        """Boucle infinie de consommation — appelle handler pour chaque événement."""
        logger.info("Démarrage de la boucle de consommation Redis")
        while True:
            try:
                event = self.pop_event(timeout=5)
                if event:
                    handler(event)
            except KeyboardInterrupt:
                logger.info("Arrêt de la boucle de consommation")
                break
            except Exception as e:
                logger.error(f"Erreur dans consume_loop: {e}")
                time.sleep(1)

    def stats(self) -> dict:
        return {
            "raw_queue_len": self._client.llen(self._raw_queue),
            "alert_queue_len": self._client.llen(self._alert_queue),
            "redis_ping": self._client.ping(),
        }


# Singleton global
_queue: EventQueue | None = None


def get_queue() -> EventQueue:
    global _queue
    if _queue is None:
        _queue = EventQueue()
    return _queue
