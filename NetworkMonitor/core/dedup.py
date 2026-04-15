from collections import OrderedDict
from time import time


class AlertDedup:
    """
    Дедуп алертов с TTL и ограничением размера.
    Не даёт памяти расти бесконечно.
    """

    def __init__(self, ttl_sec: int = 300, max_size: int = 10_000):
        self._ttl = int(ttl_sec)
        self._max_size = int(max_size)
        self._seen: OrderedDict[tuple, float] = OrderedDict()

    def should_emit(self, src_ip: str, dst_ip: str, dport: int, verdict: str) -> bool:
        key = (src_ip, dst_ip, dport, verdict)
        now = time()

        last_seen = self._seen.get(key)
        if last_seen is not None and (now - last_seen) < self._ttl:
            return False

        self._seen[key] = now
        self._seen.move_to_end(key)

        while len(self._seen) > self._max_size:
            self._seen.popitem(last=False)

        return True

    def clear(self) -> None:
        self._seen.clear()