# stats.py
# Thread-safe live traffic statistics. The sniffer updates these counters on
# every packet; the dashboard reads them to draw the "live network" panel
# (total packets, packets-per-second, protocol breakdown).

import time
import threading
from collections import deque


class TrafficStats:
    """Rolling counters describing the traffic the IDS is currently seeing."""

    def __init__(self):
        self._lock = threading.Lock()
        self.start_time = time.time()

        self.total_packets = 0
        self.protocols = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}

        # Timestamps of recent packets, used to compute a live packets/sec rate.
        self._recent = deque(maxlen=5000)

    def record(self, protocol: str):
        """Called once per captured packet."""
        with self._lock:
            self.total_packets += 1
            if protocol not in self.protocols:
                protocol = "OTHER"
            self.protocols[protocol] += 1
            self._recent.append(time.time())

    def packets_per_second(self) -> float:
        """Average packet rate over the last 5 seconds."""
        now = time.time()
        with self._lock:
            recent = [t for t in self._recent if now - t <= 5]
        return round(len(recent) / 5.0, 1)

    def uptime_seconds(self) -> int:
        return int(time.time() - self.start_time)

    def snapshot(self) -> dict:
        """A JSON-friendly view of all stats for the dashboard."""
        with self._lock:
            protocols = dict(self.protocols)
            total = self.total_packets
        return {
            "total_packets": total,
            "protocols": protocols,
            "packets_per_second": self.packets_per_second(),
            "uptime_seconds": self.uptime_seconds(),
        }


# Shared instance imported across the app.
stats = TrafficStats()
