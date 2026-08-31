"""Sliding-window heuristic detector with deterministically bounded state."""

import math
import threading
from collections import OrderedDict, deque

from config import config

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


class DetectionEngine:
    """Analyse normalized packet fields and emit heuristic alerts."""

    _TRACKERS = ("scan_tracker", "dos_tracker", "syn_tracker", "icmp_tracker", "brute_tracker")

    def __init__(self, alert_system, cfg=config):
        self.alerts = alert_system
        self.cfg = cfg
        self.lock = threading.Lock()
        self.scan_tracker = OrderedDict()
        self.dos_tracker = OrderedDict()
        self.syn_tracker = OrderedDict()
        self.icmp_tracker = OrderedDict()
        self.brute_tracker = OrderedDict()
        self._last_alert = OrderedDict()
        self._last_seen = {}
        self._expiry_queue = deque(maxlen=cfg.max_tracker_keys * len(self._TRACKERS) * 2)
        self._packet_count = 0
        self._clock = 0.0

    def analyze(self, src_ip, dst_ip, dst_port, protocol, timestamp, tcp_flags=0):
        """Analyse one packet; malformed fields are ignored safely."""
        normalized = self._normalize(src_ip, dst_ip, dst_port, protocol, timestamp, tcp_flags)
        if normalized is None:
            return
        src_ip, dst_ip, dst_port, protocol, timestamp, tcp_flags = normalized

        with self.lock:
            # A monotonic logical clock makes late packet timestamps predictable.
            self._clock = max(self._clock, timestamp)
            timestamp = self._clock
            self._packet_count += 1
            if self._packet_count % self.cfg.cleanup_interval_packets == 0:
                self._cleanup(timestamp)

            self._check_blacklist(src_ip, dst_ip, protocol, timestamp)
            self._check_dos(src_ip, timestamp)
            if protocol == "ICMP":
                self._check_icmp_flood(src_ip, timestamp)
            if protocol == "TCP":
                self._check_stealth_scan(src_ip, dst_ip, dst_port, tcp_flags, timestamp)
                self._check_syn_flood(src_ip, tcp_flags, timestamp)
            if dst_port is not None:
                self._check_port_scan(src_ip, dst_port, protocol, tcp_flags, timestamp)
                self._check_brute_force(src_ip, dst_ip, dst_port, protocol, tcp_flags, timestamp)
                self._check_sensitive_port(src_ip, dst_ip, dst_port, protocol, timestamp)

    @staticmethod
    def _normalize(src_ip, dst_ip, dst_port, protocol, timestamp, tcp_flags):
        if not isinstance(src_ip, str) or not src_ip or not isinstance(dst_ip, str) or not dst_ip:
            return None
        protocol = str(protocol).upper() if protocol is not None else "OTHER"
        if protocol not in {"TCP", "UDP", "ICMP", "OTHER"}:
            protocol = "OTHER"
        try:
            timestamp = float(timestamp)
            tcp_flags = int(tcp_flags or 0)
        except (TypeError, ValueError, OverflowError):
            return None
        if not math.isfinite(timestamp) or timestamp < 0:
            return None
        if dst_port is not None:
            try:
                dst_port = int(dst_port)
            except (TypeError, ValueError, OverflowError):
                return None
            if not 0 <= dst_port <= 65535:
                return None
        return src_ip, dst_ip, dst_port, protocol, timestamp, tcp_flags

    def _events(self, tracker_name, key, timestamp):
        tracker = getattr(self, tracker_name)
        events = tracker.get(key)
        if events is None:
            if len(tracker) >= self.cfg.max_tracker_keys:
                old_key, _ = tracker.popitem(last=False)
                self._last_seen.pop((tracker_name, old_key), None)
            events = deque(maxlen=self.cfg.max_events_per_key)
            tracker[key] = events
        else:
            tracker.move_to_end(key)
        marker = (tracker_name, key)
        self._last_seen[marker] = timestamp
        self._expiry_queue.append((timestamp, tracker_name, key))
        return events

    def _cleanup(self, timestamp):
        cutoff = timestamp - self.cfg.state_ttl
        processed = 0
        while self._expiry_queue and processed < self.cfg.cleanup_budget:
            seen, tracker_name, key = self._expiry_queue[0]
            if seen >= cutoff:
                break
            self._expiry_queue.popleft()
            processed += 1
            marker = (tracker_name, key)
            if self._last_seen.get(marker) != seen:
                continue
            getattr(self, tracker_name).pop(key, None)
            self._last_seen.pop(marker, None)

        while self._last_alert:
            key, seen = next(iter(self._last_alert.items()))
            if seen >= cutoff:
                break
            self._last_alert.pop(key, None)

    def state_sizes(self):
        """Return non-sensitive state counts for diagnostics and tests."""
        with self.lock:
            result = {name: len(getattr(self, name)) for name in self._TRACKERS}
            result["cooldowns"] = len(self._last_alert)
            result["expiry_queue"] = len(self._expiry_queue)
            result["events"] = sum(
                len(events) for name in self._TRACKERS for events in getattr(self, name).values()
            )
            return result

    def _cooled_down(self, key, timestamp):
        last = self._last_alert.get(key)
        if last is not None and timestamp - last <= self.cfg.alert_cooldown:
            return False
        self._last_alert[key] = timestamp
        self._last_alert.move_to_end(key)
        while len(self._last_alert) > self.cfg.max_cooldown_entries:
            self._last_alert.popitem(last=False)
        return True

    @staticmethod
    def _prune(events, cutoff, has_port=False):
        while events and (events[0][0] if has_port else events[0]) < cutoff:
            events.popleft()

    def _check_dos(self, src_ip, timestamp):
        events = self._events("dos_tracker", src_ip, timestamp)
        events.append(timestamp)
        self._prune(events, timestamp - self.cfg.dos_window)
        if len(events) >= self.cfg.dos_threshold and self._cooled_down(("dos", src_ip), timestamp):
            self.alerts.trigger(src_ip, "DoS / Flood", "HIGH", f"{len(events)} packets in {self.cfg.dos_window:g}s")

    def _check_syn_flood(self, src_ip, tcp_flags, timestamp):
        if not ((tcp_flags & TCP_SYN) and not (tcp_flags & TCP_ACK)):
            return
        events = self._events("syn_tracker", src_ip, timestamp)
        events.append(timestamp)
        self._prune(events, timestamp - self.cfg.syn_flood_window)
        if len(events) >= self.cfg.syn_flood_threshold and self._cooled_down(("syn", src_ip), timestamp):
            self.alerts.trigger(src_ip, "SYN Flood", "CRITICAL", f"{len(events)} SYN packets in {self.cfg.syn_flood_window:g}s")

    def _check_icmp_flood(self, src_ip, timestamp):
        events = self._events("icmp_tracker", src_ip, timestamp)
        events.append(timestamp)
        self._prune(events, timestamp - self.cfg.icmp_flood_window)
        if len(events) >= self.cfg.icmp_flood_threshold and self._cooled_down(("icmp", src_ip), timestamp):
            self.alerts.trigger(src_ip, "ICMP Flood", "HIGH", f"{len(events)} ICMP packets in {self.cfg.icmp_flood_window:g}s")

    def _check_port_scan(self, src_ip, dst_port, protocol, tcp_flags, timestamp):
        if protocol == "TCP" and not ((tcp_flags & TCP_SYN) and not (tcp_flags & TCP_ACK)):
            return
        events = self._events("scan_tracker", src_ip, timestamp)
        events.append((timestamp, dst_port))
        self._prune(events, timestamp - self.cfg.port_scan_window, True)
        distinct = len({port for _, port in events})
        if distinct >= self.cfg.port_scan_threshold and self._cooled_down(("scan", src_ip), timestamp):
            self.alerts.trigger(src_ip, "Port Scan", "MEDIUM", f"{distinct} distinct ports in {self.cfg.port_scan_window:g}s")

    def _check_stealth_scan(self, src_ip, dst_ip, dst_port, tcp_flags, timestamp):
        scan_type = {0x00: "NULL scan", TCP_FIN: "FIN scan", TCP_FIN | TCP_PSH | TCP_URG: "XMAS scan"}.get(tcp_flags)
        if scan_type and self._cooled_down(("stealth", src_ip), timestamp):
            self.alerts.trigger(src_ip, "Stealth Scan", "MEDIUM", f"{scan_type} -> {dst_ip}:{dst_port}")

    def _check_brute_force(self, src_ip, dst_ip, dst_port, protocol, tcp_flags, timestamp):
        if dst_port not in self.cfg.auth_ports:
            return
        if protocol == "TCP" and not ((tcp_flags & TCP_SYN) and not (tcp_flags & TCP_ACK)):
            return
        key = (src_ip, dst_port)
        events = self._events("brute_tracker", key, timestamp)
        events.append((timestamp, dst_port))
        self._prune(events, timestamp - self.cfg.brute_force_window, True)
        if len(events) >= self.cfg.brute_force_threshold and self._cooled_down(("brute", *key), timestamp):
            service = self.cfg.auth_ports[dst_port]
            self.alerts.trigger(src_ip, "Brute Force", "HIGH", f"{len(events)} {service} attempts to {dst_ip}:{dst_port} in {self.cfg.brute_force_window:g}s")

    def _check_sensitive_port(self, src_ip, dst_ip, dst_port, protocol, timestamp):
        if dst_port in self.cfg.sensitive_ports and self._cooled_down(("sensitive", src_ip, dst_port), timestamp):
            name = self.cfg.sensitive_ports[dst_port]
            self.alerts.trigger(src_ip, "Suspicious Port Access", "HIGH", f"{protocol} -> {dst_ip}:{dst_port} ({name})")

    def _check_blacklist(self, src_ip, dst_ip, protocol, timestamp):
        bad_ip = src_ip if src_ip in self.cfg.ip_blacklist else dst_ip if dst_ip in self.cfg.ip_blacklist else None
        if bad_ip and self._cooled_down(("blacklist", bad_ip), timestamp):
            self.alerts.trigger(bad_ip, "Blacklisted IP", "CRITICAL", f"{protocol} traffic involving example watchlist IP {bad_ip}")
