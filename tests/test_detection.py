# tests/test_detection.py
# Unit tests for the detection engine. These run WITHOUT any network access,
# admin rights, or Npcap — they feed synthetic packets straight into the engine
# and assert the right alerts fire. Run with:  pytest  (or: python -m pytest)

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from detection import DetectionEngine

SYN_ONLY = 0x02
SYN_ACK = 0x12
XMAS = 0x29


class FakeAlerts:
    """Records every alert instead of printing, so tests can inspect them."""
    def __init__(self):
        self.alerts = []

    def trigger(self, attacker_ip, attack_type, severity="MEDIUM", details=""):
        self.alerts.append({
            "attacker_ip": attacker_ip, "attack_type": attack_type,
            "severity": severity, "details": details,
        })

    def types(self):
        return [a["attack_type"] for a in self.alerts]


def make_engine():
    alerts = FakeAlerts()
    cfg = Config()  # use default thresholds
    return DetectionEngine(alerts, cfg), alerts


def test_port_scan_detected():
    engine, alerts = make_engine()
    now = time.time()
    for port in range(1, 30):  # 29 distinct ports > threshold of 15
        engine.analyze("1.2.3.4", "192.168.1.10", port, "TCP", now, SYN_ONLY)
    assert "Port Scan" in alerts.types()


def test_normal_traffic_no_alert():
    engine, alerts = make_engine()
    now = time.time()
    # A few legitimate established connections (SYN-ACK) must not alert.
    for _ in range(10):
        engine.analyze("192.168.1.5", "192.168.1.10", 443, "TCP", now, SYN_ACK)
    assert alerts.types() == []


def test_dos_flood_detected():
    engine, alerts = make_engine()
    now = time.time()
    for _ in range(engine.cfg.dos_threshold + 5):
        engine.analyze("9.9.9.9", "192.168.1.10", 80, "TCP", now, SYN_ACK)
    assert "DoS / Flood" in alerts.types()


def test_syn_flood_detected():
    engine, alerts = make_engine()
    now = time.time()
    for _ in range(engine.cfg.syn_flood_threshold + 5):
        engine.analyze("6.6.6.6", "192.168.1.10", 80, "TCP", now, SYN_ONLY)
    assert "SYN Flood" in alerts.types()


def test_icmp_flood_detected():
    engine, alerts = make_engine()
    now = time.time()
    for _ in range(engine.cfg.icmp_flood_threshold + 5):
        engine.analyze("7.7.7.7", "192.168.1.10", None, "ICMP", now)
    assert "ICMP Flood" in alerts.types()


def test_stealth_xmas_scan_detected():
    engine, alerts = make_engine()
    engine.analyze("4.4.4.4", "192.168.1.10", 443, "TCP", time.time(), XMAS)
    assert "Stealth Scan" in alerts.types()


def test_brute_force_detected():
    engine, alerts = make_engine()
    now = time.time()
    for _ in range(engine.cfg.brute_force_threshold + 2):
        engine.analyze("5.5.5.5", "192.168.1.10", 22, "TCP", now, SYN_ONLY)
    assert "Brute Force" in alerts.types()


def test_sensitive_port_detected():
    engine, alerts = make_engine()
    engine.analyze("3.3.3.3", "192.168.1.10", 445, "TCP", time.time(), SYN_ONLY)
    assert "Suspicious Port Access" in alerts.types()


def test_blacklisted_ip_detected():
    engine, alerts = make_engine()
    bad = next(iter(engine.cfg.ip_blacklist))
    engine.analyze(bad, "192.168.1.10", 4444, "TCP", time.time(), SYN_ONLY)
    assert "Blacklisted IP" in alerts.types()


def test_alert_cooldown_prevents_spam():
    engine, alerts = make_engine()
    now = time.time()
    # Two back-to-back scans within the cooldown window should alert only once.
    for _ in range(2):
        for port in range(1, 30):
            engine.analyze("1.1.1.2", "192.168.1.10", port, "TCP", now, SYN_ONLY)
    assert alerts.types().count("Port Scan") == 1


def test_unique_sources_remain_bounded():
    alerts = FakeAlerts()
    cfg = Config(max_tracker_keys=32, max_cooldown_entries=40)
    engine = DetectionEngine(alerts, cfg)
    for number in range(2000):
        engine.analyze(f"10.{number // 65536}.{number // 256 % 256}.{number % 256}",
                       "192.168.1.10", 80, "UDP", float(number))
    sizes = engine.state_sizes()
    assert all(sizes[name] <= 32 for name in engine._TRACKERS)
    assert sizes["cooldowns"] <= 40
    assert sizes["expiry_queue"] <= 32 * len(engine._TRACKERS) * 2


def test_inactive_state_and_cooldown_are_evicted():
    alerts = FakeAlerts()
    cfg = Config(cleanup_interval_packets=1, cleanup_budget=20, state_ttl=31)
    engine = DetectionEngine(alerts, cfg)
    engine.analyze("10.0.0.1", "192.168.1.10", 445, "TCP", 1.0, SYN_ONLY)
    assert engine.state_sizes()["cooldowns"]
    engine.analyze("10.0.0.2", "192.168.1.10", 80, "TCP", 40.0, SYN_ACK)
    assert "10.0.0.1" not in engine.dos_tracker
    assert engine.state_sizes()["cooldowns"] == 0


def test_window_boundary_and_out_of_order_timestamps_are_predictable():
    alerts = FakeAlerts()
    cfg = Config(port_scan_threshold=2)
    engine = DetectionEngine(alerts, cfg)
    engine.analyze("10.0.0.1", "192.168.1.10", 80, "TCP", 20.0, SYN_ONLY)
    # A late packet is evaluated at the engine's current logical time.
    engine.analyze("10.0.0.1", "192.168.1.10", 81, "TCP", 10.0, SYN_ONLY)
    assert "Port Scan" in alerts.types()


def test_duplicate_ports_do_not_form_a_scan_and_malformed_input_is_ignored():
    engine, alerts = make_engine()
    for _ in range(30):
        engine.analyze("10.0.0.1", "192.168.1.10", 80, "TCP", 10.0, SYN_ONLY)
    engine.analyze(None, "192.168.1.10", 80, "TCP", 10.0, SYN_ONLY)
    engine.analyze("10.0.0.1", "192.168.1.10", "bad", "TCP", 10.0, SYN_ONLY)
    engine.analyze("10.0.0.1", "192.168.1.10", 80, "TCP", float("nan"), SYN_ONLY)
    assert "Port Scan" not in alerts.types()
