# simulator.py
# Demo / "no-setup" mode. Instead of capturing real packets (which needs admin
# rights + Npcap + an actual attacker), this feeds the SAME detection engine a
# stream of synthetic packets that reproduce every attack the IDS can detect.
#
# This is what makes the project runnable by anyone — a recruiter can clone it,
# run `python main.py --simulate`, open the dashboard, and immediately watch
# alerts light up. The detection logic exercised is identical to live mode; only
# the packet source differs.

import time
import random

from stats import stats

# A small cast of fake hosts to make the dashboard look realistic.
VICTIM = "192.168.1.10"
NORMAL_PEERS = ["192.168.1.5", "192.168.1.20", "192.168.1.33", "198.51.100.10", "203.0.113.8"]
ATTACKERS = ["192.168.1.66", "10.0.0.99", "172.16.5.4", "192.168.1.150"]
BLACKLISTED = "192.0.2.66"  # RFC 5737 example; also present in config.ip_blacklist

# TCP flag constants (match detection.py)
SYN = 0x02
SYN_ACK = 0x12
FIN = 0x01
XMAS = 0x29


def _feed(engine, src, dst, port, proto, flags=0):
    """Send one synthetic packet through the engine and count it in stats."""
    stats.record(proto)
    engine.analyze(src, dst, port, proto, time.time(), flags)


def _normal_traffic(engine, n=40):
    """Benign chatter so the live graphs aren't empty between attacks."""
    for _ in range(n):
        src = random.choice(NORMAL_PEERS)
        proto = random.choice(["TCP", "UDP", "TCP"])
        port = random.choice([80, 443, 53, 123, 22])
        flags = SYN_ACK if proto == "TCP" else 0
        _feed(engine, src, VICTIM, port, proto, flags)
        time.sleep(0.01)


def _port_scan(engine, attacker):
    """Probe 60 distinct ports with SYN packets — triggers Port Scan."""
    print(f"[sim] {attacker} -> port scan on {VICTIM}")
    for port in range(20, 80):
        _feed(engine, attacker, VICTIM, port, "TCP", SYN)
        time.sleep(0.005)


def _dos_flood(engine, attacker):
    """Blast 600 packets to trigger DoS / Flood."""
    print(f"[sim] {attacker} -> DoS flood on {VICTIM}")
    for _ in range(600):
        _feed(engine, attacker, VICTIM, 80, "TCP", SYN_ACK)


def _syn_flood(engine, attacker):
    """250 half-open SYN connections — triggers SYN Flood (critical)."""
    print(f"[sim] {attacker} -> SYN flood on {VICTIM}")
    for _ in range(250):
        _feed(engine, attacker, VICTIM, 80, "TCP", SYN)


def _icmp_flood(engine, attacker):
    """120 ICMP echo packets — triggers ICMP Flood."""
    print(f"[sim] {attacker} -> ICMP (ping) flood on {VICTIM}")
    for _ in range(120):
        _feed(engine, attacker, VICTIM, None, "ICMP")


def _brute_force(engine, attacker):
    """25 SSH connection attempts — triggers Brute Force."""
    print(f"[sim] {attacker} -> SSH brute force on {VICTIM}")
    for _ in range(25):
        _feed(engine, attacker, VICTIM, 22, "TCP", SYN)
        time.sleep(0.01)


def _stealth_scan(engine, attacker):
    """A XMAS-scan packet — triggers Stealth Scan."""
    print(f"[sim] {attacker} -> XMAS stealth scan on {VICTIM}")
    _feed(engine, attacker, VICTIM, 443, "TCP", XMAS)


def _sensitive_port(engine, attacker):
    """Touch SMB (445) — triggers Suspicious Port Access."""
    print(f"[sim] {attacker} -> SMB (445) access on {VICTIM}")
    _feed(engine, attacker, VICTIM, 445, "TCP", SYN)


def _blacklisted(engine):
    """Traffic from a known-bad IP — triggers Blacklisted IP (critical)."""
    print(f"[sim] {BLACKLISTED} -> blacklisted IP contact")
    _feed(engine, BLACKLISTED, VICTIM, 4444, "TCP", SYN)


# Each attack scenario, picked at random each cycle.
SCENARIOS = [
    _port_scan, _dos_flood, _syn_flood, _icmp_flood,
    _brute_force, _stealth_scan, _sensitive_port,
]


def start_simulation(engine):
    """
    Continuously: a little normal traffic, then one random attack, repeat.
    Blocks the calling thread until Ctrl+C, exactly like the real sniffer, so
    main.py can treat live and demo mode the same way.
    """
    print("[+] SIMULATION MODE — generating synthetic attack traffic.")
    print("[*] No admin rights or Npcap needed. Watch the dashboard light up.\n")
    while True:
        _normal_traffic(engine)
        scenario = random.choice(SCENARIOS)
        attacker = random.choice(ATTACKERS)
        scenario(engine, attacker)
        # Occasionally sprinkle in blacklisted-IP contact.
        if random.random() < 0.3:
            _blacklisted(engine)
        time.sleep(random.uniform(2.5, 5.0))
