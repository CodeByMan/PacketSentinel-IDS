# alerts.py
# Central alert pipeline. When the detection engine finds something suspicious
# it calls AlertSystem.trigger(), which fans the alert out to four places:
#   1. the terminal (colored, human-readable)
#   2. alerts.log   (plain text, greppable)
#   3. ids.db       (SQLite, permanent history)   — optional
#   4. an in-memory list the live dashboard reads
#
# Candidate MITRE ATT&CK context is attached for analyst review. A heuristic
# alert is not proof that a particular ATT&CK technique occurred.

import datetime
import threading

from colorama import Fore, Style, init

from config import config

init(autoreset=True)  # make ANSI colors work on Windows terminals

# ── Shared in-memory store the dashboard polls ───────────────────────────────
# Capped so a long run can't grow memory without bound; the SQLite DB keeps the
# full history.
alert_store: list = []
alert_lock = threading.Lock()

SEVERITY_COLORS = {
    "CRITICAL": Fore.MAGENTA,
    "HIGH":     Fore.RED,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.GREEN,
}

# Possible mappings only; analysts must validate each alert against context.
POSSIBLE_MITRE = {
    "Port Scan":              "T1046 Network Service Discovery",
    "Stealth Scan":           "T1046 Network Service Discovery",
    "DoS / Flood":            "T1499 Endpoint Denial of Service",
    "SYN Flood":              "T1499.001 Direct Network Flood",
    "ICMP Flood":             "T1499 Endpoint Denial of Service",
    "Brute Force":            "T1110 Brute Force",
    "Suspicious Port Access": "T1021 Remote Services",
    "Blacklisted IP":         "T1071 Application Layer Protocol",
}


class AlertSystem:
    """Fires alerts to the terminal, log file, database, and in-memory store."""

    def __init__(self, log_file="alerts.log", database=None, max_in_memory=None):
        self.log_file = log_file
        self.database = database  # optional AlertDatabase instance
        self.max_in_memory = max_in_memory or config.alert_retention
        if not isinstance(self.max_in_memory, int) or self.max_in_memory <= 0:
            raise ValueError("max_in_memory must be a positive integer")

    def trigger(self, attacker_ip, attack_type, severity="MEDIUM", details=""):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color = SEVERITY_COLORS.get(severity, Fore.WHITE)
        mitre = POSSIBLE_MITRE.get(attack_type, "—")

        # 1. Terminal block ----------------------------------------------------
        # Use ASCII characters only so this never crashes on Windows code pages.
        print(f"\n{color}{'=' * 60}")
        print(f"  [ALERT]  {severity}  -  {timestamp}")
        print(f"  Type    : {attack_type}")
        print(f"  Source  : {attacker_ip}")
        print(f"  Info    : {details}")
        print(f"  Possible MITRE: {mitre}")
        print(f"{'=' * 60}{Style.RESET_ALL}")

        # 2. Log file ----------------------------------------------------------
        log_line = (
            f"{timestamp} | {severity:8} | {attack_type:25} | "
            f"{attacker_ip:15} | {details}\n"
        )
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_line)
        except OSError as exc:
            print(f"[!] Could not write to log file: {exc}")

        # Build the canonical alert dict (shared by DB + dashboard).
        alert = {
            "timestamp":   timestamp,
            "attacker_ip": attacker_ip,
            "attack_type": attack_type,
            "severity":    severity,
            "details":     details,
            "mitre":       mitre,
        }

        # 3. Persist to SQLite -------------------------------------------------
        if self.database is not None:
            try:
                self.database.insert(alert)
            except Exception as exc:  # never let a DB hiccup kill detection
                print(f"[!] Could not write alert to database: {exc}")

        # 4. In-memory store (capped) -----------------------------------------
        with alert_lock:
            alert_store.append(alert)
            if len(alert_store) > self.max_in_memory:
                del alert_store[:len(alert_store) - self.max_in_memory]
