# main.py
# Entry point for the IDS. Wires the components together, starts the Flask
# dashboard in a background thread, then runs a packet source in the foreground:
#
#   simulation (default) – generate synthetic traffic offline
#   --live               – capture real packets (needs permission/admin/Npcap)
#   --pcap FILE          – replay a saved .pcap capture file (offline analysis)
#
# Press Ctrl+C to stop everything.

import sys
import argparse
import threading

# Make stdout tolerant of any character on Windows code pages (cp1252 etc.)
# so a stray Unicode glyph can never crash the IDS.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

from config import config
from alerts import AlertSystem
from detection import DetectionEngine
from database import AlertDatabase
from dashboard import start_dashboard
from sniffer import start_sniffing, replay_pcap
from simulator import start_simulation

BANNER = r"""
   _____ ____  _____    _____ _   _ _______ _____  _    _ _____ _____ ____  _   _
  |_   _|  _ \/ ____|  |_   _| \ | |__   __|  __ \| |  | |  __ \_   _/ __ \| \ | |
    | | | |_) | (___      | | |  \| |  | |  | |__) | |  | | |  | || || |  | |  \| |
    | | |  _ < \___ \     | | | . ` |  | |  |  _  /| |  | | |  | || || |  | | . ` |
   _| |_| |_) |____) |   _| |_| |\  |  | |  | | \ \| |__| | |__| || || |__| | |\  |
  |_____|____/|_____/   |_____|_| \_|  |_|  |_|  \_\\____/|_____/_____\____/|_| \_|
        Real-Time Intrusion Detection System  -  Python + Scapy + Flask
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="Real-time network Intrusion Detection System.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--simulate", action="store_true",
                     help="Offline synthetic demo (also the default mode).")
    src.add_argument("--live", action="store_true",
                     help="Capture an authorized live network (may need admin/Npcap).")
    src.add_argument("--pcap", metavar="FILE",
                     help="Replay and analyse a saved .pcap capture file.")

    p.add_argument("-i", "--interface", metavar="NAME",
                   help="Network interface to sniff (default: auto-detect).")
    p.add_argument("-p", "--port", type=int, default=config.dashboard_port,
                   help="Port for the web dashboard.")
    p.add_argument("--host", choices=("127.0.0.1", "localhost"),
                   default=config.dashboard_host,
                   help="Dashboard bind address; unauthenticated access is loopback-only.")
    p.add_argument("--no-dashboard", action="store_true",
                   help="Run detection only, without the web dashboard.")
    p.add_argument("--no-loopback", action="store_true",
                   help="Disable the Windows loopback (self-scan) sniffer.")
    return p.parse_args()


def main():
    args = parse_args()

    # Push CLI overrides into the shared config.
    if args.interface:
        config.interface = args.interface
    if args.no_loopback:
        config.capture_loopback = False
    if not 1 <= args.port <= 65535:
        raise SystemExit("dashboard port must be between 1 and 65535")
    config.dashboard_port = args.port
    config.dashboard_host = args.host

    mode = "LIVE CAPTURE" if args.live else "PCAP REPLAY" if args.pcap else "SIMULATION"

    print(BANNER)
    print("=" * 70)
    print(f"  Mode       : {mode}")
    if not args.no_dashboard:
        shown_host = "localhost" if config.dashboard_host == "127.0.0.1" else config.dashboard_host
        print(f"  Dashboard  : http://{shown_host}:{config.dashboard_port}")
    print(f"  Log file   : {config.log_file}")
    print(f"  Database   : {config.db_file}")
    print("  Stop       : Ctrl+C")
    print("=" * 70)

    # ── Core components ──────────────────────────────────────────────────────
    database = AlertDatabase(config.db_file)
    alert_system = AlertSystem(log_file=config.log_file, database=database)
    engine = DetectionEngine(alert_system, config)

    # ── Dashboard in a background daemon thread ──────────────────────────────
    if not args.no_dashboard:
        threading.Thread(
            target=start_dashboard,
            kwargs={"host": config.dashboard_host, "port": config.dashboard_port, "database": database},
            daemon=True,
            name="FlaskDashboard",
        ).start()
        print(f"[+] Web dashboard started on {config.dashboard_host}:{config.dashboard_port}\n")

    # ── Run the chosen packet source (blocks until Ctrl+C) ───────────────────
    try:
        if args.live:
            start_sniffing(engine)
        elif args.pcap:
            replay_pcap(engine, args.pcap)
            # Keep the dashboard alive after a one-shot replay so results stay visible.
            if not args.no_dashboard:
                print("\n[*] Replay done — dashboard still live. Press Ctrl+C to exit.")
                threading.Event().wait()
        else:
            start_simulation(engine)
    except KeyboardInterrupt:
        print("\n[*] Stopping IDS — goodbye.")
        sys.exit(0)
    except Exception as exc:
        print(f"\n[!] Error: {exc}")
        if args.live:
            print("[!] For live capture, run as Administrator with Npcap installed,")
            print("[!] or try demo mode instead:  python main.py --simulate")
        sys.exit(1)


if __name__ == "__main__":
    main()
