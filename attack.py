"""Conservatively capped active lab checks for explicitly authorized hosts.

Running this file with no arguments performs no network activity. The normal
project demo is ``python main.py --simulate``.
"""

import argparse
import ipaddress
import socket
import sys
import threading
import time

ACKNOWLEDGEMENT = "I-OWN-OR-AM-AUTHORIZED-TO-TEST-THIS-TARGET"
RFC1918 = tuple(ipaddress.ip_network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))
MAX_PORTS = 32
MAX_CONNECTIONS = 600
MAX_THREADS = 8
MAX_RAW_PACKETS = 250


def validate_target(value):
    """Return an allowed IPv4 target or raise argparse.ArgumentTypeError."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("target must be a literal IPv4 address, not a domain") from exc
    if address.version != 4:
        raise argparse.ArgumentTypeError("only IPv4 lab targets are supported")
    allowed = address.is_loopback or any(address in network for network in RFC1918)
    if not allowed or address.is_multicast or address.is_unspecified or address.is_link_local:
        raise argparse.ArgumentTypeError("target must be loopback or an RFC 1918 private IPv4 address")
    return str(address)


def _tcp_knock(target, port, timeout=0.15):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(min(max(timeout, 0.05), 0.25))
    try:
        sock.connect((target, port))
    except OSError:
        pass
    finally:
        sock.close()


def port_scan(target, ports=MAX_PORTS):
    ports = min(max(int(ports), 1), MAX_PORTS)
    print(f"[*] Authorized port check: {ports} ports on {target}")
    for port in range(1, ports + 1):
        _tcp_knock(target, port)


def dos_flood(target, port=80, count=MAX_CONNECTIONS, threads=MAX_THREADS):
    """Capped connection burst for an isolated, authorized lab."""
    count = min(max(int(count), 1), MAX_CONNECTIONS)
    threads = min(max(int(threads), 1), MAX_THREADS, count)
    print(f"[*] Authorized capped burst: {count} connections to {target}:{port}")

    def worker(amount):
        for _ in range(amount):
            _tcp_knock(target, port)

    base, remainder = divmod(count, threads)
    pool = [
        threading.Thread(target=worker, args=(base + (index < remainder),), daemon=True)
        for index in range(threads)
    ]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join()


def brute_force(target, port=22, count=25):
    """Capped connection-attempt pattern; no credentials are sent."""
    count = min(max(int(count), 1), 30)
    for _ in range(count):
        _tcp_knock(target, port)


def sensitive_access(target):
    _tcp_knock(target, 445)


def _scapy_components():
    try:
        from scapy.all import ICMP, IP, TCP, RandShort, send
    except ImportError as exc:
        raise RuntimeError(f"Scapy is required for raw lab checks: {exc}") from exc
    return ICMP, IP, TCP, RandShort, send


def syn_flood(target, port=80, count=MAX_RAW_PACKETS):
    _, IP, TCP, RandShort, send = _scapy_components()
    count = min(max(int(count), 1), MAX_RAW_PACKETS)
    send(IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="S"), count=count, verbose=0)


def icmp_flood(target, count=120):
    ICMP, IP, _, _, send = _scapy_components()
    count = min(max(int(count), 1), 150)
    send(IP(dst=target) / ICMP(), count=count, verbose=0)


def stealth_scan(target):
    _, IP, TCP, RandShort, send = _scapy_components()
    sport = RandShort()
    for flags in ("", "F", "FPU"):
        send(IP(dst=target) / TCP(sport=sport, dport=80, flags=flags), verbose=0)


def full_check(target, raw=False):
    port_scan(target)
    time.sleep(0.5)
    sensitive_access(target)
    time.sleep(0.5)
    brute_force(target)
    time.sleep(0.5)
    dos_flood(target)
    if raw:
        time.sleep(0.5)
        syn_flood(target)
        time.sleep(0.5)
        icmp_flood(target)
        time.sleep(0.5)
        stealth_scan(target)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Capped active checks for an isolated, authorized private lab.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("action", nargs="?", default="simulate", choices=(
        "simulate", "port-scan", "dos", "brute-force", "sensitive",
        "syn-flood", "icmp-flood", "stealth", "full",
    ))
    parser.add_argument("--target", type=validate_target)
    parser.add_argument("--raw", action="store_true", help="Include capped raw-packet checks in 'full'.")
    parser.add_argument(
        "--i-understand-and-am-authorized",
        dest="acknowledgement",
        metavar="TEXT",
        help=f"Required exact text: {ACKNOWLEDGEMENT}",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.action == "simulate":
        print("Safe default: no network activity was performed.")
        print("Run the offline demo with: python main.py --simulate")
        return 0
    if not args.target:
        print("error: active checks require --target with a private/loopback IPv4 address", file=sys.stderr)
        return 2
    if args.acknowledgement != ACKNOWLEDGEMENT:
        print(f"error: active checks require --i-understand-and-am-authorized {ACKNOWLEDGEMENT}", file=sys.stderr)
        return 2

    print("AUTHORIZED PRIVATE-LAB CHECK; traffic is real but conservatively capped.")
    actions = {
        "port-scan": port_scan,
        "dos": dos_flood,
        "brute-force": brute_force,
        "sensitive": sensitive_access,
        "syn-flood": syn_flood,
        "icmp-flood": icmp_flood,
        "stealth": stealth_scan,
    }
    try:
        if args.action == "full":
            full_check(args.target, args.raw)
        else:
            actions[args.action](args.target)
    except (KeyboardInterrupt, RuntimeError) as exc:
        print(f"Stopped: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
