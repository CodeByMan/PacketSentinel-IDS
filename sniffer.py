"""Scapy live capture and resource-limited streaming PCAP replay."""

import ipaddress
import os
import time

from scapy.all import AsyncSniffer, ICMP, IP, TCP, UDP, PcapReader, conf, sniff

from config import config
from stats import stats


def _is_private(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.is_private or address.is_loopback


def _process_packet(packet, engine, cfg=config):
    """Extract only the fields used by the detector; ignore malformed frames."""
    try:
        if IP not in packet:
            return False
        src_ip = str(packet[IP].src)
        dst_ip = str(packet[IP].dst)
        if cfg.monitor_private_only and not (_is_private(src_ip) or _is_private(dst_ip)):
            return False

        dst_port = None
        protocol = "OTHER"
        tcp_flags = 0
        if TCP in packet:
            protocol = "TCP"
            dst_port = int(packet[TCP].dport)
            tcp_flags = int(packet[TCP].flags)
        elif UDP in packet:
            protocol = "UDP"
            dst_port = int(packet[UDP].dport)
        elif ICMP in packet:
            protocol = "ICMP"
        try:
            timestamp = float(packet.time)
        except (AttributeError, TypeError, ValueError, OverflowError):
            timestamp = time.time()
    except (AttributeError, TypeError, ValueError, OverflowError):
        return False

    stats.record(protocol)
    engine.analyze(src_ip, dst_ip, dst_port, protocol, timestamp, tcp_flags)
    return True


def replay_pcap(
    engine,
    pcap_file,
    *,
    max_packets=None,
    max_bytes=None,
    max_seconds=None,
    cfg=config,
):
    """Stream an authorized PCAP while enforcing packet, byte, and time limits."""
    max_packets = cfg.pcap_max_packets if max_packets is None else max_packets
    max_bytes = cfg.pcap_max_bytes if max_bytes is None else max_bytes
    max_seconds = cfg.pcap_max_seconds if max_seconds is None else max_seconds
    for name, value in (("max_packets", max_packets), ("max_bytes", max_bytes), ("max_seconds", max_seconds)):
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0
        ):
            raise ValueError(f"{name} must be positive or None")
    if max_bytes is not None and os.path.getsize(pcap_file) > max_bytes:
        raise ValueError(f"PCAP exceeds the configured {max_bytes}-byte limit")

    print(f"[+] Streaming authorized capture: {pcap_file}")
    started = time.monotonic()
    processed = 0
    with PcapReader(pcap_file) as reader:
        iterator = iter(reader)
        while max_packets is None or processed < max_packets:
            if max_seconds is not None and time.monotonic() - started >= max_seconds:
                print(f"[!] Replay stopped at the configured {max_seconds:g}-second limit.")
                break
            try:
                packet = next(iterator)
            except StopIteration:
                break
            _process_packet(packet, engine, cfg)
            processed += 1
        if max_packets is not None and processed >= max_packets:
            print(f"[!] Replay stopped at the configured {max_packets}-packet limit.")
    print(f"[+] Replay complete: {processed} packets read.")
    return processed


def start_sniffing(engine, cfg=config):
    """Start authorized live capture and optionally monitor Windows loopback."""
    callback = lambda packet: _process_packet(packet, engine, cfg)
    iface = cfg.interface
    iface_label = iface or f"{conf.iface} (auto)"
    if cfg.capture_loopback:
        try:
            loopback = AsyncSniffer(
                iface=r"\Device\NPF_Loopback", filter="ip", prn=callback, store=False,
            )
            loopback.start()
            print(r"[+] Loopback sniffer active -> \Device\NPF_Loopback")
        except Exception as exc:
            print(f"[!] Loopback sniffer unavailable ({exc}); loopback capture is off.")
    print(f"[+] Live sniffer active -> {iface_label}")
    print("[*] Capture only networks you own or are authorized to monitor. Ctrl+C stops capture.\n")
    sniff(iface=iface, filter="ip", prn=callback, store=False)
