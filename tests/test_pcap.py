import os
import sys

import pytest
from scapy.all import IP, TCP, PcapWriter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from sniffer import replay_pcap


class FakeEngine:
    def __init__(self):
        self.packets = []

    def analyze(self, *fields):
        self.packets.append(fields)


def test_pcap_replay_streams_and_honors_packet_limit(tmp_path):
    path = tmp_path / "authorized-sample.pcap"
    writer = PcapWriter(str(path), sync=True)
    try:
        for port in (80, 81, 82):
            writer.write(IP(src="192.168.1.2", dst="192.168.1.3") / TCP(dport=port, flags="S"))
    finally:
        writer.close()

    engine = FakeEngine()
    count = replay_pcap(engine, str(path), max_packets=2, max_bytes=10_000,
                        max_seconds=5, cfg=Config())
    assert count == 2
    assert len(engine.packets) == 2


def test_pcap_byte_limit_is_checked_before_open(tmp_path):
    path = tmp_path / "too-large.pcap"
    path.write_bytes(b"0123456789")
    with pytest.raises(ValueError, match="exceeds"):
        replay_pcap(FakeEngine(), str(path), max_bytes=5, cfg=Config())
