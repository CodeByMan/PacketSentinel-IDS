"""Validated configuration for the intrusion-detection prototype."""

from dataclasses import asdict, dataclass, field


@dataclass
class Config:
    """All tunable settings, with conservative resource limits."""

    port_scan_threshold: int = 15
    port_scan_window: float = 10
    dos_threshold: int = 500
    dos_window: float = 10
    syn_flood_threshold: int = 200
    syn_flood_window: float = 10
    icmp_flood_threshold: int = 100
    icmp_flood_window: float = 10
    brute_force_threshold: int = 20
    brute_force_window: float = 30
    alert_cooldown: float = 30
    monitor_private_only: bool = True
    log_file: str = "alerts.log"
    db_file: str = "ids.db"
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 5000
    interface: str | None = None
    capture_loopback: bool = True

    max_tracker_keys: int = 2048
    max_events_per_key: int = 1000
    max_cooldown_entries: int = 4096
    state_ttl: float = 120
    cleanup_interval_packets: int = 64
    cleanup_budget: int = 128
    alert_retention: int = 1000
    pcap_max_packets: int | None = 100_000
    pcap_max_bytes: int | None = 256 * 1024 * 1024
    pcap_max_seconds: float | None = 300

    sensitive_ports: dict[int, str] = field(default_factory=lambda: {
        23: "Telnet", 135: "RPC", 445: "SMB", 3389: "RDP", 1433: "MSSQL",
    })
    auth_ports: dict[int, str] = field(default_factory=lambda: {
        21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP",
    })
    # RFC 5737 documentation addresses; examples, not a live threat feed.
    ip_blacklist: set[str] = field(default_factory=lambda: {
        "192.0.2.66", "198.51.100.23", "203.0.113.41",
    })

    def __post_init__(self):
        positive = {
            "port_scan_threshold": self.port_scan_threshold,
            "port_scan_window": self.port_scan_window,
            "dos_threshold": self.dos_threshold,
            "dos_window": self.dos_window,
            "syn_flood_threshold": self.syn_flood_threshold,
            "syn_flood_window": self.syn_flood_window,
            "icmp_flood_threshold": self.icmp_flood_threshold,
            "icmp_flood_window": self.icmp_flood_window,
            "brute_force_threshold": self.brute_force_threshold,
            "brute_force_window": self.brute_force_window,
            "alert_cooldown": self.alert_cooldown,
            "max_tracker_keys": self.max_tracker_keys,
            "max_events_per_key": self.max_events_per_key,
            "max_cooldown_entries": self.max_cooldown_entries,
            "state_ttl": self.state_ttl,
            "cleanup_interval_packets": self.cleanup_interval_packets,
            "cleanup_budget": self.cleanup_budget,
            "alert_retention": self.alert_retention,
        }
        for name, value in positive.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"{name} must be a positive number")
        integer_fields = (
            "port_scan_threshold", "dos_threshold", "syn_flood_threshold",
            "icmp_flood_threshold", "brute_force_threshold", "max_tracker_keys",
            "max_events_per_key", "max_cooldown_entries", "cleanup_interval_packets",
            "cleanup_budget", "alert_retention",
        )
        for name in integer_fields:
            if isinstance(getattr(self, name), bool) or not isinstance(getattr(self, name), int):
                raise ValueError(f"{name} must be a positive integer")
        for name in ("pcap_max_packets", "pcap_max_bytes", "pcap_max_seconds"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0
            ):
                raise ValueError(f"{name} must be positive or None")
        for name in ("pcap_max_packets", "pcap_max_bytes"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, int):
                raise ValueError(f"{name} must be a positive integer or None")
        if isinstance(self.dashboard_port, bool) or not isinstance(self.dashboard_port, int) or not 1 <= self.dashboard_port <= 65535:
            raise ValueError("dashboard_port must be between 1 and 65535")
        if self.dashboard_host not in {"127.0.0.1", "localhost"}:
            raise ValueError("dashboard_host must be 127.0.0.1 or localhost")

        largest_threshold = max(
            self.port_scan_threshold, self.dos_threshold, self.syn_flood_threshold,
            self.icmp_flood_threshold, self.brute_force_threshold,
        )
        if self.max_events_per_key < largest_threshold:
            raise ValueError("max_events_per_key must be at least the largest threshold")
        largest_window = max(
            self.port_scan_window, self.dos_window, self.syn_flood_window,
            self.icmp_flood_window, self.brute_force_window, self.alert_cooldown,
        )
        if self.state_ttl < largest_window:
            raise ValueError("state_ttl must be at least the largest window/cooldown")

    def to_dict(self):
        return asdict(self)


config = Config()
