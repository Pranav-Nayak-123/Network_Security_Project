from collections import defaultdict, deque

from network_ids.config import ENABLED_RULES, IDS_RULES, SUSPICIOUS_PORTS
from network_ids.models import PacketInfo


class IntrusionDetector:
    def __init__(self) -> None:
        self.ip_ports = defaultdict(deque)
        self.ip_packet_times = defaultdict(deque)
        self.ip_icmp_times = defaultdict(deque)
        self.last_alert_time: dict[tuple[str, str], float] = {}

    def _in_cooldown(self, rule_name: str, ip: str, now: float) -> bool:
        key = (rule_name, ip)
        last = self.last_alert_time.get(key)
        if last is None:
            return False
        return now - last < IDS_RULES["alert_cooldown_seconds"]

    def _remember_alert(self, rule_name: str, ip: str, now: float) -> None:
        self.last_alert_time[(rule_name, ip)] = now

    @staticmethod
    def _trim_window(queue: deque, now: float, window_seconds: int) -> None:
        min_time = now - window_seconds
        while queue and queue[0][0] < min_time:
            queue.popleft()

    @staticmethod
    def _trim_time_window(queue: deque, now: float, window_seconds: int) -> None:
        min_time = now - window_seconds
        while queue and queue[0] < min_time:
            queue.popleft()

    def detect(self, info: PacketInfo) -> list[str]:
        alerts: list[str] = []
        now = info.epoch_time
        src_ip = info.src_ip

        self.ip_packet_times[src_ip].append(now)
        self._trim_time_window(
            self.ip_packet_times[src_ip],
            now,
            IDS_RULES["traffic_flood_window_seconds"],
        )

        if info.protocol == "ICMP":
            self.ip_icmp_times[src_ip].append(now)
            self._trim_time_window(
                self.ip_icmp_times[src_ip],
                now,
                IDS_RULES["icmp_flood_window_seconds"],
            )

        if info.dst_port is not None and ENABLED_RULES["port_scan"]:
            self.ip_ports[src_ip].append((now, info.dst_port))
            self._trim_window(
                self.ip_ports[src_ip],
                now,
                IDS_RULES["port_scan_window_seconds"],
            )

            unique_ports = {port for _, port in self.ip_ports[src_ip]}
            if (
                len(unique_ports) >= IDS_RULES["port_scan_unique_ports_threshold"]
                and not self._in_cooldown("port_scan", src_ip, now)
            ):
                alerts.append(f"Possible Port Scan from {src_ip}")
                self._remember_alert("port_scan", src_ip, now)

        if (
            ENABLED_RULES["traffic_flood"]
            and
            len(self.ip_packet_times[src_ip]) >= IDS_RULES["traffic_flood_packet_threshold"]
            and not self._in_cooldown("traffic_flood", src_ip, now)
        ):
            alerts.append(f"Traffic Flood detected from {src_ip}")
            self._remember_alert("traffic_flood", src_ip, now)

        if (
            ENABLED_RULES["icmp_flood"]
            and info.protocol == "ICMP"
            and len(self.ip_icmp_times[src_ip]) >= IDS_RULES["icmp_flood_packet_threshold"]
            and not self._in_cooldown("icmp_flood", src_ip, now)
        ):
            alerts.append(f"ICMP Flood detected from {src_ip}")
            self._remember_alert("icmp_flood", src_ip, now)

        if (
            ENABLED_RULES["suspicious_port_access"]
            and info.dst_port in SUSPICIOUS_PORTS
            and not self._in_cooldown("suspicious_port", src_ip, now)
        ):
            service = SUSPICIOUS_PORTS[info.dst_port]
            alerts.append(
                f"Suspicious Port Access: {src_ip} -> {info.dst_ip}:{info.dst_port} ({service})"
            )
            self._remember_alert("suspicious_port", src_ip, now)

        if (
            ENABLED_RULES["unknown_protocol"]
            and info.protocol == "UNKNOWN"
            and not self._in_cooldown("unknown_protocol", src_ip, now)
        ):
            alerts.append(f"Unknown Protocol traffic detected from {src_ip}")
            self._remember_alert("unknown_protocol", src_ip, now)

        return alerts
