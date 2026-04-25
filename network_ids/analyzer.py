from collections import Counter, deque
from datetime import datetime

import pandas as pd

from network_ids.models import PacketInfo


class TrafficAnalyzer:
    def __init__(self) -> None:
        self.start_time = datetime.now()
        self.end_time: datetime | None = None

        self.total_packets = 0
        self.packets_per_protocol: Counter[str] = Counter()
        self.packets_per_src_ip: Counter[str] = Counter()
        self.packets_per_dst_ip: Counter[str] = Counter()
        self.port_usage: Counter[int] = Counter()
        self.packet_sizes: list[int] = []

        self.packet_timestamps = deque()
        self.packets_over_time: Counter[str] = Counter()

    def update(self, info: PacketInfo) -> None:
        self.total_packets += 1
        self.packets_per_protocol[info.protocol] += 1
        self.packets_per_src_ip[info.src_ip] += 1
        self.packets_per_dst_ip[info.dst_ip] += 1
        self.packet_sizes.append(info.packet_size)

        if info.dst_port is not None:
            self.port_usage[info.dst_port] += 1

        self.packet_timestamps.append(info.epoch_time)
        self._trim_rate_window(info.epoch_time)

        second_key = datetime.fromtimestamp(info.epoch_time).strftime("%H:%M:%S")
        self.packets_over_time[second_key] += 1

    def _trim_rate_window(self, current_time: float) -> None:
        one_second_ago = current_time - 1.0
        while self.packet_timestamps and self.packet_timestamps[0] < one_second_ago:
            self.packet_timestamps.popleft()

    def current_packet_rate(self) -> int:
        return len(self.packet_timestamps)

    def stop(self) -> None:
        self.end_time = datetime.now()

    def capture_duration_seconds(self) -> float:
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()

    def summary(self, alert_count: int) -> dict:
        most_active_src = self.packets_per_src_ip.most_common(1)
        most_active_dst = self.packets_per_dst_ip.most_common(1)
        most_used_proto = self.packets_per_protocol.most_common(1)
        most_used_port = self.port_usage.most_common(1)

        unique_ips = set(self.packets_per_src_ip.keys()) | set(self.packets_per_dst_ip.keys())
        avg_packet_size = round(sum(self.packet_sizes) / len(self.packet_sizes), 2) if self.packet_sizes else 0.0

        return {
            "Total Packets": self.total_packets,
            "Unique IP Addresses": len(unique_ips),
            "Most Active Source IP": most_active_src[0][0] if most_active_src else "N/A",
            "Most Active Destination IP": most_active_dst[0][0] if most_active_dst else "N/A",
            "Most Used Protocol": most_used_proto[0][0] if most_used_proto else "N/A",
            "Most Used Port": most_used_port[0][0] if most_used_port else "N/A",
            "Number of Alerts": alert_count,
            "Average Packet Size": avg_packet_size,
            "Capture Duration (seconds)": round(self.capture_duration_seconds(), 2),
        }

    def summary_dataframe(self, alert_count: int) -> pd.DataFrame:
        return pd.DataFrame(list(self.summary(alert_count).items()), columns=["Metric", "Value"])

