import csv
from pathlib import Path

from network_ids.config import ALERT_LOG_FILE, LOG_DIR, PACKET_LOG_FILE
from network_ids.models import PacketInfo


class NetworkLogger:
    def __init__(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._initialize_packet_log()
        self._initialize_alert_log()

    @staticmethod
    def _ensure_file(path: Path) -> None:
        if not path.exists():
            path.touch()

    def _initialize_packet_log(self) -> None:
        if PACKET_LOG_FILE.exists():
            return
        with PACKET_LOG_FILE.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Timestamp",
                    "Source IP",
                    "Destination IP",
                    "Protocol",
                    "Source Port",
                    "Destination Port",
                    "Service",
                    "Packet Size",
                    "Flags",
                ]
            )

    def _initialize_alert_log(self) -> None:
        self._ensure_file(ALERT_LOG_FILE)

    def log_packet(self, info: PacketInfo) -> None:
        with PACKET_LOG_FILE.open("a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    info.timestamp,
                    info.src_ip,
                    info.dst_ip,
                    info.protocol,
                    info.src_port if info.src_port is not None else "-",
                    info.dst_port if info.dst_port is not None else "-",
                    info.service,
                    info.packet_size,
                    info.flags,
                ]
            )

    def log_alert(self, timestamp: str, message: str, ip_address: str) -> None:
        with ALERT_LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"{timestamp} | {message} | IP: {ip_address}\n")

