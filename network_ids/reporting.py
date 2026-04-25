from pathlib import Path

from network_ids.analyzer import TrafficAnalyzer
from network_ids.config import REPORT_DIR, SUMMARY_REPORT_CSV, SUMMARY_REPORT_FILE
from network_ids.models import PacketInfo


def print_packet(info: PacketInfo, total_packets: int, alert_count: int, packet_rate: int) -> None:
    print(
        "\nPacket Captured:\n"
        f"  Timestamp        : {info.timestamp}\n"
        f"  Source IP        : {info.src_ip}:{info.src_port if info.src_port else '-'}\n"
        f"  Destination IP   : {info.dst_ip}:{info.dst_port if info.dst_port else '-'}\n"
        f"  Protocol         : {info.protocol}\n"
        f"  Service          : {info.service}\n"
        f"  Packet Size      : {info.packet_size} bytes\n"
        f"  TCP Flags        : {info.flags}\n"
        f"  Live Packet Count: {total_packets}\n"
        f"  Live Alert Count : {alert_count}\n"
        f"  Packet Rate      : {packet_rate} pkt/s"
    )


def print_alert(message: str) -> None:
    print(f"ALERT: {message}")


def print_summary(analyzer: TrafficAnalyzer, alert_count: int) -> dict:
    summary = analyzer.summary(alert_count)
    print("\nTraffic Summary Report")
    print("=" * 60)
    for metric, value in summary.items():
        print(f"{metric:<28}: {value}")
    print("=" * 60)
    return summary


def export_summary(analyzer: TrafficAnalyzer, alert_count: int) -> tuple[Path, Path]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    summary = analyzer.summary(alert_count)

    with SUMMARY_REPORT_FILE.open("w", encoding="utf-8") as f:
        f.write("Traffic Summary Report\n")
        f.write("=" * 60 + "\n")
        for metric, value in summary.items():
            f.write(f"{metric}: {value}\n")
        f.write("=" * 60 + "\n")

    analyzer.summary_dataframe(alert_count).to_csv(SUMMARY_REPORT_CSV, index=False)
    return SUMMARY_REPORT_FILE, SUMMARY_REPORT_CSV

