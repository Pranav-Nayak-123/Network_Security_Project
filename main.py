from scapy.all import sniff

from network_ids.analyzer import TrafficAnalyzer
from network_ids.config import ENABLED_RULES, SNIFF_INTERFACE
from network_ids.ids import IntrusionDetector
from network_ids.network_logger import NetworkLogger
from network_ids.reporting import export_summary, print_alert, print_packet, print_summary
from network_ids.sniffer import extract_packet_info
from network_ids.visualizer import generate_graphs


def start_sniffer() -> None:
    analyzer = TrafficAnalyzer()
    detector = IntrusionDetector()
    logger = NetworkLogger()
    alert_count = 0

    print("Starting Network Traffic Analyzer and IDS...")
    print("Press Ctrl+C to stop capture and view summary.\n")
    enabled = [rule for rule, is_on in ENABLED_RULES.items() if is_on]
    print(f"Active IDS Rules: {', '.join(enabled)}\n")

    def process_packet(packet) -> None:
        nonlocal alert_count
        info = extract_packet_info(packet)
        if info is None:
            return

        analyzer.update(info)
        logger.log_packet(info)

        alerts = detector.detect(info)
        for message in alerts:
            alert_count += 1
            print_alert(message)
            logger.log_alert(info.timestamp, message, info.src_ip)

        print_packet(
            info=info,
            total_packets=analyzer.total_packets,
            alert_count=alert_count,
            packet_rate=analyzer.current_packet_rate(),
        )

    try:
        sniff(prn=process_packet, iface=SNIFF_INTERFACE, store=False)
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
    finally:
        analyzer.stop()
        print_summary(analyzer, alert_count)
        txt_path, csv_path = export_summary(analyzer, alert_count)
        graph_path = generate_graphs(analyzer)

        print("\nSaved Reports:")
        print(f"  - Summary (text): {txt_path}")
        print(f"  - Summary (csv) : {csv_path}")
        print(f"  - Graph image   : {graph_path}")


def main() -> None:
    start_sniffer()


if __name__ == "__main__":
    main()
