from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "reports"

PACKET_LOG_FILE = LOG_DIR / "packet_log.csv"
ALERT_LOG_FILE = LOG_DIR / "alerts_log.txt"
SUMMARY_REPORT_FILE = REPORT_DIR / "summary_report.txt"
SUMMARY_REPORT_CSV = REPORT_DIR / "summary_report.csv"
GRAPH_OUTPUT_FILE = REPORT_DIR / "traffic_graphs.png"

SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    445: "SMB",
    3389: "RDP",
}

IDS_RULES = {
    "port_scan_window_seconds": 10,
    "port_scan_unique_ports_threshold": 15,
    "traffic_flood_window_seconds": 5,
    "traffic_flood_packet_threshold": 80,
    "icmp_flood_window_seconds": 3,
    "icmp_flood_packet_threshold": 30,
    "alert_cooldown_seconds": 8,
}

# Keep rules configurable so the project can be demonstrated in a simple or extended mode.
ENABLED_RULES = {
    "port_scan": True,
    "suspicious_port_access": True,
    "traffic_flood": True,
    "icmp_flood": True,
    "unknown_protocol": True,
}

SNIFF_INTERFACE = None
