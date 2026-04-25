import socket
from datetime import datetime

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP

from network_ids.models import PacketInfo


def _resolve_service(port: int | None, protocol: str) -> str:
    if port is None:
        return "n/a"
    proto = "udp" if protocol.upper() in {"UDP", "DNS"} else "tcp"
    try:
        return socket.getservbyport(int(port), proto)
    except OSError:
        return "unknown"


def _identify_protocol(packet) -> str:
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        if tcp_layer.sport == 80 or tcp_layer.dport == 80:
            return "HTTP"
        if tcp_layer.sport == 443 or tcp_layer.dport == 443:
            return "HTTPS"
        return "TCP"
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        if udp_layer.sport == 53 or udp_layer.dport == 53:
            return "DNS"
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return "UNKNOWN"


def extract_packet_info(packet) -> PacketInfo | None:
    if not packet.haslayer(IP):
        return None

    ts_epoch = float(getattr(packet, "time", datetime.now().timestamp()))
    ts_text = datetime.fromtimestamp(ts_epoch).strftime("%Y-%m-%d %H:%M:%S")
    protocol = _identify_protocol(packet)

    src_port = None
    dst_port = None
    flags = "-"

    if packet.haslayer(TCP):
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
        flags = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    service = _resolve_service(dst_port, protocol)

    return PacketInfo(
        timestamp=ts_text,
        epoch_time=ts_epoch,
        src_ip=packet[IP].src,
        dst_ip=packet[IP].dst,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        packet_size=len(packet),
        flags=flags,
        service=service,
    )

