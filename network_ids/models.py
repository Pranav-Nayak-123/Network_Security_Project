from dataclasses import dataclass


@dataclass
class PacketInfo:
    timestamp: str
    epoch_time: float
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    packet_size: int
    flags: str
    service: str

