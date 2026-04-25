# Real-Time Network Traffic Analyzer and Intrusion Detection System

## Project Overview
This project is a mini network monitoring and intrusion detection tool built in Python.  
It behaves like a simplified combination of Wireshark + Snort:
- Captures packets in real time
- Extracts and displays packet metadata
- Maintains live traffic statistics
- Detects suspicious behavior using IDS rules
- Logs packets and alerts to files
- Generates a summary report and traffic graphs on stop

## Features
- Live packet sniffing using `scapy`
- Protocol identification: `TCP`, `UDP`, `ICMP`, `DNS`, `HTTP`, `HTTPS`, `UNKNOWN`
- IDS alerts for:
  - Port scanning
  - Suspicious port access (21, 22, 23, 25, 445, 3389)
  - Traffic flood
  - ICMP flood
  - Unknown protocol traffic
- Continuous logging:
  - `logs/packet_log.csv`
  - `logs/alerts_log.txt`
- Ctrl+C summary report:
  - total packets
  - active IPs and protocols
  - average packet size
  - alert count
  - capture duration
- Graph generation using `matplotlib`

## Viva-Friendly Scope (Recommended)
If you want to keep your explanation simple for lecturers, present these as your core IDS rules:
- Port scanning
- Suspicious port access
- Traffic flood

You can enable/disable rules from `network_ids/config.py` under `ENABLED_RULES`.

## Project Structure
```text
Network_Security_Project/
+-- main.py
+-- requirements.txt
+-- README.md
+-- network_ids/
|   +-- __init__.py
|   +-- config.py
|   +-- models.py
|   +-- sniffer.py
|   +-- analyzer.py
|   +-- ids.py
|   +-- network_logger.py
|   +-- reporting.py
|   +-- visualizer.py
+-- logs/
|   +-- packet_log.csv
|   +-- alerts_log.txt
+-- reports/
    +-- summary_report.txt
    +-- summary_report.csv
    +-- traffic_graphs.png
```

## Installation
1. Create and activate a virtual environment (recommended):
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

2. Install dependencies:
```powershell
pip install -r requirements.txt
```

## How to Run
Run as administrator/root because raw packet sniffing requires elevated privileges.

```powershell
python main.py
```

Stop with `Ctrl+C` to display the summary and show graphs.

## Sample Terminal Output
```text
Starting Network Traffic Analyzer and IDS...
Press Ctrl+C to stop capture and view summary.

Packet Captured:
  Timestamp        : 2026-04-05 11:32:10
  Source IP        : 192.168.1.15:53122
  Destination IP   : 142.250.193.78:443
  Protocol         : HTTPS
  Service          : https
  Packet Size      : 74 bytes
  TCP Flags        : PA
  Live Packet Count: 12
  Live Alert Count : 1
  Packet Rate      : 7 pkt/s

ALERT: Possible Port Scan from 192.168.1.10
ALERT: Suspicious Port Access: 192.168.1.20 -> 192.168.1.1:23 (Telnet)
```

## Intrusion Detection Logic
Rules are implemented in `network_ids/ids.py`:

1. Port Scan Detection  
Tracks destination ports contacted by each source IP within a time window.  
If one source IP hits too many unique ports quickly, it raises:
`ALERT: Possible Port Scan from <ip>`

2. Suspicious Port Access  
If traffic targets known risky ports (FTP/SSH/Telnet/SMTP/SMB/RDP), it raises an alert.

3. Traffic Flood Detection  
If a source IP sends too many packets in a short window, it raises flood alert.

4. ICMP Flood Detection  
If too many ICMP packets come from one IP in a short window, it raises ICMP flood alert.

5. Unknown Protocol Detection  
If protocol cannot be classified, it raises a suspicious protocol alert.

Each rule uses cooldown timing to avoid alert spam.

## Graphs Generated at Stop
- Protocol distribution (pie chart)
- Top 5 source IPs (bar chart)
- Port usage distribution (bar chart)
- Packet size distribution (histogram)
- Packets over time (line chart)

## Notes
- You can tune IDS thresholds and suspicious ports in `network_ids/config.py`.
- You can toggle IDS rules in `network_ids/config.py` using `ENABLED_RULES`.
- If you want to monitor a specific NIC, set `SNIFF_INTERFACE` in `config.py`.
- Traffic visibility depends on your network and privileges.
