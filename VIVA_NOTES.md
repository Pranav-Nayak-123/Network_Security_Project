# Viva Notes (Quick)

## One-Line Project Description
This is a Python-based real-time network traffic monitor with basic intrusion detection rules and alert logging.

## Module-Wise Explanation
1. Packet Sniffer (`sniffer.py`)
- Captures live packets using Scapy.
- Extracts source IP, destination IP, protocol, ports, packet size, and TCP flags.

2. Traffic Analyzer (`analyzer.py`)
- Keeps counters for protocol, IP, and port usage.
- Computes packet rate and average packet size.

3. IDS Engine (`ids.py`)
- Applies rule-based checks:
  - Port scan detection
  - Suspicious port access
  - Traffic flood
  - ICMP flood
  - Unknown protocol traffic
- Cooldown logic avoids repeated alert spam.

4. Logging (`network_logger.py`)
- Stores packet records in CSV.
- Stores alerts in text log.

5. Reporting and Graphs (`reporting.py`, `visualizer.py`)
- Prints final summary on Ctrl+C.
- Exports summary and graphs for analysis.

## Why Rule-Based IDS?
- Easy to understand and explain for a mini-project.
- Fast, lightweight, and no model training required.
- Demonstrates core IDS concept clearly.

## Common Viva Questions
1. Why Scapy?
- It provides low-level packet capture and parsing in Python.

2. Why not full Snort-like signatures?
- This project is a simplified educational prototype focused on core behavior detection.

3. What are limitations?
- Threshold-based rules can produce false positives/negatives.
- Encrypted traffic payload is not inspected deeply.

4. How can this be improved?
- Add signature rules, whitelist support, dashboard UI, and persistent database logging.

