import matplotlib.pyplot as plt

from network_ids.analyzer import TrafficAnalyzer
from network_ids.config import GRAPH_OUTPUT_FILE, REPORT_DIR


def generate_graphs(analyzer: TrafficAnalyzer) -> str:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    fig, axes = plt.subplots(3, 2, figsize=(16, 14))
    fig.suptitle("Network Traffic Analysis Graphs", fontsize=16, fontweight="bold")

    proto_labels = list(analyzer.packets_per_protocol.keys()) or ["No Data"]
    proto_values = list(analyzer.packets_per_protocol.values()) or [1]
    axes[0, 0].pie(proto_values, labels=proto_labels, autopct="%1.1f%%", startangle=140)
    axes[0, 0].set_title("Protocol Distribution")

    top_src = analyzer.packets_per_src_ip.most_common(5)
    src_labels = [ip for ip, _ in top_src] or ["No Data"]
    src_values = [count for _, count in top_src] or [0]
    axes[0, 1].bar(src_labels, src_values, color="steelblue")
    axes[0, 1].set_title("Top 5 Source IPs")
    axes[0, 1].set_ylabel("Packets")
    axes[0, 1].tick_params(axis="x", rotation=30)

    top_ports = analyzer.port_usage.most_common(10)
    port_labels = [str(port) for port, _ in top_ports] or ["No Data"]
    port_values = [count for _, count in top_ports] or [0]
    axes[1, 0].bar(port_labels, port_values, color="darkorange")
    axes[1, 0].set_title("Port Usage Distribution (Top 10)")
    axes[1, 0].set_ylabel("Packets")
    axes[1, 0].tick_params(axis="x", rotation=30)

    if analyzer.packet_sizes:
        axes[1, 1].hist(analyzer.packet_sizes, bins=20, color="seagreen", edgecolor="black")
    else:
        axes[1, 1].bar(["No Data"], [0], color="seagreen")
    axes[1, 1].set_title("Packet Size Distribution")
    axes[1, 1].set_xlabel("Packet Size (bytes)")
    axes[1, 1].set_ylabel("Frequency")

    time_keys = sorted(analyzer.packets_over_time.keys())
    time_values = [analyzer.packets_over_time[k] for k in time_keys]
    if time_keys:
        axes[2, 0].plot(time_keys, time_values, marker="o", linewidth=1.5, color="purple")
    else:
        axes[2, 0].plot(["00:00:00"], [0], marker="o", linewidth=1.5, color="purple")
    axes[2, 0].set_title("Packets Over Time")
    axes[2, 0].set_ylabel("Packets")
    axes[2, 0].tick_params(axis="x", rotation=45)

    axes[2, 1].axis("off")
    axes[2, 1].text(
        0.03,
        0.8,
        (
            "Generated Charts\n"
            "- Protocol distribution (pie)\n"
            "- Top source IPs\n"
            "- Port usage distribution\n"
            "- Packet size distribution\n"
            "- Packets over time"
        ),
        fontsize=12,
        va="top",
    )

    plt.tight_layout(rect=[0, 0, 1, 0.97])
    plt.savefig(GRAPH_OUTPUT_FILE, dpi=150)
    plt.show()
    return str(GRAPH_OUTPUT_FILE)

