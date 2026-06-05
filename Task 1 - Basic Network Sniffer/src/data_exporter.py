"""
Data Exporter Module
Exports captured traffic and analysis reports in various formats.
"""

import csv
import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime

try:
    from scapy.all import wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class DataExporter:
    """Exports traffic data and reports."""

    def __init__(self, output_dir: str = "output"):
        """
        Initialize data exporter.

        Args:
            output_dir: Directory for exported files
        """
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def export_csv(self, packets: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
        """
        Export captured packets to CSV format.

        Args:
            packets: List of parsed packets
            filename: Output filename (auto-generated if None)

        Returns:
            Path to exported file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"packets_{timestamp}.csv"

        filepath = os.path.join(self.output_dir, filename)

        if not packets:
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Error", "No packets to export"])
            return filepath

        # Get all possible keys from packets
        all_keys = set()
        for packet in packets:
            all_keys.update(packet.keys())

        fieldnames = sorted(list(all_keys))

        # Write CSV
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for packet in packets:
                # Convert complex types to strings
                row = {}
                for key in fieldnames:
                    value = packet.get(key, "")
                    if isinstance(value, (list, dict)):
                        row[key] = json.dumps(value)
                    else:
                        row[key] = str(value)
                writer.writerow(row)

        return filepath

    def export_pcap(self, packets: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
        """
        Export captured packets to PCAP format.

        Args:
            packets: List of packet data
            filename: Output filename (auto-generated if None)

        Returns:
            Path to exported file
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for PCAP export")

        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"packets_{timestamp}.pcap"

        filepath = os.path.join(self.output_dir, filename)

        # Extract raw packets
        raw_packets = [pkt.get("packet") for pkt in packets if pkt.get("packet")]

        if raw_packets:
            wrpcap(filepath, raw_packets)

        return filepath

    def export_json(self, data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """
        Export data to JSON format.

        Args:
            data: Data to export
            filename: Output filename (auto-generated if None)

        Returns:
            Path to exported file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.json"

        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)

        return filepath

    def export_report(self, statistics: Dict[str, Any], threats: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
        """
        Export comprehensive analysis report.

        Args:
            statistics: Traffic statistics
            threats: Detected threats
            filename: Output filename (auto-generated if None)

        Returns:
            Path to exported file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.txt"

        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("NETWORK TRAFFIC ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")

            # Statistics section
            f.write("TRAFFIC STATISTICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Packets: {statistics.get('total_packets', 0)}\n")
            f.write(f"Total Bytes: {statistics.get('total_bytes', 0):,}\n")
            f.write(f"Average Packet Size: {statistics.get('average_packet_size', 0):.2f} bytes\n\n")

            # Protocol breakdown
            f.write("PROTOCOL BREAKDOWN\n")
            f.write("-" * 80 + "\n")
            protocols = statistics.get("protocols", {})
            for protocol, info in sorted(protocols.items()):
                f.write(f"{protocol:15} {info.get('count', 0):10} packets ({info.get('percentage', 0):.2f}%)\n")
            f.write("\n")

            # Top IPs
            f.write("TOP IP ADDRESSES\n")
            f.write("-" * 80 + "\n")
            for ip_info in statistics.get("top_ips", [])[:10]:
                f.write(f"{ip_info['ip']:20} {ip_info['total_bytes']:15,} bytes "
                       f"({ip_info['packets']:5} packets)\n")
            f.write("\n")

            # Top Ports
            f.write("TOP PORTS\n")
            f.write("-" * 80 + "\n")
            for port_info in statistics.get("top_ports", [])[:10]:
                f.write(f"Port {port_info['port']:5} ({port_info['service']:15}) "
                       f"{port_info['traffic_count']:10} connections\n")
            f.write("\n")

            # Top DNS Queries
            f.write("TOP DNS QUERIES\n")
            f.write("-" * 80 + "\n")
            for dns_info in statistics.get("top_dns_queries", [])[:10]:
                f.write(f"{dns_info['domain']:40} {dns_info['query_count']:5} queries\n")
            f.write("\n")

            # Threats section
            f.write("DETECTED THREATS\n")
            f.write("-" * 80 + "\n")
            if threats:
                for threat in threats:
                    f.write(f"[{threat.get('severity', 'UNKNOWN')}] {threat.get('type', 'Unknown').upper()}\n")
                    f.write(f"  Message: {threat.get('message', 'N/A')}\n")
                    f.write(f"  Time: {threat.get('timestamp', 'N/A')}\n")
                    if threat.get('source_ip'):
                        f.write(f"  Source: {threat.get('source_ip')}\n")
                    f.write("\n")
            else:
                f.write("No threats detected.\n\n")

            f.write("=" * 80 + "\n")

        return filepath

    def export_threat_report(self, threats: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
        """
        Export detected threats report.

        Args:
            threats: List of detected threats
            filename: Output filename (auto-generated if None)

        Returns:
            Path to exported file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threats_{timestamp}.csv"

        filepath = os.path.join(self.output_dir, filename)

        fieldnames = ["timestamp", "type", "severity", "source_ip", "target_ip", "message", "details"]

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for threat in threats:
                row = {
                    "timestamp": threat.get("timestamp", ""),
                    "type": threat.get("type", ""),
                    "severity": threat.get("severity", ""),
                    "source_ip": threat.get("source_ip", ""),
                    "target_ip": threat.get("target_ip", ""),
                    "message": threat.get("message", ""),
                    "details": json.dumps(threat),
                }
                writer.writerow(row)

        return filepath

    @staticmethod
    def get_file_size(filepath: str) -> str:
        """Get formatted file size."""
        size = os.path.getsize(filepath)
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"

    def list_exports(self) -> List[Dict[str, Any]]:
        """List all exported files."""
        files = []
        if os.path.exists(self.output_dir):
            for filename in os.listdir(self.output_dir):
                filepath = os.path.join(self.output_dir, filename)
                if os.path.isfile(filepath):
                    files.append({
                        "name": filename,
                        "size": self.get_file_size(filepath),
                        "modified": datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat(),
                    })
        return sorted(files, key=lambda x: x["modified"], reverse=True)
