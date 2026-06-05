"""
Traffic Analyzer Module
Analyzes and generates statistics from captured network traffic.
"""

from typing import Dict, Any, List, Optional
from collections import defaultdict


class TrafficAnalyzer:
    """Analyzes network traffic patterns."""

    def __init__(self):
        """Initialize traffic analyzer."""
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {"sent_bytes": 0, "recv_bytes": 0, "packets": 0})
        self.port_stats = defaultdict(int)
        self.dns_queries = defaultdict(int)
        self.total_bytes = 0
        self.total_packets = 0

    def analyze_packet(self, parsed_packet: Dict[str, Any]):
        """
        Analyze a single packet and update statistics.

        Args:
            parsed_packet: Parsed packet information
        """
        # Protocol statistics
        for protocol in parsed_packet.get("protocols", []):
            self.protocol_stats[protocol] += 1

        # IP statistics
        src_ip = parsed_packet.get("src_ip")
        dst_ip = parsed_packet.get("dst_ip")
        size = parsed_packet.get("size", 0)

        if src_ip:
            self.ip_stats[src_ip]["sent_bytes"] += size
            self.ip_stats[src_ip]["packets"] += 1

        if dst_ip:
            self.ip_stats[dst_ip]["recv_bytes"] += size
            self.ip_stats[dst_ip]["packets"] += 1

        # Port statistics
        src_port = parsed_packet.get("src_port")
        dst_port = parsed_packet.get("dst_port")

        if src_port:
            self.port_stats[src_port] += 1
        if dst_port:
            self.port_stats[dst_port] += 1

        # DNS query statistics
        dns_info = parsed_packet.get("dns_info")
        if dns_info:
            for query in dns_info.get("queries", []):
                domain = query.get("name", "unknown")
                self.dns_queries[domain] += 1

        # Totals
        self.total_bytes += size
        self.total_packets += 1

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive traffic statistics."""
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "average_packet_size": self.total_bytes / self.total_packets if self.total_packets > 0 else 0,
            "protocols": self._get_protocol_stats(),
            "top_ips": self._get_top_ips(),
            "top_ports": self._get_top_ports(),
            "top_dns_queries": self._get_top_dns_queries(),
        }

    def _get_protocol_stats(self) -> Dict[str, Any]:
        """Get protocol statistics."""
        if not self.protocol_stats:
            return {}

        total = sum(self.protocol_stats.values())
        return {
            protocol: {
                "count": count,
                "percentage": (count / total * 100) if total > 0 else 0,
            }
            for protocol, count in self.protocol_stats.items()
        }

    def _get_top_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top communicating IP addresses."""
        sorted_ips = sorted(
            self.ip_stats.items(),
            key=lambda x: x[1]["sent_bytes"] + x[1]["recv_bytes"],
            reverse=True
        )

        return [
            {
                "ip": ip,
                "sent_bytes": stats["sent_bytes"],
                "recv_bytes": stats["recv_bytes"],
                "total_bytes": stats["sent_bytes"] + stats["recv_bytes"],
                "packets": stats["packets"],
            }
            for ip, stats in sorted_ips[:limit]
        ]

    def _get_top_ports(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top used ports."""
        sorted_ports = sorted(
            self.port_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [
            {
                "port": port,
                "traffic_count": count,
                "service": self._get_common_service(port),
            }
            for port, count in sorted_ports[:limit]
        ]

    def _get_top_dns_queries(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top DNS queries."""
        sorted_queries = sorted(
            self.dns_queries.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [
            {
                "domain": domain,
                "query_count": count,
            }
            for domain, count in sorted_queries[:limit]
        ]

    @staticmethod
    def _get_common_service(port: int) -> str:
        """Get common service name for a port."""
        common_ports = {
            20: "FTP-DATA",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            67: "DHCP",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTP",
            587: "SMTP",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-ALT",
            8443: "HTTPS-ALT",
        }
        return common_ports.get(port, "Unknown")

    def get_protocol_breakdown(self) -> Dict[str, int]:
        """Get protocol breakdown."""
        return dict(self.protocol_stats)

    def get_ip_conversation_matrix(self) -> List[Dict[str, Any]]:
        """Get IP conversation summary."""
        conversations = []
        for ip, stats in self.ip_stats.items():
            conversations.append({
                "ip": ip,
                "sent_bytes": stats["sent_bytes"],
                "recv_bytes": stats["recv_bytes"],
                "total_packets": stats["packets"],
            })
        return sorted(conversations, key=lambda x: x["sent_bytes"] + x["recv_bytes"], reverse=True)

    def filter_by_protocol(self, protocol: str) -> Dict[str, int]:
        """Filter statistics by protocol."""
        if protocol in self.protocol_stats:
            return {protocol: self.protocol_stats[protocol]}
        return {}

    def filter_by_ip(self, ip_address: str) -> Dict[str, Any]:
        """Get statistics for a specific IP address."""
        if ip_address in self.ip_stats:
            return {
                "ip": ip_address,
                **self.ip_stats[ip_address],
            }
        return {}

    def clear_statistics(self):
        """Clear all statistics."""
        self.protocol_stats.clear()
        self.ip_stats.clear()
        self.port_stats.clear()
        self.dns_queries.clear()
        self.total_bytes = 0
        self.total_packets = 0
