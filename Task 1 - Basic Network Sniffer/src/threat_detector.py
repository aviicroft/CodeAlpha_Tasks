"""
Threat Detector Module
Detects suspicious network activities and potential threats.
"""

from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime, timedelta


class ThreatDetector:
    """Detects suspicious network activities."""

    def __init__(self):
        """Initialize threat detector."""
        self.port_scan_threshold = 20  # ports in scan_window
        self.port_scan_window = 30  # seconds
        self.dns_flood_threshold = 50  # queries in dns_window
        self.dns_flood_window = 10  # seconds
        self.arp_spoofing_threshold = 5  # duplicate responses

        # Tracking data structures
        self.connection_attempts = defaultdict(list)  # src_ip -> list of (dst_ip, port, timestamp)
        self.dns_queries = defaultdict(list)  # src_ip -> list of (query, timestamp)
        self.arp_responses = defaultdict(lambda: defaultdict(int))  # ip -> {mac: count}
        self.threats = []

    def analyze(self, parsed_packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze a packet for threats.

        Args:
            parsed_packet: Parsed packet information

        Returns:
            List of detected threats (if any)
        """
        threats = []
        timestamp = datetime.fromisoformat(parsed_packet.get("timestamp", datetime.now().isoformat()))

        # Check for port scanning
        port_scan_threat = self._check_port_scanning(parsed_packet, timestamp)
        if port_scan_threat:
            threats.append(port_scan_threat)

        # Check for DNS flooding
        dns_flood_threat = self._check_dns_flooding(parsed_packet, timestamp)
        if dns_flood_threat:
            threats.append(dns_flood_threat)

        # Check for ARP spoofing
        arp_spoof_threat = self._check_arp_spoofing(parsed_packet, timestamp)
        if arp_spoof_threat:
            threats.append(arp_spoof_threat)

        return threats

    def _check_port_scanning(self, packet: Dict[str, Any], timestamp: datetime) -> Optional[Dict[str, Any]]:
        """
        Detect port scanning activity.

        A scan is detected when a single host connects to many different ports in a short time.
        """
        if "TCP" not in packet.get("protocols", []):
            return None

        src_ip = packet.get("src_ip")
        dst_port = packet.get("dst_port")

        if not src_ip or dst_port is None:
            return None

        dst_ip = packet.get("dst_ip")

        # Add connection attempt
        self.connection_attempts[src_ip].append({
            "dst_ip": dst_ip,
            "port": dst_port,
            "timestamp": timestamp,
        })

        # Clean old entries
        cutoff_time = timestamp - timedelta(seconds=self.port_scan_window)
        self.connection_attempts[src_ip] = [
            conn for conn in self.connection_attempts[src_ip]
            if conn["timestamp"] > cutoff_time
        ]

        # Check if threshold exceeded
        unique_ports = len(set(conn["port"] for conn in self.connection_attempts[src_ip]))

        if unique_ports >= self.port_scan_threshold:
            return {
                "type": "port_scanning",
                "severity": "HIGH",
                "source_ip": src_ip,
                "ports_scanned": unique_ports,
                "timestamp": timestamp.isoformat(),
                "message": f"Potential port scan from {src_ip}: {unique_ports} ports in {self.port_scan_window}s",
            }

        return None

    def _check_dns_flooding(self, packet: Dict[str, Any], timestamp: datetime) -> Optional[Dict[str, Any]]:
        """
        Detect DNS flooding attacks.

        A flood is detected when a single host makes many DNS queries in a short time.
        """
        if "DNS" not in packet.get("protocols", []):
            return None

        src_ip = packet.get("src_ip")
        if not src_ip:
            return None

        dns_info = packet.get("dns_info", {})
        queries = dns_info.get("queries", [])

        if not queries:
            return None

        # Add DNS queries
        for query in queries:
            self.dns_queries[src_ip].append({
                "query": query.get("name"),
                "timestamp": timestamp,
            })

        # Clean old entries
        cutoff_time = timestamp - timedelta(seconds=self.dns_flood_window)
        self.dns_queries[src_ip] = [
            q for q in self.dns_queries[src_ip]
            if q["timestamp"] > cutoff_time
        ]

        # Check if threshold exceeded
        query_count = len(self.dns_queries[src_ip])

        if query_count >= self.dns_flood_threshold:
            return {
                "type": "dns_flooding",
                "severity": "MEDIUM",
                "source_ip": src_ip,
                "query_count": query_count,
                "timestamp": timestamp.isoformat(),
                "message": f"Potential DNS flood from {src_ip}: {query_count} queries in {self.dns_flood_window}s",
            }

        return None

    def _check_arp_spoofing(self, packet: Dict[str, Any], timestamp: datetime) -> Optional[Dict[str, Any]]:
        """
        Detect ARP spoofing attempts.

        ARP spoofing is detected when multiple MAC addresses claim to have the same IP.
        """
        if "ARP" not in packet.get("protocols", []):
            return None

        ip_addr = packet.get("arp_psrc")
        mac_addr = packet.get("arp_hwsrc")

        if not ip_addr or not mac_addr:
            return None

        # Track MAC addresses per IP
        self.arp_responses[ip_addr][mac_addr] += 1

        # Clean old entries (keep only recent data)
        if len(self.arp_responses[ip_addr]) > self.arp_spoofing_threshold:
            return {
                "type": "arp_spoofing",
                "severity": "HIGH",
                "target_ip": ip_addr,
                "mac_addresses": len(self.arp_responses[ip_addr]),
                "timestamp": timestamp.isoformat(),
                "message": f"Potential ARP spoofing detected for {ip_addr}: {len(self.arp_responses[ip_addr])} different MAC addresses",
            }

        return None

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of detected threats."""
        threat_counts = defaultdict(int)
        for threat in self.threats:
            threat_counts[threat["type"]] += 1

        return {
            "total_threats": len(self.threats),
            "threat_types": dict(threat_counts),
            "recent_threats": self.threats[-10:],  # Last 10 threats
        }

    def clear_threats(self):
        """Clear threat history."""
        self.threats.clear()
        self.connection_attempts.clear()
        self.dns_queries.clear()
        self.arp_responses.clear()
