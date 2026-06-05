"""
Protocol Parser Module
Decodes and extracts information from network protocols.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime

try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, ARP, ICMP, Raw, Ether, IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class ProtocolParser:
    """Parses and decodes network protocols."""

    def __init__(self):
        """Initialize protocol parser."""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required")

    def parse(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a captured packet.

        Args:
            packet_data: Dictionary containing packet and timestamp

        Returns:
            Dictionary with parsed packet information
        """
        packet = packet_data.get("packet")
        timestamp = packet_data.get("timestamp", datetime.now())

        if not packet:
            return {"error": "No packet data"}

        parsed = {
            "timestamp": timestamp.isoformat(),
            "size": len(packet),
            "layers": [],
            "protocols": [],
        }

        # Parse each layer
        self._parse_ethernet(packet, parsed)
        self._parse_ip(packet, parsed)
        self._parse_transport(packet, parsed)
        self._parse_application(packet, parsed)

        return parsed

    def _parse_ethernet(self, packet, parsed: Dict[str, Any]):
        """Parse Ethernet layer."""
        try:
            from scapy.all import Ether
            if Ether in packet:
                eth = packet[Ether]
                parsed["layers"].append("Ethernet")
                parsed["protocols"].append("Ethernet")
                parsed["eth_src"] = eth.src
                parsed["eth_dst"] = eth.dst
                parsed["eth_type"] = eth.type
        except:
            pass

    def _parse_ip(self, packet, parsed: Dict[str, Any]):
        """Parse IP layer."""
        try:
            if IP in packet:
                ip = packet[IP]
                parsed["layers"].append("IP")
                parsed["protocols"].append("IPv4")
                parsed["src_ip"] = ip.src
                parsed["dst_ip"] = ip.dst
                parsed["ttl"] = ip.ttl
                parsed["ip_id"] = ip.id
                parsed["flags"] = ip.flags
                return

            if IPv6 in packet:
                ipv6 = packet[IPv6]
                parsed["layers"].append("IPv6")
                parsed["protocols"].append("IPv6")
                parsed["src_ip"] = ipv6.src
                parsed["dst_ip"] = ipv6.dst
                parsed["hop_limit"] = ipv6.hlim
        except:
            pass

    def _parse_transport(self, packet, parsed: Dict[str, Any]):
        """Parse TCP/UDP layer."""
        try:
            if TCP in packet:
                tcp = packet[TCP]
                parsed["layers"].append("TCP")
                parsed["protocols"].append("TCP")
                parsed["src_port"] = tcp.sport
                parsed["dst_port"] = tcp.dport
                parsed["seq"] = tcp.seq
                parsed["ack"] = tcp.ack
                parsed["flags"] = self._parse_tcp_flags(tcp.flags)
                return

            if UDP in packet:
                udp = packet[UDP]
                parsed["layers"].append("UDP")
                parsed["protocols"].append("UDP")
                parsed["src_port"] = udp.sport
                parsed["dst_port"] = udp.dport
                parsed["length"] = udp.len
                return

            if ICMP in packet:
                icmp = packet[ICMP]
                parsed["layers"].append("ICMP")
                parsed["protocols"].append("ICMP")
                parsed["icmp_type"] = icmp.type
                parsed["icmp_code"] = icmp.code
                return

            if ARP in packet:
                arp = packet[ARP]
                parsed["layers"].append("ARP")
                parsed["protocols"].append("ARP")
                parsed["arp_op"] = arp.op
                parsed["arp_psrc"] = arp.psrc
                parsed["arp_pdst"] = arp.pdst
                parsed["arp_hwsrc"] = arp.hwsrc
                parsed["arp_hwdst"] = arp.hwdst
        except:
            pass

    def _parse_application(self, packet, parsed: Dict[str, Any]):
        """Parse application layer protocols."""
        try:
            # DNS
            if DNS in packet:
                dns = packet[DNS]
                parsed["protocols"].append("DNS")
                parsed["dns_info"] = self._extract_dns_info(dns)

            # HTTP detection (basic)
            if Raw in packet:
                raw_load = packet[Raw].load
                if isinstance(raw_load, bytes):
                    try:
                        decoded = raw_load.decode("utf-8", errors="ignore")
                        if "HTTP/" in decoded or "GET " in decoded or "POST " in decoded:
                            parsed["protocols"].append("HTTP")
                            parsed["http_raw"] = decoded[:200]
                    except:
                        pass
        except:
            pass

    @staticmethod
    def _extract_dns_info(dns) -> Dict[str, Any]:
        """Extract DNS query/response information."""
        dns_info = {
            "qd_count": dns.qdcount,
            "an_count": dns.ancount,
            "queries": [],
            "answers": [],
        }

        try:
            # Extract queries
            if dns.qdcount > 0 and DNSQR in dns:
                for i in range(dns.qdcount):
                    dns_qr = dns[DNSQR](i)
                    dns_info["queries"].append({
                        "name": str(dns_qr.qname),
                        "type": dns_qr.qtype,
                    })

            # Extract answers
            if dns.ancount > 0 and DNSRR in dns:
                for i in range(dns.ancount):
                    dns_rr = dns[DNSRR](i)
                    dns_info["answers"].append({
                        "name": str(dns_rr.rrname),
                        "type": dns_rr.type,
                        "data": str(dns_rr.rdata),
                    })
        except:
            pass

        return dns_info

    @staticmethod
    def _parse_tcp_flags(flags: int) -> List[str]:
        """Parse TCP flags into readable format."""
        flag_names = []
        if flags & 0x01:
            flag_names.append("FIN")
        if flags & 0x02:
            flag_names.append("SYN")
        if flags & 0x04:
            flag_names.append("RST")
        if flags & 0x08:
            flag_names.append("PSH")
        if flags & 0x10:
            flag_names.append("ACK")
        if flags & 0x20:
            flag_names.append("URG")
        return flag_names

    def get_summary(self, parsed: Dict[str, Any]) -> str:
        """Get a human-readable summary of the packet."""
        src = parsed.get("src_ip", "Unknown")
        dst = parsed.get("dst_ip", "Unknown")
        src_port = parsed.get("src_port", "")
        dst_port = parsed.get("dst_port", "")
        protocols = " / ".join(parsed.get("protocols", ["Unknown"]))

        port_info = ""
        if src_port and dst_port:
            port_info = f":{src_port} → :{dst_port}"

        return f"{src}{port_info} → {dst} [{protocols}]"
