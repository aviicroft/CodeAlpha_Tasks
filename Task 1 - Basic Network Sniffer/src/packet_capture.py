"""
Packet Capture Module
Handles live network packet capture using Scapy.
"""

import threading
import time
from collections import deque
from datetime import datetime
from typing import List, Optional, Dict, Any

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, ARP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketCapture:
    """Manages live network packet capture."""

    def __init__(self, interface: Optional[str] = None, max_packets: int = 10000, timeout: int = 300):
        """
        Initialize packet capture.

        Args:
            interface: Network interface to capture on (None for auto-detect)
            max_packets: Maximum number of packets to store
            timeout: Capture timeout in seconds
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required. Install it with: pip install scapy")

        self.interface = interface
        self.max_packets = max_packets
        self.timeout = timeout
        self.packets = deque(maxlen=max_packets)
        self.is_capturing = False
        self.capture_thread: Optional[threading.Thread] = None
        self.packet_count = 0
        self.start_time: Optional[datetime] = None

    def start(self) -> bool:
        """Start packet capture in a background thread."""
        if self.is_capturing:
            return False

        self.is_capturing = True
        self.packet_count = 0
        self.start_time = datetime.now()
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        return True

    def stop(self) -> bool:
        """Stop packet capture."""
        if not self.is_capturing:
            return False

        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        return True

    def _capture_loop(self):
        """Internal loop for capturing packets."""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=False,
                timeout=self.timeout,
                stop_filter=lambda x: not self.is_capturing,
            )
        except Exception as e:
            print(f"Error during capture: {e}")
            self.is_capturing = False

    def _packet_callback(self, packet):
        """Callback for each captured packet."""
        if self.is_capturing:
            packet_data = {
                "timestamp": datetime.now(),
                "packet": packet,
                "size": len(packet),
                "raw": bytes(packet),
            }
            self.packets.append(packet_data)
            self.packet_count += 1

    def get_packets(self) -> List[Dict[str, Any]]:
        """Get all captured packets."""
        return list(self.packets)

    def get_packets_since(self, timestamp: datetime) -> List[Dict[str, Any]]:
        """Get packets captured since a specific timestamp."""
        return [
            pkt for pkt in self.packets
            if pkt["timestamp"] >= timestamp
        ]

    def clear_packets(self):
        """Clear all captured packets."""
        self.packets.clear()
        self.packet_count = 0

    def get_statistics(self) -> Dict[str, Any]:
        """Get capture statistics."""
        return {
            "total_packets": self.packet_count,
            "stored_packets": len(self.packets),
            "is_capturing": self.is_capturing,
            "start_time": self.start_time,
            "elapsed_seconds": (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
        }

    @staticmethod
    def get_interfaces() -> List[str]:
        """Get available network interfaces."""
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except:
            return []
