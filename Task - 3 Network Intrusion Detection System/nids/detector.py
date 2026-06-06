# *Author: Avinash K*
"""Network Intrusion Detection System detector.
Implements simple detection rules based on configuration.
"""
import time
import threading
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, ICMP
from .config_loader import load_config
from .logger import log_alert

# Load configuration once at startup
CONFIG = load_config()

# Helper structures for sliding windows
class SlidingWindowCounter:
    def __init__(self, time_window):
        self.time_window = time_window
        self.events = deque()  # (timestamp, key)
        self.counts = defaultdict(int)
        self.lock = threading.Lock()

    def add(self, key):
        now = time.time()
        with self.lock:
            self.events.append((now, key))
            self.counts[key] += 1
            self._evict()

    def get_count(self, key):
        with self.lock:
            self._evict()
            return self.counts.get(key, 0)

    def _evict(self):
        cutoff = time.time() - self.time_window
        while self.events and self.events[0][0] < cutoff:
            ts, key = self.events.popleft()
            self.counts[key] -= 1
            if self.counts[key] <= 0:
                del self.counts[key]

# Instantiate counters per detection rule
port_scan_counter = SlidingWindowCounter(CONFIG['detection']['port_scan']['time_window'])
brute_force_counter = SlidingWindowCounter(CONFIG['detection']['brute_force']['time_window'])
failed_conn_counter = SlidingWindowCounter(CONFIG['detection']['failed_connections']['time_window'])
syn_flood_counter = SlidingWindowCounter(CONFIG['detection']['syn_flood']['time_window'])

# State for tracking distinct ports per source (for port scan)
source_ports = defaultdict(set)

def detect_packet(pkt):
    if IP not in pkt:
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    # Port Scan detection (TCP SYN to many ports)
    if TCP in pkt and pkt[TCP].flags == 'S':
        source_ports[src].add(pkt[TCP].dport)
        # add to counter for distinct ports
        port_scan_counter.add(src)
        if len(source_ports[src]) >= CONFIG['detection']['port_scan']['port_threshold']:
            alert = f"Port scan detected from {src} (>{CONFIG['detection']['port_scan']['port_threshold']} ports)"
            log_alert('Port Scan', alert)
            # Reset to avoid spamming
            source_ports[src].clear()
    # Brute Force detection (multiple connection attempts to same dst port)
    if TCP in pkt and pkt[TCP].flags == 'S':
        key = (src, pkt[TCP].dport)
        brute_force_counter.add(key)
        if brute_force_counter.get_count(key) >= CONFIG['detection']['brute_force']['attempt_threshold']:
            alert = f"Brute force attempts from {src} to port {pkt[TCP].dport}"
            log_alert('Brute Force', alert)
    # Suspicious ICMP detection
    if ICMP in pkt:
        if len(pkt[ICMP].payload) > CONFIG['detection']['icmp_suspicious']['max_payload_size']:
            alert = f"Large ICMP packet from {src} ({len(pkt[ICMP].payload)} bytes)"
            log_alert('ICMP Suspicious', alert)
    # Failed connections (RST packets)
    if TCP in pkt and pkt[TCP].flags == 'R':
        key = src
        failed_conn_counter.add(key)
        if failed_conn_counter.get_count(key) >= CONFIG['detection']['failed_connections']['rst_threshold']:
            alert = f"High number of RST packets from {src}"
            log_alert('Failed Connections', alert)
    # SYN Flood detection (many SYNs overall)
    if TCP in pkt and pkt[TCP].flags == 'S':
        syn_flood_counter.add('global')
        if syn_flood_counter.get_count('global') >= CONFIG['detection']['syn_flood']['syn_threshold']:
            alert = f"Potential SYN flood (>{CONFIG['detection']['syn_flood']['syn_threshold']} SYNs)"
            log_alert('SYN Flood', alert)

def start_sniff(interface=None):
    """Start sniffing packets in a background thread."""
    sniff_thread = threading.Thread(target=sniff, kwargs={'prn': detect_packet, 'store': False, 'iface': interface}, daemon=True)
    sniff_thread.start()
    return sniff_thread
