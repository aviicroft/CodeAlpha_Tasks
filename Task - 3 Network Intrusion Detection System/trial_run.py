# *Author: Avinash K*
"""Trial run for the NIDS detector.
Starts sniffing, generates synthetic traffic to trigger each detection rule,
waits briefly, then writes a concise markdown report of the alerts.
"""
import time
import threading
from pathlib import Path
import csv

from nids.detector import start_sniff
from nids.logger import log_alert

# Scapy is used for generating test packets
from scapy.all import IP, TCP, ICMP, send

def generate_traffic():
    # Port scan: send SYN to 25 distinct ports on localhost
    for port in range(1000, 1025):
        pkt = IP(dst="127.0.0.1")/TCP(dport=port, flags='S')
        send(pkt, verbose=False)
    # Brute force: repeat SYN to same port many times
    for _ in range(12):
        pkt = IP(dst="127.0.0.1")/TCP(dport=22, flags='S')
        send(pkt, verbose=False)
    # Large ICMP payload
    pkt = IP(dst="127.0.0.1")/ICMP()/('X'*1500)
    send(pkt, verbose=False)
    # SYN flood: many SYN packets to a single port
    for _ in range(110):
        pkt = IP(dst="127.0.0.1")/TCP(dport=80, flags='S')
        send(pkt, verbose=False)
    # Failed connections (RST) – send RST packets
    for _ in range(20):
        pkt = IP(dst="127.0.0.1")/TCP(dport=80, flags='R')
        send(pkt, verbose=False)

def main():
    # Start sniffing in background
    start_sniff()
    # Give sniff thread a moment to be ready
    time.sleep(1)
    # Generate synthetic traffic
    generate_traffic()
    # Allow detector to process packets
    time.sleep(5)
    # Read alerts CSV and produce markdown report
    csv_path = Path(__file__).parent / "logs" / "alerts.csv"
    alerts = []
    if csv_path.exists():
        with open(csv_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            alerts = list(reader)
    report_path = Path(__file__).parent / "trial_result.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("# *Author: Avinash K*\n\n")
        f.write("## NIDS Trial Run Result\n\n")
        f.write(f"Total alerts generated: {len(alerts)}\n\n")
        for i, a in enumerate(alerts, 1):
            f.write(f"{i}. **{a['category']}** – {a['message']} (⏰ {a['timestamp']})\n")
    print("Trial completed. Report written to", report_path)

if __name__ == "__main__":
    main()
