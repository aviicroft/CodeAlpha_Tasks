#!/usr/bin/env python3
"""
Basic Network Sniffer
====================

A lightweight command‑line packet sniffer built with **Scapy**.
It captures live traffic, prints a concise summary to the console,
and records every packet in a CSV log file.

Features
--------
- Live capture of Ethernet frames on any interface
- Optional filtering: TCP, UDP, ICMP (or “all”)
- Displays: source IP, destination IP, protocol, size, payload (hex)
- CSV logging of every captured packet (append‑only)
- Graceful handling of permission errors and keyboard interrupt
- Clean, typed argparse‑based CLI

Prerequisites
-------------
- Python 3.7+ (type hints are used)
- Scapy (`pip install scapy`) – installed via requirements.txt
- Administrator / root privileges to open a raw socket on the selected interface
  (on Windows run the script from an elevated PowerShell/Command Prompt,
  on Linux/macOS with `sudo`).

Author  : Avinash (Cybersecurity intern)
License : MIT (see LICENSE file)
"""

import argparse
import csv
import datetime
import sys
from pathlib import Path

# Scapy import – wrapped in a try/except so we can give a clear message
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    # Force Scapy to use a pure L3 socket (no WinPcap/Npcap).
    # This works on Windows without installing a pcap driver, but captures
    # only IP‑level traffic (no Ethernet‑only frames like ARP).
    from scapy.config import conf
    conf.use_pcap = False
except ImportError as exc:  # pragma: no cover
    sys.exit(
        "Scapy is not installed. Please run:\n"
        "    pip install -r requirements.txt\n"
        f"Original error: {exc}"
    )


# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def build_filter(protocol: str) -> str:
    """
    Convert the user‑friendly protocol name into a BPF filter string.

    Args:
        protocol: 'tcp', 'udp', 'icmp', or 'all'.

    Returns:
        BPF filter string understood by Scapy/sniff().
    """
    if protocol == "all":
        return ""  # No filter – capture everything
    return protocol.lower()  # Scapy passes the string directly to libpcap


def format_payload(packet) -> str:
    """
    Return payload as a hex string, truncated to a reasonable length.
    Empty payload returns an empty string.
    """
    if Raw in packet:
        # Show only first 32 bytes to keep the console tidy
        raw_bytes = bytes(packet[Raw].load)[:32]
        return raw_bytes.hex()
    return ""


def log_packet(csv_path: Path, row: list) -> None:
    """
    Append a row to the CSV log file. Creates the file with a header if it
    does not yet exist.

    Args:
        csv_path: Path object pointing to the CSV file.
        row: List of column values matching the CSV header.
    """
    file_exists = csv_path.is_file()
    with csv_path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # Write header only once
        if not file_exists:
            writer.writerow(
                [
                    "timestamp",
                    "src_ip",
                    "dst_ip",
                    "protocol",
                    "size_bytes",
                    "payload_hex",
                ]
            )
        writer.writerow(row)


def packet_handler(packet, args) -> None:
    """
    Callback invoked by Scapy for every captured packet.

    It extracts the required fields, prints a short summary,
    and appends the data to the CSV log.

    Args:
        packet: Scapy packet object.
        args:   Namespace produced by argparse (contains csv_path, etc.).
    """
    # We only care about IP packets – ignore non‑IP frames.
    if IP not in packet:
        return

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto_num = ip_layer.proto
    size = len(packet)

    # Resolve protocol name – limited to the three we filter for.
    if TCP in packet:
        proto_name = "TCP"
    elif UDP in packet:
        proto_name = "UDP"
    elif ICMP in packet:
        proto_name = "ICMP"
    else:
        # Unknown or other protocol; show the numeric ID
        proto_name = f"IP({proto_num})"

    payload_hex = format_payload(packet)

    # ---- Console output -------------------------------------------------
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(
        f"[{timestamp}] {src_ip} → {dst_ip} | {proto_name:<5} | "
        f"{size:4} B | {payload_hex}"
    )

    # ---- CSV logging ----------------------------------------------------
    log_row = [
        datetime.datetime.now().isoformat(),
        src_ip,
        dst_ip,
        proto_name,
        size,
        payload_hex,
    ]
    log_packet(args.csv_path, log_row)


# ----------------------------------------------------------------------
# Main entry point
# ----------------------------------------------------------------------
def parse_arguments() -> argparse.Namespace:
    """
    Define and parse command‑line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer – capture live packets with Scapy",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Network interface to sniff on (default: Scapy's default)",
    )
    parser.add_argument(
        "-p",
        "--protocol",
        choices=["all", "tcp", "udp", "icmp"],
        default="all",
        help="Packet filter – capture only the selected protocol",
    )
    parser.add_argument(
        "-c",
        "--csv",
        type=str,
        default="logs/captured_packets.csv",
        help="Path to CSV file where packets are logged",
    )
    parser.add_argument(
        "-t",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Stop sniffing after N seconds (0 = no timeout)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    # Resolve CSV path and ensure its parent directory exists
    args.csv_path = Path(args.csv).expanduser().resolve()
    args.csv_path.parent.mkdir(parents=True, exist_ok=True)

    bpf_filter = build_filter(args.protocol)

    print("\n=== Basic Network Sniffer ===")
    print(f"Interface   : {args.interface or '(default)'}")
    print(f"Protocol    : {args.protocol.upper()}")
    print(f"CSV Log     : {args.csv_path}")
    if args.count:
        print(f"Packet limit: {args.count}")
    if args.timeout:
        print(f"Timeout     : {args.timeout}s")
    print("Press Ctrl+C to stop.\n")

    # ------------------------------------------------------------------
    # Start the sniffing loop – wrapped to catch permission errors and Ctrl+C
    # ------------------------------------------------------------------
    try:
        sniff(
            iface=args.interface,
            filter=bpf_filter,
            prn=lambda pkt: packet_handler(pkt, args),
            count=args.count if args.count > 0 else 0,
            timeout=args.timeout if args.timeout > 0 else None,
        )
    except PermissionError as perm_err:
        # Most OSes require admin/root to open a raw socket
        sys.exit(
            f"\n[ERROR] Permission denied while opening interface '{args.interface}'.\n"
            "Run the script with elevated privileges (e.g., sudo on Linux/macOS "
            "or an Administrator command prompt on Windows)."
        )
    except KeyboardInterrupt:
        print("\n[INFO] Sniffing stopped by user (Ctrl+C).")
    except Exception as e:  # pragma: no cover
        sys.exit(f"\n[ERROR] Unexpected error: {e}")

    print("\n[INFO] Capture finished. Logged packets can be found in:")
    print(f"       {args.csv_path}\n")


if __name__ == "__main__":
    main()
