"""
Advanced Network Traffic Analyzer - Main Entry Point
"""

import sys
import os
import argparse
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from packet_capture import PacketCapture
from protocol_parser import ProtocolParser
from threat_detector import ThreatDetector
from traffic_analyzer import TrafficAnalyzer
from data_exporter import DataExporter


def cli_mode():
    """Run in command-line mode."""
    print("=" * 80)
    print("Advanced Network Traffic Analyzer - CLI Mode")
    print("=" * 80)
    print()

    # Initialize components
    capture = PacketCapture()
    parser = ProtocolParser()
    detector = ThreatDetector()
    analyzer = TrafficAnalyzer()
    exporter = DataExporter()

    # Check if capturing is possible
    interfaces = capture.get_interfaces()
    if not interfaces:
        print("ERROR: No network interfaces found!")
        print("Please ensure you have:")
        print("  - Windows: Npcap installed (https://npcap.com/)")
        print("  - Linux/macOS: libpcap installed")
        return 1

    print(f"Available interfaces: {', '.join(interfaces)}")
    print()

    # Start capture
    print("Starting packet capture...")
    if capture.start():
        print("✓ Capture started")
    else:
        print("✗ Failed to start capture")
        return 1

    # Simple monitor
    try:
        print("\nCapturing packets (Press Ctrl+C to stop)...\n")
        packet_count = 0
        while True:
            packets = capture.get_packets()
            new_count = len(packets)

            if new_count > packet_count:
                print(f"\r[{datetime.now().strftime('%H:%M:%S')}] Captured {new_count} packets", end="")
                packet_count = new_count

    except KeyboardInterrupt:
        print("\n\nStopping capture...")
        capture.stop()

    # Generate report
    print("\nGenerating report...")
    for packet_data in capture.get_packets():
        parsed = parser.parse(packet_data)
        threats = detector.analyze(parsed)
        analyzer.analyze_packet(parsed)

    stats = analyzer.get_statistics()
    threats = detector.threats

    filepath = exporter.export_report(stats, threats, "network_analysis.txt")
    print(f"✓ Report generated: {filepath}")

    return 0


def gui_mode():
    """Run in GUI mode."""
    try:
        from gui import main
        main()
    except ImportError as e:
        print(f"ERROR: {e}")
        print("GUI requires Tkinter. Please install it:")
        print("  Windows: Included with Python")
        print("  Linux: sudo apt-get install python3-tk")
        print("  macOS: brew install python-tk")
        return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Advanced Network Traffic Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                  # Launch GUI
  python main.py --cli            # Launch CLI mode
  python main.py --help           # Show this help
        """
    )

    parser.add_argument("--cli", action="store_true", help="Run in CLI mode")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0.0")

    args = parser.parse_args()

    if args.cli:
        return cli_mode()
    else:
        return gui_mode()


if __name__ == "__main__":
    sys.exit(main())
