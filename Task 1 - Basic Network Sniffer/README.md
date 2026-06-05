# Advanced Network Traffic Analyzer

## Overview
A comprehensive Python-based network traffic analysis tool designed for cybersecurity professionals and network administrators. This application captures live network packets, decodes multiple protocols, and provides advanced threat detection capabilities with a modern GUI interface.

**Difficulty Level:** Intermediate

## Key Features

### Core Features
- **Live Packet Capture:** Capture network packets in real-time using Scapy
- **Protocol Decoding:** Support for Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, and HTTP protocols
- **Detailed Packet Information:** Display timestamps, source/destination IPs, ports, protocol types, and packet lengths
- **Protocol Extraction:** Automatically extract DNS queries and HTTP request information

### Advanced Features
- **Protocol Filtering:** Filter captured traffic by protocol type
- **IP-based Search:** Search packets by source or destination IP address
- **PCAP Export:** Save captured traffic to standard PCAP format files
- **Statistics Generation:** Generate comprehensive traffic statistics
- **Threat Detection:** 
  - Port scanning detection
  - ARP spoofing detection
  - DNS flooding detection
- **Report Generation:** Export analysis reports in CSV and text formats

### User Interface
- **Modern GUI:** Built with Tkinter/CustomTkinter for cross-platform compatibility
- **Live Dashboard:** Real-time packet monitoring with live statistics
- **Intuitive Controls:** Easy-to-use start/stop capture controls
- **Multi-tab Interface:** Organized tabs for different analysis functions

## Project Structure
```
AdvancedNetworkAnalyzer/
├── src/
│   ├── __init__.py
│   ├── packet_capture.py          # Packet capture engine
│   ├── protocol_parser.py          # Protocol decoding
│   ├── threat_detector.py          # Threat detection algorithms
│   ├── traffic_analyzer.py         # Traffic analysis engine
│   ├── data_exporter.py            # Export to CSV/PCAP
│   ├── gui.py                      # Tkinter GUI application
│   └── main.py                     # Entry point
├── docs/
│   ├── ARCHITECTURE.md             # Network architecture explanation
│   ├── INSTALLATION_GUIDE.md       # Installation instructions
│   ├── USAGE_GUIDE.md              # Advanced usage documentation
│   └── PROTOCOL_ANALYSIS.md        # Protocol analysis details
├── tests/
│   ├── __init__.py
│   └── test_main.py                # Comprehensive unit tests
├── output/                         # Export output directory
├── requirements.txt                # Python dependencies
├── setup.py                        # Package setup
└── README.md                       # This file
```

## Quick Start

### Prerequisites
- Python 3.8 or higher
- Administrator/root privileges (for packet capture)
- Npcap (Windows) or libpcap (Linux/macOS)

### Installation

**1. Install Dependencies:**
```bash
# Windows
pip install -r requirements.txt

# Linux/macOS
pip3 install -r requirements.txt
```

**2. Run Application:**
```bash
# Windows (as Administrator)
python src/main.py

# Linux/macOS (with sudo)
sudo python3 src/main.py
```

### First Run
1. Click "Start Capture" button
2. Application begins monitoring network traffic
3. Generate traffic by visiting websites, using applications
4. View packets in real-time table
5. Analyze statistics and threats in respective tabs
6. Export data as needed

## Detailed Documentation

### Installation
For detailed installation instructions including platform-specific setup:
👉 [INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md)

### Network Architecture & Protocols
For comprehensive protocol analysis and network architecture:
👉 [ARCHITECTURE.md](docs/ARCHITECTURE.md)

### Advanced Usage
For advanced features, analysis techniques, and troubleshooting:
👉 [USAGE_GUIDE.md](docs/USAGE_GUIDE.md)

## Core Components

### 1. Packet Capture Engine (`packet_capture.py`)
- **Function:** Captures live network packets from specified interface
- **Technology:** Uses Scapy library for raw packet access
- **Features:**
  - Multi-threaded capture
  - Circular buffer for efficient memory usage
  - Interface auto-detection
  - Configurable packet limits and timeouts

### 2. Protocol Parser (`protocol_parser.py`)
- **Function:** Decodes and extracts information from network protocols
- **Supported Protocols:**
  - Ethernet (Layer 2)
  - IPv4/IPv6 (Layer 3)
  - TCP/UDP (Layer 4)
  - DNS, HTTP (Layer 7)
  - ARP, ICMP (Network utilities)
- **Output:** Structured packet information with all relevant fields

### 3. Threat Detector (`threat_detector.py`)
- **Function:** Analyzes packets for suspicious patterns
- **Detection Algorithms:**
  - **Port Scanning:** Monitors for multiple connection attempts to different ports
  - **ARP Spoofing:** Tracks MAC/IP address mappings for inconsistencies
  - **DNS Flooding:** Detects abnormal DNS query rates
- **Output:** Severity-rated threat alerts with details

### 4. Traffic Analyzer (`traffic_analyzer.py`)
- **Function:** Generates comprehensive network statistics
- **Analysis Features:**
  - Protocol breakdown and percentages
  - Top communicating IP addresses
  - Most used ports and services
  - Popular DNS queries
  - Data volume analysis
- **Output:** Statistical summaries and rankings

### 5. Data Exporter (`data_exporter.py`)
- **Function:** Exports captured data in multiple formats
- **Export Formats:**
  - CSV: Tabular format for spreadsheet analysis
  - PCAP: Standard libpcap format for Wireshark
  - TXT: Human-readable reports
  - JSON: Structured data format
- **Use Cases:** Archival, further analysis, documentation

### 6. GUI Application (`gui.py`)
- **Framework:** Tkinter (fallback) / CustomTkinter (modern)
- **Interface Tabs:**
  - Packet Capture: Live traffic monitoring
  - Statistics: Traffic analysis dashboard
  - Threats: Detected security issues
  - Export: Data export and file management
- **Features:** Real-time updates, filtering, searching

## Advanced Features

### Protocol Filtering
```
Available Filters:
- All       (no filter)
- TCP       (Transmission Control Protocol)
- UDP       (User Datagram Protocol)
- DNS       (Domain Name System)
- HTTP      (HyperText Transfer Protocol)
- ARP       (Address Resolution Protocol)
- ICMP      (Internet Control Message Protocol)
```

### IP-Based Search
Find all packets from or to a specific IP address:
```
Search IP: 192.168.1.100
Results: All packets with this IP as source or destination
```

### Threat Detection
Real-time alerts for:
- **Port Scanning:** Source scans 20+ ports in 30 seconds
- **ARP Spoofing:** Single IP has 5+ different MAC addresses
- **DNS Flooding:** 50+ DNS queries in 10 seconds

### Statistics Generation
Comprehensive analysis including:
- Total packets and bytes
- Protocol distribution
- Top communicating hosts
- Active ports and services
- DNS query patterns

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 7+, Ubuntu 18+, macOS 10.12+ | Windows 10+, Ubuntu 20+, macOS 11+ |
| Python | 3.8 | 3.10+ |
| RAM | 2 GB | 4 GB+ |
| CPU | Dual-core 2 GHz | Quad-core 2.5 GHz+ |
| Storage | 100 MB | 500 MB |
| Privileges | Admin/Root | Admin/Root |

## Performance

### Typical Usage
- **Memory:** 50-150 MB
- **CPU:** 5-15% during capture
- **Network Impact:** Passive (no traffic generation)
- **Maximum Capture Rate:** 100,000 packets/second

### Optimization Tips
- Reduce packet storage limit for memory constraints
- Use protocol filters to reduce processing
- Clear packets periodically
- Disable unused threat detection features
- Close other applications if CPU-limited

## Troubleshooting

### "No network interfaces found"
**Windows:** Install Npcap from https://npcap.com/
**Linux/macOS:** Install libpcap: `sudo apt-get install libpcap-dev`

### "Permission denied" on Linux/macOS
```bash
# Option 1: Run with sudo
sudo python3 src/main.py

# Option 2: Set capabilities
sudo setcap cap_net_raw=ep /usr/bin/python3
```

### GUI doesn't appear
```bash
pip install customtkinter
# Linux may need:
sudo apt-get install python3-tk
```

### High CPU Usage
1. Reduce packet limit in settings
2. Use protocol filters
3. Clear packets regularly
4. Disable threat detection if not needed

See [USAGE_GUIDE.md](docs/USAGE_GUIDE.md#troubleshooting) for more solutions.

## Testing

Run the comprehensive test suite:
```bash
python -m pytest tests/
# Or directly:
python tests/test_main.py
```

### Test Coverage
- Packet capture functionality
- Protocol parser accuracy
- Threat detection algorithms
- Traffic analysis statistics
- Data export formats
- GUI responsiveness

## Security Considerations

⚠️ **Important:**
- Use on authorized networks only
- Comply with applicable laws and regulations
- Some traffic may contain sensitive data
- Implement appropriate access controls
- Archive captured data securely
- Respect user privacy

## Contributing

Contributions welcome! Please ensure:
- Code follows PEP 8 style guide
- All tests pass
- Documentation is updated
- Commits are well-documented

## License

MIT License - See LICENSE file for details

## Support

For issues and questions:
1. Check [USAGE_GUIDE.md](docs/USAGE_GUIDE.md) troubleshooting section
2. Review [ARCHITECTURE.md](docs/ARCHITECTURE.md) for technical details
3. Check [INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md) for setup issues

## References

### Useful Resources
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [RFC 791 - IP Protocol](https://tools.ietf.org/html/rfc791)
- [RFC 793 - TCP](https://tools.ietf.org/html/rfc793)
- [RFC 1035 - DNS](https://tools.ietf.org/html/rfc1035)
- [Wireshark Documentation](https://www.wireshark.org/docs/)

### Network Analysis Tools
- **Wireshark:** GUI-based packet analyzer
- **tcpdump:** Command-line packet sniffer
- **NetFlow:** Network traffic analysis
- **Zeek:** Network intrusion detection system

## Disclaimer

This tool is provided for **authorized network analysis only**. Users are responsible for:
- Ensuring they have proper authorization to monitor networks
- Complying with all applicable laws and regulations
- Protecting captured data from unauthorized access
- Using the tool ethically and responsibly

Unauthorized network monitoring may be illegal in your jurisdiction.

## Author & Acknowledgments

**Created by:** CodeAlpha Cybersecurity Projects

**Technology Stack:**
- Python 3.8+
- Scapy (packet manipulation)
- Tkinter (GUI)
- Custom threat detection algorithms

---

**Version:** 1.0.0  
**Last Updated:** 2024  
**Status:** Stable Release

For latest updates and information, visit the project repository.
