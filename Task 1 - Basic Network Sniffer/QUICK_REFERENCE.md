# QUICK REFERENCE CARD

## Installation Quick Start

### Windows
```bash
pip install -r requirements.txt
# Install Npcap from https://npcap.com/
python src/main.py
```

### Linux/macOS
```bash
sudo apt-get install libpcap-dev  # or: brew install libpcap
pip3 install -r requirements.txt
sudo python3 src/main.py
```

## Common Commands

```bash
# GUI Mode (default)
python src/main.py

# CLI Mode
python src/main.py --cli

# Run Tests
python tests/test_main.py
python -m pytest tests/

# Install Package
pip install .

# Create Virtual Environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

## GUI Navigation

| Tab | Purpose | Key Actions |
|-----|---------|------------|
| **Packet Capture** | Monitor traffic | Start/Stop, Filter, Search |
| **Statistics** | View analysis | Protocol breakdown, Top IPs/Ports |
| **Threats** | Security alerts | Port scans, ARP spoofing, DNS floods |
| **Export** | Save data | CSV, PCAP, Reports, Threats |

## Keyboard Shortcuts

- **Ctrl+C:** Stop capture (CLI)
- **Ctrl+E:** Export data
- **Ctrl+F:** Search packets
- **F5:** Refresh display
- **Alt+F4:** Exit application

## Filtering Examples

```
Protocol: TCP          # Show only TCP packets
Protocol: DNS          # Show only DNS queries
Search IP: 192.168.1   # Find traffic with this IP
```

## Export Formats

| Format | Use Case | Extension |
|--------|----------|-----------|
| CSV | Spreadsheet analysis | .csv |
| PCAP | Wireshark analysis | .pcap |
| Text | Documentation | .txt |
| Threat | Security log | .csv |

## Threat Detection Thresholds

Edit `src/threat_detector.py`:
```python
port_scan_threshold = 20        # Alert at 20 ports
port_scan_window = 30           # in 30 seconds
dns_flood_threshold = 50        # Alert at 50 queries
dns_flood_window = 10           # in 10 seconds
arp_spoofing_threshold = 5      # Alert at 5 MACs per IP
```

## Common Ports

| Port | Service | Protocol |
|------|---------|----------|
| 22 | SSH | TCP |
| 53 | DNS | UDP |
| 80 | HTTP | TCP |
| 443 | HTTPS | TCP |
| 3306 | MySQL | TCP |

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No interfaces found | Install Npcap/libpcap |
| Permission denied | Run with sudo/Administrator |
| GUI doesn't show | Install: `pip install customtkinter` |
| High CPU usage | Use protocol filters, clear packets |
| No packets captured | Check interface selection, verify admin mode |

## Project Files

```
src/                  Core Python modules
  ├── main.py         Entry point
  ├── gui.py          GUI interface
  ├── packet_capture.py    Packet capture engine
  ├── protocol_parser.py   Protocol decoding
  ├── threat_detector.py   Threat detection
  ├── traffic_analyzer.py  Statistics
  └── data_exporter.py     Export functionality

docs/                 Documentation
  ├── INSTALLATION_GUIDE.md    Setup instructions
  ├── ARCHITECTURE.md          Technical details
  └── USAGE_GUIDE.md           Advanced usage

tests/                Unit tests
  └── test_main.py    Test suite

requirements.txt      Dependencies
setup.py              Installation script
```

## Performance Tips

1. **Clear packets regularly** → Click "Clear Packets"
2. **Use protocol filters** → Reduce processing
3. **Reduce packet limit** → For memory constraints
4. **Disable unused threats** → Improve performance
5. **Export old data** → Free up memory

## Getting Help

1. Check docs/ folder for detailed guides
2. See TROUBLESHOOTING in USAGE_GUIDE.md
3. Run: `python -m pytest tests/` to verify setup
4. Review error messages in console

## Quick Analysis Workflow

1. **Start Capture** → Click "Start Capture"
2. **Generate Traffic** → Open web browser, ping, etc.
3. **Wait 30 seconds** → Let traffic accumulate
4. **Stop Capture** → Click "Stop Capture"
5. **Review Statistics** → Click "Statistics" tab
6. **Check Threats** → Click "Threats" tab
7. **Export Results** → Click "Export" tab

## System Requirements Check

```bash
# Check Python
python --version

# Verify Scapy
python -c "from scapy.all import sniff; print('OK')"

# List network interfaces
python -c "from scapy.all import get_if_list; print(get_if_list())"

# Run full test
python tests/test_main.py
```

## Key Features

✓ Real-time packet capture
✓ 8+ protocol support
✓ 3 threat detection types
✓ Multiple export formats
✓ Live statistics dashboard
✓ Customizable filtering
✓ Comprehensive documentation
✓ Full test coverage

## Support Resources

- **Installation Issues:** docs/INSTALLATION_GUIDE.md
- **Technical Details:** docs/ARCHITECTURE.md
- **Usage Guide:** docs/USAGE_GUIDE.md
- **Scapy Docs:** https://scapy.readthedocs.io/
- **Wireshark:** https://www.wireshark.org/

---
**Version:** 1.0.0 | **License:** MIT | **Status:** Production Ready
