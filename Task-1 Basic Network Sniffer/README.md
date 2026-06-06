# Basic Network Sniffer

A lightweight, beginner‑friendly packet sniffer written in Python using **Scapy**.  
It captures live traffic, prints a concise summary to the console, and logs every packet to a CSV file for later analysis.

---

## Features
- Capture live network traffic on any interface.
- Optional protocol filtering: TCP, UDP, ICMP, or all.
- Display source/destination IP, protocol, packet size, and a hex preview of payload.
- Log captured packets to `logs/captured_packets.csv` (append‑only CSV).
- Clean, typed `argparse`‑based command‑line interface.
- Graceful handling of permission errors and `Ctrl+C` termination.

---

## Installation
1. Clone the repo or copy the folder.
2. (Recommended) Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/macOS
   .\\venv\\Scripts\\activate  # Windows PowerShell
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. **Run with elevated privileges** (required for raw sockets):
   - Linux/macOS: `sudo python src/sniffer.py`
   - Windows: open PowerShell as *Administrator* and run `python src/sniffer.py`.

---

## Usage
```bash
python src/sniffer.py [options]
```
### Options
| Flag | Description | Example |
|------|-------------|---------|
| `-i`, `--interface` | Interface to sniff (default = Scapy default) | `-i eth0` |
| `-p`, `--protocol` | Protocol filter – `all`, `tcp`, `udp`, `icmp` | `-p tcp` |
| `-c`, `--csv` | CSV log path (default `logs/captured_packets.csv`) | `-c mylog.csv` |
| `-t`, `--count` | Stop after *n* packets (0 = unlimited) | `-t 100` |
| `--timeout` | Stop after *N* seconds (0 = no timeout) | `--timeout 60` |

Press **Ctrl+C** to stop capturing.

---

## CSV Log Format
| Column | Meaning |
|--------|---------|
| `timestamp` | ISO‑8601 capture time |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `protocol` | `TCP`, `UDP`, `ICMP`, or `IP(<num>)` |
| `size_bytes` | Packet length in bytes |
| `payload_hex` | Hex view of the first 32 payload bytes |

---

## Troubleshooting
- **PermissionError** – run the script with admin/root rights.
- **No packets displayed** – verify the interface name (`ifconfig`, `ip a`, or PowerShell `Get‑NetAdapter`).
- **CSV not created** – ensure the `logs/` directory is writable; the script creates it automatically.

---

## Contributing
Feel free to fork the repo and submit pull requests. Ideas for extensions:
- IPv6 support
- Export to PCAP for Wireshark
- Simple GUI front‑end
- Real‑time statistics dashboard

---

## License
MIT License – see the `LICENSE` file.
