# Basic Network Sniffer – Project Documentation

## Overview
The **Basic Network Sniffer** is a teaching‑oriented utility that demonstrates how to capture, filter, display, and log network packets using the **Scapy** library. It is designed for beginners and cybersecurity interns who want to learn about packet analysis in Python.

## Architecture
```
+-------------------+          +-----------------+
|   Command line    |  args →  |   argparse      |
|   (user input)    |          +-----------------+
+----------+--------+                     |
           |                              v
           |                      +---------------+
           |                      | Build BPF     |
           |                      | filter string |
           |                      +-------+-------+
           |                              |
           |                              v
           |                +---------------------------+
           |                | scapy.sniff() (live loop) |
           |                +-----------+---------------+
           |                            |
           |                +-----------+-----------+
           |                |                       |
           v                v                       v
  +----------------+  +------------+          +-------------+
  | packet_handler |  | CSV logger |          | Console UI  |
  +----------------+  +------------+          +-------------+
```

- **argparse** parses CLI options.
- **BPF filter** limits traffic at the kernel level.
- **sniff()** captures packets; each packet triggers `packet_handler`.
- **packet_handler** extracts fields, prints a summary, and writes a CSV row.
- **log_packet** manages CSV creation and appending.

All components are synchronous for simplicity; the script is suitable for low‑to‑moderate traffic volumes.

## Design Decisions
| Decision | Reason |
|----------|--------|
| Single‑file implementation | Lower entry barrier for newcomers |
| CSV logging | Human‑readable, easy to import into spreadsheets |
| Payload truncation (32 bytes) | Keeps console output tidy while still showing useful data |
| `pathlib.Path` | Platform‑agnostic file handling |
| Graceful error handling | Provides clear guidance on permission problems |
| `Ctrl+C` handling | Allows clean exit without a traceback |

## Extensibility Roadmap
- IPv6 support
- Export raw packets to PCAP for Wireshark analysis
- Simple GUI front‑end (Tkinter / PySimpleGUI)
- Real‑time statistics (packet rate, bandwidth)
- Advanced filter DSL for custom BPF expressions

## Security Considerations
- **Privileges**: Capturing raw packets requires admin/root rights. Ensure you trust the environment.
- **Data privacy**: Logged payloads may contain sensitive data. Store logs securely and avoid committing them to version control.
- **DoS risk**: The tool is passive (read‑only) and does not modify traffic.

---

*End of documentation.*