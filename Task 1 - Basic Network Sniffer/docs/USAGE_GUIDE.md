# Advanced Usage Guide

## Table of Contents
1. [Quick Start](#quick-start)
2. [GUI Walkthrough](#gui-walkthrough)
3. [Advanced Features](#advanced-features)
4. [Analysis Techniques](#analysis-techniques)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

---

## Quick Start

### Launching the Application

**GUI Mode (Default):**
```bash
# Windows (with Administrator)
python src/main.py

# Linux/macOS (with sudo)
sudo python3 src/main.py
```

**CLI Mode:**
```bash
python src/main.py --cli
```

### First-Time Setup
1. Launch the application
2. Navigate to the "Packet Capture" tab
3. Click "Start Capture"
4. Generate traffic (open a web browser, ping a website)
5. Observe captured packets in real-time
6. Click "Stop Capture" when done

---

## GUI Walkthrough

### Main Tabs

#### 1. Packet Capture Tab
**Purpose:** Real-time packet monitoring and filtering

**Components:**
- **Start/Stop Buttons:** Control packet capture
- **Protocol Filter:** Filter by specific protocol
- **IP Search:** Find packets from/to specific IP
- **Packets Table:** Display captured packets

**Usage:**
1. Click "Start Capture" to begin monitoring
2. Use filters to narrow results:
   ```
   Protocol: TCP (captures only TCP traffic)
   Search IP: 192.168.1.1 (shows only packets with this IP)
   ```
3. Click on packet rows for details
4. Use "Clear Packets" to reset data

**Columns Explained:**
- **Timestamp:** When packet was captured
- **Source:** Source IP:Port (if applicable)
- **Destination:** Destination IP:Port
- **Protocol:** Protocol stack (e.g., "TCP / HTTP")
- **Length:** Packet size in bytes
- **Info:** Protocol-specific information

#### 2. Statistics Tab
**Purpose:** View comprehensive traffic analysis

**Displays:**
```
TRAFFIC STATISTICS
├── Total Packets: Count of all captured packets
├── Total Bytes: Sum of all packet sizes
└── Average Packet Size: Mean packet size

PROTOCOL BREAKDOWN
├── TCP: X packets (Y%)
├── UDP: X packets (Y%)
├── DNS: X packets (Y%)
├── HTTP: X packets (Y%)
└── ARP: X packets (Y%)

TOP IP ADDRESSES
├── 192.168.1.100: 5MB (1000 packets)
├── 8.8.8.8: 3MB (500 packets)
└── ...

TOP PORTS
├── Port 443 (HTTPS): 2000 connections
├── Port 53 (DNS): 1500 connections
└── ...

TOP DNS QUERIES
├── google.com: 150 queries
├── github.com: 100 queries
└── ...
```

**Analysis Tips:**
- Identify chatty hosts (consuming most bandwidth)
- Understand protocol distribution
- Spot unusual traffic patterns
- Track popular services being accessed

#### 3. Threats Tab
**Purpose:** View detected security threats

**Threat Types:**

**Port Scanning:**
```
[HIGH] PORT_SCANNING
Message: Potential port scan from 192.168.1.105: 25 ports in 30s
Time: 2024-01-15 10:30:45
```
- Indicates aggressive connection attempts
- Usually precursor to attack

**ARP Spoofing:**
```
[HIGH] ARP_SPOOFING
Message: Potential ARP spoofing detected for 192.168.1.1: 5 different MAC addresses
```
- Multiple MAC addresses claiming same IP
- Indicates MITM attack attempt

**DNS Flooding:**
```
[MEDIUM] DNS_FLOODING
Message: Potential DNS flood from 192.168.1.110: 85 queries in 10s
```
- Excessive DNS queries
- Could be bot activity or DDoS

#### 4. Export Tab
**Purpose:** Save and export data

**Export Formats:**

1. **CSV Export**
   - Includes all packet details
   - Compatible with Excel, Python Pandas
   - Use for: Further analysis, reporting

2. **PCAP Export**
   - Standard libpcap format
   - Compatible with Wireshark
   - Use for: Deep packet inspection, archival

3. **Text Report**
   - Human-readable summary
   - Includes statistics and threats
   - Use for: Documentation, sharing results

4. **Threat Report**
   - CSV with detected threats
   - Includes severity and details
   - Use for: Security incident tracking

---

## Advanced Features

### 1. Protocol Filtering

**Filter Options:**
```
All      - Show all traffic
TCP      - Transmission Control Protocol (connection-oriented)
UDP      - User Datagram Protocol (connectionless)
DNS      - Domain Name System
HTTP     - HyperText Transfer Protocol
ARP      - Address Resolution Protocol
ICMP     - Internet Control Message Protocol
```

**Example Workflows:**

**Monitor DNS Traffic:**
```
1. Set Protocol Filter: DNS
2. Observe: Domains being queried
3. Identify: Suspicious domains accessed
4. Export: DNS activity report
```

**Track HTTP Traffic:**
```
1. Set Protocol Filter: HTTP
2. Monitor: Web browsing activity
3. Identify: Accessed websites
4. Note: Unencrypted data transmission
```

### 2. IP Search and Filtering

**Search Patterns:**
```
Single IP:     192.168.1.1 - Shows all packets from/to this IP
Subnet:        192.168.1   - Shows all packets in 192.168.1.0/24
CIDR:          192.168.0/16 - Shows 192.168.0.0/16 traffic
```

**Example Analysis:**

**Monitor Specific Host:**
```
1. Search IP: 192.168.1.105
2. Results: All traffic from/to this host
3. Analyze: What services it accesses
4. Detect: Suspicious connections
```

### 3. Threat Detection Configuration

**Adjust Detection Thresholds:**

Edit `src/threat_detector.py`:
```python
self.port_scan_threshold = 20      # Alert after 20 ports
self.port_scan_window = 30         # in 30 seconds
self.dns_flood_threshold = 50      # Alert after 50 queries
self.dns_flood_window = 10         # in 10 seconds
self.arp_spoofing_threshold = 5    # Alert after 5 MACs per IP
```

**Example: Lower Sensitivity**
```python
self.port_scan_threshold = 50      # Only alert on heavy scanning
self.dns_flood_threshold = 100     # Higher threshold = fewer false positives
```

---

## Analysis Techniques

### 1. Baseline Establishment

**Create Network Baseline:**
```
1. Run analyzer for 1 hour during normal operations
2. Record total traffic volume
3. Note typical protocol distribution
4. Identify normal traffic patterns
5. Save statistics for comparison
```

### 2. Anomaly Detection

**Look for Deviations:**
```
Unusual Patterns:
├── Sudden traffic spike (200% increase)
├── New protocols appearing
├── Known ports with different services
├── After-hours traffic during business hours
└── Repeated failed connections
```

### 3. Incident Investigation

**Systematic Investigation:**
```
1. Identify suspect traffic
   └─ Use IP/Protocol filters
2. Extract detailed packets
   └─ Export to PCAP for Wireshark analysis
3. Generate timeline
   └─ Sort by timestamp
4. Correlate with threats
   └─ Review threat detection logs
5. Document findings
   └─ Export comprehensive report
```

### 4. Performance Analysis

**Identify Bottlenecks:**
```
1. Check top IPs consuming bandwidth
2. Monitor port usage patterns
3. Detect DNS resolution delays
4. Track packet loss indicators
5. Analyze TCP retransmission patterns
```

---

## Advanced Configuration

### Custom Analysis Scripts

**Example: Detect Specific Traffic**

Create `custom_analyzer.py`:
```python
from src.packet_capture import PacketCapture
from src.protocol_parser import ProtocolParser

capture = PacketCapture()
parser = ProtocolParser()

capture.start()

# Your custom analysis
while capture.is_capturing:
    packets = capture.get_packets()
    for pkt_data in packets:
        parsed = parser.parse(pkt_data)
        
        # Example: Find HTTPS traffic to suspicious domains
        if "HTTPS" in parsed.get("protocols", []):
            dst = parsed.get("dst_ip")
            print(f"HTTPS connection to {dst}")

capture.stop()
```

### Interface Selection

**Capture on Specific Interface:**

Edit `src/main.py`:
```python
# Change from None (auto-detect) to specific interface
self.capture = PacketCapture(interface="eth0")  # Linux
self.capture = PacketCapture(interface="Wi-Fi")  # Windows
```

---

## Troubleshooting

### Common Issues and Solutions

#### No Packets Captured
```
Problem: Start capture but no packets appear
Solution:
  1. Verify you have admin/sudo privileges
  2. Check if interface is selected correctly
  3. Ensure Npcap/libpcap is installed
  4. Try different network interface
  5. Check firewall settings
```

#### High CPU Usage
```
Problem: Application consuming 50%+ CPU
Solution:
  1. Reduce packet capture rate
  2. Increase buffer size
  3. Disable threat detection
  4. Close other applications
  5. Clear packets: click "Clear Packets"
  6. Reduce statistics update frequency
```

#### Memory Leak / Increasing Memory
```
Problem: Memory usage grows over time
Solution:
  1. Periodically click "Clear Packets"
  2. Reduce max_packets setting (default 10000)
  3. Export old data and clear
  4. Restart application
  5. Reduce logging verbosity
```

#### Export Fails
```
Problem: Cannot export to CSV/PCAP
Solution:
  1. Check output directory permissions
  2. Ensure disk space available
  3. Close files in use by other programs
  4. Try different export format
  5. Check file path for special characters
```

#### Threat Detection False Positives
```
Problem: Too many threat alerts
Solution:
  1. Increase detection thresholds
  2. Add IPs to whitelist
  3. Disable specific threat type
  4. Increase time window
  5. Review and adjust algorithm
```

---

## Best Practices

### 1. Data Security
- **Sensitive Data:** Use on secure networks only
- **Packet Storage:** Encrypted storage for PCAP files
- **Credentials:** Never capture credentials-containing traffic
- **Retention:** Delete captured traffic regularly

### 2. Legal Compliance
- **Authorization:** Only monitor networks you own/manage
- **Notification:** Inform users about monitoring if required
- **Retention Policies:** Follow organizational guidelines
- **Privacy Laws:** Comply with GDPR, CCPA, etc.

### 3. Performance
- **Regular Clearing:** Clear packets every hour
- **Filter Early:** Use protocol/IP filters to reduce data
- **Archive Results:** Export old data to files
- **Resource Monitoring:** Watch CPU and memory usage

### 4. Analysis
- **Systematic Approach:** Follow investigation procedures
- **Documentation:** Log all findings and actions
- **Correlation:** Compare with baseline and logs
- **Timeline:** Maintain chronological records

### 5. Reporting
```
Standard Report Format:
├── Executive Summary
├── Methodology
├── Findings
│   ├── Traffic Volume
│   ├── Protocol Distribution
│   ├── Top Hosts
│   └── Detected Threats
├── Recommendations
└── Technical Appendix
```

---

## Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Stop Capture | Ctrl+C (CLI) |
| Clear Data | Ctrl+Shift+C |
| Export CSV | Ctrl+E |
| Search | Ctrl+F |
| Refresh | F5 |
| Exit | Alt+F4 / Cmd+Q |

---

## Performance Benchmarks

| Metric | Value |
|--------|-------|
| Max Capture Rate | 100,000 packets/sec |
| Max Packet Store | 10,000 packets |
| Memory per Packet | ~500 bytes |
| CPU Load (capture) | <5% |
| CPU Load (analysis) | 10-20% |
| Typical Latency | <100ms |

---

**Last Updated:** 2024
**Version:** 1.0.0
