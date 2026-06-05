DEPLOYMENT & USAGE MANUAL
=========================

## 📍 PROJECT LOCATION

The complete Advanced Network Traffic Analyzer project is located at:
**C:\Users\Avinash\AppData\Local\Temp\AdvancedNetworkAnalyzer**

---

## 🚀 DEPLOYMENT INSTRUCTIONS

### Option 1: Using PowerShell

```powershell
# Copy project to CodeAlpha_Tasks- folder
$source = "C:\Users\Avinash\AppData\Local\Temp\AdvancedNetworkAnalyzer"
$dest = "C:\Users\Avinash\Documents\GitHub\CodeAlpha_Tasks-\AdvancedNetworkAnalyzer"

# Create destination
[System.IO.Directory]::CreateDirectory($dest) | Out-Null

# Copy files
Copy-Item -Path "$source\*" -Destination $dest -Recurse -Force

# Verify
Get-ChildItem $dest | Select-Object Name
```

### Option 2: Using File Explorer

1. Open File Explorer
2. Navigate to: C:\Users\Avinash\AppData\Local\Temp\
3. Right-click: AdvancedNetworkAnalyzer folder
4. Select: Copy
5. Navigate to: C:\Users\Avinash\Documents\GitHub\CodeAlpha_Tasks-
6. Right-click → Paste

### Option 3: Using Command Prompt

```batch
cd C:\Users\Avinash\AppData\Local\Temp
xcopy AdvancedNetworkAnalyzer C:\Users\Avinash\Documents\GitHub\CodeAlpha_Tasks-\AdvancedNetworkAnalyzer /E /I /Y
```

---

## 📦 PROJECT CONTENTS

### Source Code (src/)
```
packet_capture.py      - Captures live network packets
protocol_parser.py     - Decodes network protocols  
threat_detector.py     - Detects security threats
traffic_analyzer.py    - Generates statistics
data_exporter.py       - Exports to CSV/PCAP/JSON
gui.py                 - Modern GUI application
main.py                - Entry point
__init__.py            - Package initialization
```

### Documentation (docs/)
```
INSTALLATION_GUIDE.md  - Setup instructions (Windows/Linux/macOS)
ARCHITECTURE.md        - Network protocols & technical details
USAGE_GUIDE.md         - Advanced usage & troubleshooting
README.md              - Project overview
```

### Tests (tests/)
```
test_main.py          - Comprehensive unit tests
__init__.py           - Package initialization
```

### Configuration
```
requirements.txt      - Python dependencies
setup.py              - Installation script
LICENSE               - MIT License
.gitignore            - Git ignore rules
```

---

## ⚙️ INSTALLATION & SETUP

### Step 1: Navigate to Project Directory

```bash
cd C:\path\to\AdvancedNetworkAnalyzer
```

### Step 2: Install Python Dependencies

```bash
# Windows
pip install -r requirements.txt

# Linux/macOS
pip3 install -r requirements.txt

# With Python 3.11+ explicitly
python -m pip install -r requirements.txt
```

### Step 3: Install System Requirements

**Windows:**
1. Download Npcap: https://npcap.com/
2. Run installer with default settings
3. Enable "Install Npcap in WinPcap API-compatible Mode"
4. Restart computer

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install libpcap-dev python3-tk
```

**macOS:**
```bash
brew install libpcap
```

### Step 4: Verify Installation

```bash
# Check Scapy
python -c "from scapy.all import sniff; print('✓ Scapy OK')"

# Check Tkinter
python -c "import tkinter; print('✓ Tkinter OK')"

# List network interfaces
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

---

## ▶️ RUNNING THE APPLICATION

### GUI Mode (Default - Recommended)

```bash
# Windows (as Administrator)
python src/main.py

# Linux/macOS (with sudo)
sudo python3 src/main.py
```

### CLI Mode

```bash
python src/main.py --cli
```

### With Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/macOS)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
python src/main.py
```

---

## 📊 USING THE APPLICATION

### First-Time Usage

1. **Start the Application**
   ```bash
   python src/main.py
   ```

2. **Begin Packet Capture**
   - Click "Start Capture" button
   - Status changes to "Capturing..."

3. **Generate Network Traffic**
   - Open web browser (visit websites)
   - Ping a server: `ping google.com`
   - Download files
   - Use any network application

4. **Monitor Packets**
   - Watch packets appear in real-time in Capture tab
   - View protocol breakdown in Statistics tab
   - Check for threats in Threats tab

5. **Stop Capture**
   - Click "Stop Capture" button
   - Data remains available for analysis

6. **Export Results**
   - Navigate to Export tab
   - Choose export format (CSV, PCAP, Report)
   - Files saved to output/ directory

### Feature Usage

**Protocol Filtering:**
- Select protocol from dropdown (All, TCP, UDP, DNS, HTTP, etc.)
- Displays only packets matching selection

**IP Search:**
- Enter IP address in search box
- Shows all packets from/to that IP
- Example: `192.168.1.1`

**Statistics Tab:**
- Total packets and bytes
- Protocol breakdown with percentages
- Top communicating hosts
- Most used ports
- DNS query statistics

**Threats Tab:**
- Real-time threat alerts
- Port scanning detection
- ARP spoofing attempts
- DNS flooding warnings
- Severity rating (HIGH, MEDIUM, LOW)

**Export Tab:**
- Export captured packets as CSV (for Excel/analysis)
- Export as PCAP (for Wireshark)
- Generate text report (for documentation)
- Export threat log (for security incident tracking)

---

## 🧪 TESTING

### Run All Tests

```bash
# Using pytest
python -m pytest tests/

# Direct execution
python tests/test_main.py

# With verbose output
python -m pytest tests/ -v
```

### Test Coverage

- Protocol parsing accuracy
- Threat detection algorithms
- Traffic analysis statistics
- Data export functionality
- GUI responsiveness
- Integration workflows

### Expected Test Output

```
test_tcp_flags_parsing ... OK
test_port_scanning_detection ... OK
test_packet_analysis ... OK
test_csv_export ... OK
test_full_workflow ... OK

====== 15 passed in 0.45s ======
```

---

## 📚 DOCUMENTATION GUIDE

Read these documents in order:

1. **README.md**
   - Quick start
   - Feature overview
   - System requirements

2. **INSTALLATION_GUIDE.md**
   - Step-by-step setup
   - Platform-specific instructions
   - Troubleshooting

3. **ARCHITECTURE.md**
   - OSI model explanation
   - Protocol details
   - Network flow analysis

4. **USAGE_GUIDE.md**
   - GUI walkthrough
   - Advanced features
   - Analysis techniques
   - Troubleshooting

5. **QUICK_REFERENCE.md**
   - Quick commands
   - Common shortcuts
   - Performance tips

---

## 🔧 CONFIGURATION

### Network Interface Selection

Edit `src/packet_capture.py`:
```python
# Line: self.capture = PacketCapture(interface=None)
# Change to specific interface:
self.capture = PacketCapture(interface="eth0")  # Linux
self.capture = PacketCapture(interface="Wi-Fi")  # Windows
```

### Adjust Detection Thresholds

Edit `src/threat_detector.py`:
```python
self.port_scan_threshold = 20      # Ports before alert
self.port_scan_window = 30         # Time window (seconds)
self.dns_flood_threshold = 50      # Queries before alert
self.dns_flood_window = 10         # Time window (seconds)
self.arp_spoofing_threshold = 5    # MACs before alert
```

### Modify Packet Limits

Edit `src/packet_capture.py`:
```python
# Line: PacketCapture(interface=None, max_packets=10000, timeout=300)
self.capture = PacketCapture(max_packets=5000)  # Lower memory usage
```

---

## 🐛 TROUBLESHOOTING

### "No network interfaces found"

**Windows:**
- Ensure Npcap is installed
- Run as Administrator
- Try: Settings → Network & Internet → Change adapter options

**Linux/macOS:**
- Install libpcap: `sudo apt-get install libpcap-dev`
- Check interfaces: `ifconfig` or `ip addr`

### "Permission Denied" Error

**Windows:**
- Run Command Prompt as Administrator
- Rerun: `python src/main.py`

**Linux/macOS:**
- Use sudo: `sudo python3 src/main.py`
- Or set capabilities: `sudo setcap cap_net_raw=ep /usr/bin/python3`

### GUI doesn't appear

```bash
pip install customtkinter
# Linux may need:
sudo apt-get install python3-tk
```

### High CPU Usage

1. Click "Clear Packets" to free memory
2. Use protocol filters to reduce data
3. Disable threat detection if not needed
4. Reduce max_packets setting
5. Exit other applications

### No Packets Captured

1. Verify you have admin/root privileges
2. Check network interface is connected
3. Ensure you clicked "Start Capture"
4. Generate traffic (ping, web browsing)
5. Check firewall settings

---

## 📊 EXPORT EXAMPLES

### Export to CSV
```
Timestamp | Source IP | Dest IP | Port | Protocol | Size
2024-01-15 10:30:45 | 192.168.1.100 | 8.8.8.8 | 53891 | DNS | 67
```

### Export to PCAP
- Open in Wireshark
- Further detailed analysis
- Long-term storage

### Generate Report
- Summary statistics
- Protocol breakdown
- Threat listing
- For documentation/compliance

---

## 🎯 COMMON WORKFLOWS

### Workflow 1: Monitor DNS Traffic

```
1. Start Capture
2. Set Protocol Filter: DNS
3. Browse internet
4. Export DNS queries to CSV
5. Analyze domain access patterns
```

### Workflow 2: Detect Suspicious Activity

```
1. Start Capture
2. Monitor for 1 hour
3. Check Threats tab for alerts
4. Export PCAP of suspicious traffic
5. Analyze in Wireshark
```

### Workflow 3: Network Baseline

```
1. Clear data
2. Capture during normal operations (1 hour)
3. Generate statistics report
4. Save for future comparison
5. Note typical patterns and volumes
```

---

## 📋 QUICK COMMANDS

```bash
# Install all dependencies
pip install -r requirements.txt

# Run GUI application
python src/main.py

# Run CLI mode
python src/main.py --cli

# Run tests
python tests/test_main.py

# Install as package
pip install .

# Install with development tools
pip install -e ".[dev]"

# Check Python version
python --version

# Verify installation
python -m pytest tests/ -v
```

---

## 💾 FILE EXPORT LOCATIONS

All exports are saved to: `output/`

Format: `{type}_{timestamp}.{extension}`

Examples:
- `packets_20240115_103045.csv`
- `packets_20240115_103045.pcap`
- `report_20240115_103045.txt`
- `threats_20240115_103045.csv`

---

## 🔒 SECURITY NOTES

1. **Authorization:** Only monitor networks you own/manage
2. **Legal Compliance:** Follow local laws and regulations
3. **Data Protection:** Store captured traffic securely
4. **Credentials:** Never capture credentials-containing traffic
5. **Privacy:** Inform users if monitoring on shared networks

---

## 📞 SUPPORT

### For Installation Issues
See: `docs/INSTALLATION_GUIDE.md`

### For Usage Questions
See: `docs/USAGE_GUIDE.md`

### For Technical Details
See: `docs/ARCHITECTURE.md`

### External Resources
- Scapy: https://scapy.readthedocs.io/
- Wireshark: https://www.wireshark.org/
- Npcap: https://npcap.com/

---

## 📝 VERSION INFORMATION

- **Version:** 1.0.0
- **Status:** Production Ready
- **License:** MIT
- **Python:** 3.8+
- **Last Updated:** 2024

---

## ✓ VERIFICATION CHECKLIST

- [ ] Project copied to desired location
- [ ] Python 3.8+ installed
- [ ] dependencies installed: `pip install -r requirements.txt`
- [ ] System requirements installed (Npcap/libpcap)
- [ ] Tests pass: `python tests/test_main.py`
- [ ] Application starts: `python src/main.py`
- [ ] Documentation reviewed
- [ ] First packet capture successful

---

**Ready to use! Start with: python src/main.py**
