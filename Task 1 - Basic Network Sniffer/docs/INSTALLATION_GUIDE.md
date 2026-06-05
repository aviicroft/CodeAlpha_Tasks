# Installation Guide

## Prerequisites

### System Requirements
- **OS**: Windows 7+, Ubuntu 18.04+, macOS 10.12+
- **Python**: 3.8 or higher
- **RAM**: Minimum 2GB (4GB recommended)
- **Disk Space**: 500MB for application and dependencies
- **Administrator/Root**: Required for packet capture

### Required Libraries
- Scapy (network packet manipulation)
- Tkinter or CustomTkinter (GUI)
- libpcap (Linux/macOS) or Npcap (Windows)

---

## Installation Steps

### Step 1: Install Python

**Windows:**
1. Download Python from [python.org](https://www.python.org/downloads/)
2. Run installer and select "Add Python to PATH"
3. Verify installation: `python --version`

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip python3-tk
python3 --version
```

**macOS:**
```bash
brew install python@3.11
brew install python-tk@3.11
python3 --version
```

---

### Step 2: Install Packet Capture Library

**Windows - Install Npcap:**
1. Download Npcap from [https://npcap.com/](https://npcap.com/)
2. Run the installer with default settings
3. Enable "Install Npcap in WinPcap API-compatible Mode"
4. Restart your computer

**Linux - Install libpcap:**
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# Fedora/RHEL
sudo dnf install libpcap-devel

# Arch
sudo pacman -S libpcap
```

**macOS - Install libpcap:**
```bash
brew install libpcap
```

---

### Step 3: Clone or Download the Project

```bash
# Clone the repository (if using git)
git clone <repository-url>
cd AdvancedNetworkAnalyzer

# Or download and extract the ZIP file
```

---

### Step 4: Install Python Dependencies

```bash
# Install required packages
pip install -r requirements.txt

# Or install individually:
pip install scapy customtkinter
```

**Note for Linux/macOS:**
```bash
# Use pip3 if pip is not available
pip3 install -r requirements.txt

# Or use sudo if permission denied
sudo pip3 install -r requirements.txt
```

---

## Dependency Installation Details

### Scapy
```bash
pip install scapy
```
- Network packet crafting and analysis
- Supports Python 3.8+
- Cross-platform compatible

### Tkinter/CustomTkinter
```bash
# Tkinter (usually included with Python)
# CustomTkinter for modern UI
pip install customtkinter
```

### Optional Dependencies
```bash
# For enhanced functionality
pip install numpy pandas matplotlib
```

---

## Platform-Specific Setup

### Windows Setup

1. **Administrator Privileges:**
   - Run Command Prompt as Administrator
   - Install dependencies with administrator rights

2. **Npcap Configuration:**
   ```batch
   # Verify Npcap installation
   netsh wlan show interfaces
   ```

3. **Run Application:**
   ```batch
   # Ensure you have administrator privileges
   python src/main.py
   ```

### Linux Setup

1. **Set Capabilities for Non-Root Users:**
   ```bash
   # Allow packet capture without sudo
   sudo setcap cap_net_raw=ep /usr/bin/python3
   
   # Or run with sudo
   sudo python3 src/main.py
   ```

2. **Firewall Configuration:**
   - Ensure firewall allows packet capture
   - Check SELinux/AppArmor policies

### macOS Setup

1. **System Integrity Protection:**
   - May restrict packet capture
   - Use `sudo` for full access
   ```bash
   sudo python3 src/main.py
   ```

2. **Gatekeeper:**
   - First run may require approval
   - Go to System Preferences → Security & Privacy

---

## Verification

### Test Installation

```bash
# Check Python version
python --version

# Verify Scapy
python -c "from scapy.all import sniff; print('Scapy OK')"

# Verify Tkinter
python -c "import tkinter; print('Tkinter OK')"

# Check network interfaces
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

### Run Application

```bash
# GUI Mode
python src/main.py

# CLI Mode
python src/main.py --cli
```

---

## Troubleshooting

### Issue: "No module named 'scapy'"
**Solution:**
```bash
pip install scapy
# Or with Python 3:
pip3 install scapy
```

### Issue: "No network interfaces found"
**Windows:**
- Reinstall Npcap
- Run as Administrator
- Restart computer after Npcap installation

**Linux/macOS:**
- Install libpcap: `sudo apt-get install libpcap-dev`
- Check interface: `ifconfig` or `ip addr`

### Issue: "Permission denied" on Linux/macOS
**Solutions:**
- Run with sudo: `sudo python3 src/main.py`
- Or set capabilities: `sudo setcap cap_net_raw=ep /usr/bin/python3`
- Or add user to packet group: `sudo usermod -a -G wireshark $USER`

### Issue: Tkinter not found on Linux
```bash
sudo apt-get install python3-tk
# Or for Python 2
sudo apt-get install python-tk
```

### Issue: GUI doesn't display properly
- Install CustomTkinter: `pip install customtkinter`
- Update Tkinter: `pip install --upgrade tkinter`
- On Linux, may need X11 display support

### Issue: "ModuleNotFoundError" during import
```bash
# Ensure you're in the project directory
cd /path/to/AdvancedNetworkAnalyzer

# Run with proper Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
python src/main.py
```

---

## Virtual Environment Setup (Recommended)

### Create Virtual Environment

**Windows:**
```batch
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python src/main.py
```

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 src/main.py
```

### Benefits
- Isolated Python environment
- No system-wide package conflicts
- Easy to manage dependencies
- Reproducible setup

---

## Docker Setup (Optional)

### Create Dockerfile
```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y libpcap-dev

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python", "src/main.py"]
```

### Build and Run
```bash
docker build -t network-analyzer .
docker run --network host network-analyzer
```

---

## System Sanity Check

```bash
# Complete verification script
python -c "
import sys
print(f'Python: {sys.version}')

try:
    import scapy
    print('✓ Scapy installed')
except ImportError:
    print('✗ Scapy NOT installed')

try:
    import tkinter
    print('✓ Tkinter installed')
except ImportError:
    print('✗ Tkinter NOT installed')

try:
    from scapy.all import get_if_list
    interfaces = get_if_list()
    print(f'✓ Network interfaces found: {len(interfaces)}')
except Exception as e:
    print(f'✗ Error detecting interfaces: {e}')
"
```

---

## Getting Help

If you encounter issues:
1. Check the Troubleshooting section above
2. Review the [USAGE_GUIDE.md](USAGE_GUIDE.md)
3. Check [ARCHITECTURE.md](ARCHITECTURE.md) for technical details
4. Review error logs and system messages

---

**Last Updated:** 2024
**Version:** 1.0.0
