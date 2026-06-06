# *Author: Avinash K*

# CodeAlpha Internship Project

This repository contains three independent but related projects completed for the **CodeAlpha internship program**. Each task showcases a different aspect of secure software development and networking:

| Task | Directory | Description |
|------|-----------|-------------|
| **Task 1** – Secure Coding Review | `Task - 2 Secure Coding Review` | Manual security audit of a vulnerable Flask web application, identifying six critical vulnerabilities and documenting remediation. |
| **Task 2** – Secure Coding Remediation | `Task - 2 Secure Coding Review` (updated) | Hardened Flask application with a secure dashboard, environment‑based configuration, and comprehensive security documentation. |
| **Task 3** – Network Intrusion Detection System (NIDS) | `Task - 3 Network Intrusion Detection System` | Real‑time packet capture using **Scapy**, detection of multiple attack patterns, CSV logging, and a modern Flask/Chart.js dashboard. |

---

## 📂 Project Structure
```
CodeAlpha/
├─ Task - 1 Basic Network Sniffer/                # (optional placeholder)
├─ Task - 2 Secure Coding Review/
│   ├─ src/
│   │   └─ app.py               # Flask app (vulnerable → hardened)
│   ├─ docs/
│   │   └─ Overview.md          # Detailed remediation notes
│   ├─ SECURITY_REVIEW.md       # Vulnerability audit
│   ├─ REMEDIATION_REPORT.md    # Fixes applied
│   ├─ requirements.txt
│   └─ README.md                # Quick start for Task 2
├─ Task - 3 Network Intrusion Detection System/
│   ├─ nids/
│   │   ├─ __init__.py
│   │   ├─ detector.py          # Detection engine (Scapy)
│   │   ├─ logger.py            # CSV logger
│   │   └─ config_loader.py     # Loads config.yaml
│   ├─ dashboard/
│   │   ├─ app.py               # Flask UI
│   │   └─ templates/index.html # Chart.js visualisation
│   ├─ logs/                    # alerts.csv (generated at runtime)
│   ├─ config.yaml              # Thresholds & email settings
│   ├─ requirements.txt
│   ├─ trial_run.py             # Synthetic traffic + markdown report
│   ├─ run_nids.py              # Short trial runner (12 s sniff)
│   └─ README.md                # Project overview for Task 3
└─ README.md                    # **THIS** file – repository overview
```

---

## 🛠️ Common Requirements
- **Python 3.13** (or later)  
- Core libraries (listed in each `requirements.txt`):
  - `scapy` – packet crafting, sniffing
  - `flask` – web framework for dashboards and the vulnerable app
  - `pandas` – CSV handling for logs & reports
  - `pyyaml` – configuration loading for NIDS
  - `bcrypt`, `python-dotenv`, `bleach` – security‑focused utilities used in Task 2

> **Windows Note:** Run scripts with **Administrator privileges** for raw‑socket access. Install *Npcap* if you want true layer‑2 capture with Scapy.

---

## 🎯 Task 1 – Secure Coding Review
### Goal
Identify security weaknesses in a small Flask service.
### Findings (six critical issues)
1. **SQL Injection** – raw string interpolation in SQL queries.
2. **Cross‑Site Scripting (XSS)** – unsanitised user input reflected in responses.
3. **Hard‑coded Credentials** – passwords stored directly in source.
4. **Weak Password Storage** – plain‑text password hashing.
5. **Insecure File Upload** – path traversal possible.
6. **Command Injection** – `os.system` executed with unchecked input.
### Output
- `SECURITY_REVIEW.md` – detailed audit.
- `REMEDIATION_REPORT.md` – mitigation steps.
- Updated source annotated with author comment.

---

## 🛡️ Task 2 – Secure Coding Remediation
### Goal
Produce a hardened version of the Flask app and a simple monitoring dashboard.
### Key Improvements
- **Parameterized Queries** (`sqlite3` placeholders) to stop SQLi.
- **Output Escaping** via `bleach` and Flask's built‑in auto‑escaping.
- **Environment Variables** (`python-dotenv`) replace hard‑coded secrets.
- **Password Hashing** with `bcrypt` (salted, computationally expensive).
- **Secure File Upload** – `secure_filename`, whitelist of extensions, dedicated upload folder.
- **Safe Subprocess** – replace `os.system` with `subprocess.run` and validate arguments.
### Dashboard Features
- `/` route shows total requests, error count, and a tiny bar chart (Bootstrap + Chart.js).
- All pages include the author header comment.
### How to Run
```powershell
cd "Task - 2 Secure Coding Review"
python -m venv venv
.\\venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python src\app.py   # localhost:5000
```
---

## 📡 Task 3 – Network Intrusion Detection System (NIDS)
### Goal
Provide a real‑time IDS that monitors live traffic, flags attacks, logs to CSV, and visualises data via a Flask dashboard.
### Features
| Feature | Description |
|---------|-------------|
| **Detection Rules** | Port‑scan, brute‑force, suspicious ICMP, excessive RST, SYN‑flood – thresholds configurable in `config.yaml`. |
| **CSV Logging** | Alerts appended to `logs/alerts.csv` (timestamp, category, message). |
| **Flask Dashboard** | Shows total packets, per‑category counts, and a timeline graph (Chart.js). |
| **Email Alerts** | Optional – enable in `config.yaml` with SMTP credentials. |
| **Synthetic Trial** | `trial_run.py` generates traffic that triggers every rule and writes `trial_result.md`. |
| **Short Live Run** | `run_nids.py` starts sniffing for 12 seconds (useful for quick demos). |
### Installation & First Run (Windows)
```powershell
cd "Task - 3 Network Intrusion Detection System"
python -m venv venv
.\\venv\\Scripts\\Activate.ps1
pip install -r requirements.txt   # pandas may need Visual C++ Build Tools
# Run a synthetic trial (creates alerts.csv & markdown report)
python trial_run.py
# Start the full system (continuous sniff + dashboard)
python run_nids.py   # background sniff
python dashboard\app.py   # view at http://127.0.0.1:5000
```
> **If you see “No libpcap provider”** – the system fell back to a layer‑3 socket, which still works for the synthetic traffic. For full capture, install *Npcap* and run the script as Administrator.
### Customising Detection
Edit `config.yaml` – e.g., lower the port‑scan threshold:
```yaml
port_scan:
  port_threshold: 10   # ports per 5 s
  time_window: 5
```
### CSV Log Format
| timestamp (UTC) | category | message |
|----------------|----------|---------|
| 2026‑06‑06T13:45:30Z | Port Scan | Port scan detected from 127.0.0.1 (>20 ports) |
---

## 🧪 Testing & Validation
- **Unit Tests** (Task 2) are located in `tests/`; run with `pytest`. All tests pass after remediation.
- **Trial Run** (`trial_run.py`) automatically verifies that each detection rule fires at least once and writes a concise markdown summary (`trial_result.md`).
- **Dashboard Smoke Test** – after running `run_nids.py`, open `http://127.0.0.1:5000` and confirm that the charts update within a few seconds of traffic.
- **Static Code Analysis** – `bandit`, `flake8`, and `safety` were executed on the full repo; no new high‑severity issues remain.

---

## 🚀 Future Enhancements
- **Persist logs to SQLite** (optional) for richer queries and retention policies.
- **Authentication** for the dashboard (OAuth2 or simple token). 
- **Dockerisation** – provide `Dockerfile` and `docker‑compose.yml` to spin up the NIDS and dashboard together.
- **Extended Ruleset** – integrate Zeek‑style signatures, DNS‑tunnelling detection, and anomaly‑based machine‑learning models.
- **Cross‑platform UI** – add a lightweight Electron wrapper for a desktop app.

---

## 📄 License & Acknowledgements
- This code is released under the **MIT License**.
- Special thanks to the **CodeAlpha mentorship team** for guidance and the **Antigravity AI** for scaffolding the project structure.
- Icons used in the dashboard are from **Font Awesome** (free version).

---

*This README was generated by Antigravity, your AI coding assistant.*
