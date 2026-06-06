*Author: Avinash K*

# Secure Coding Review and Vulnerability Assessment

## Overview

This repository contains a deliberately vulnerable Python web application built with **Flask**. It demonstrates common security flaws:

- SQL Injection
- Cross‑Site Scripting (XSS)
- Hard‑coded Credentials
- Weak Password Storage
- Insecure File Upload
- Command Injection

The project also includes:

1. **Vulnerable source code** (`src/app.py`).
2. **Security review report** (`SECURITY_REVIEW.md`).
3. **Remediation report** with secure code examples (`REMEDIATION_REPORT.md`).
4. **README** with usage instructions (`README.md`).
5. **Documentation** (`docs/Overview.md`).
6. **GitHub‑style repository structure**.

Static analysis tools such as **Bandit**, **Flake8**, and **Safety** are integrated via a simple `requirements.txt` and can be run locally to discover many of these issues automatically.

---

## Getting Started

```bash
# Clone the repository (if hosted on GitHub)
# git clone https://github.com/your-org/secure-coding-review.git
# cd secure-coding-review

# Install dependencies
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run the vulnerable app
python src/app.py
```

The app will be available at `http://127.0.0.1:5000/`.

---

## License

This project is for educational purposes only. Use responsibly.
