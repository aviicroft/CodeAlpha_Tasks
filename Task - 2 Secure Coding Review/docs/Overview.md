*Author: Avinash K*

# Project Overview

This repository demonstrates a **secure‑coding review** workflow applied to a deliberately vulnerable Flask web application. It is intended for:

- Security training and capture‑the‑flag style exercises.
- Demonstrating how to perform a manual code audit and how static analysis tools can help.
- Showing the full remediation lifecycle – from vulnerable code to hardened, production‑ready code.

---

## Repository Layout
```
Task - 2 Secure Coding Review/
├─ src/                     # Vulnerable Flask application
│   └─ app.py              # Main entry point (vulnerable version)
├─ docs/                    # Documentation
│   └─ Overview.md         # This file
├─ tests/ (optional)       # Place for future integration tests
├─ requirements.txt         # Python dependencies + security tools
├─ SECURITY_REVIEW.md      # Detailed audit findings
├─ REMEDIATION_REPORT.md   # Secure code replacements
├─ README.md                # Getting‑started guide
└─ .gitignore (optional)  # Exclude uploads, venv, etc.
```

---

## Getting Started

1. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   ```
2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the vulnerable app**
   ```bash
   python src/app.py
   ```
   The app will listen on `http://127.0.0.1:5000/`.

---

## Auditing Workflow
1. **Static analysis** – run Bandit, Flake8, Safety.
   ```bash
   bandit -r src/
   flake8 src/
   safety check -r requirements.txt
   ```
2. **Manual review** – consult `SECURITY_REVIEW.md` for a step‑by‑step walkthrough of each vulnerability.
3. **Remediation** – apply the patches listed in `REMEDIATION_REPORT.md`. The file also contains the updated code snippets.
4. **Verification** – re‑run the static analysis tools and the application to ensure the issues are resolved.

---

## Extending the Project
- Add **unit tests** under a `tests/` directory to automate regression checks.
- Integrate the audit into a CI pipeline (GitHub Actions, GitLab CI, etc.) using the same static‑analysis commands.
- Replace the insecure example with a real‑world codebase to practice on production‑grade software.

---

## License & Disclaimer
This code is **intentionally insecure** and **must not be deployed** to any production environment. It is provided solely for **educational purposes**. Use responsibly.
