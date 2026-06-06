# Security Review Report

**Project:** Secure Coding Review and Vulnerability Assessment
**Target Application:** `src/app.py` – a deliberately vulnerable Flask web app.
**Date:** 2026‑06‑06

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Methodology](#methodology)
3. [Findings](#findings)
   - [1. SQL Injection](#sql-injection)
   - [2. Cross‑Site Scripting (XSS)](#cross-site-scripting-xss)
   - [3. Hard‑coded Credentials](#hard-coded-credentials)
   - [4. Weak Password Storage](#weak-password-storage)
   - [5. Insecure File Upload](#insecure-file-upload)
   - [6. Command Injection](#command-injection)
4. [Static Analysis Results](#static-analysis-results)
5. [Conclusion & Recommendations](#conclusion--recommendations)

---

## Executive Summary
The application contains **six critical security flaws** that allow an attacker to gain unauthorized access, execute arbitrary code, and exfiltrate sensitive data. All flaws are *high* risk according to OWASP Top 10. The vulnerabilities can be demonstrated locally with simple HTTP requests. Remediation requires both code changes and security‑by‑design practices.

---

## Methodology
1. **Manual code review** – examined each route for insecure patterns.
2. **Dynamic testing** – crafted HTTP requests to trigger each vulnerability.
3. **Static analysis** – run Bandit, Flake8, and Safety against the codebase.
4. **Risk assessment** – classified using OWASP risk rating (Low/Medium/High/Critical).

---

## Findings

### 1. SQL Injection
- **Location:** `src/app.py` – `get_user` route (`/user?id=`).
- **Description:** User‑controlled `id` parameter is interpolated directly into an SQL query string.
- **Risk Level:** **Critical** (OWASP‑A01 – Injection).
- **Impact:** An attacker can retrieve, modify, or delete any data in the SQLite database, potentially escalating to full system compromise.
- **Exploitation Example:**
  ```bash
  curl "http://127.0.0.1:5000/user?id=1%20OR%201=1"
  ```
  Returns all users, leaking the hard‑coded API key.
- **Remediation:** Use parameterised queries (`?` placeholders) provided by the DB‑API.

### 2. Cross‑Site Scripting (XSS)
- **Location:** `search` route (`/search?q=`).
- **Description:** Query parameter `q` is rendered directly in HTML without escaping.
- **Risk Level:** **High** (OWASP‑A07 – XSS).
- **Impact:** An attacker can inject malicious JavaScript that runs in the victim’s browser, stealing cookies or performing actions on behalf of the user.
- **Exploitation Example:**
  ```bash
  curl "http://127.0.0.1:5000/search?q=%3Cscript%3Ealert('XSS')%3C/script%3E"
  ```
  The response contains the script tag unescaped.
- **Remediation:** Use Flask’s `{{ }}` auto‑escaping in templates or `escape()` from `markupsafe`.

### 3. Hard‑coded Credentials
- **Location:** `creds` route (`/creds`).
- **Description:** Username and password are hard‑coded and exposed via an endpoint.
- **Risk Level:** **Critical** (OWASP‑A02 – Broken Authentication).
- **Impact:** Anyone can obtain admin credentials, log in, and read or modify data.
- **Exploitation Example:** Visit `http://127.0.0.1:5000/creds` to retrieve credentials.
- **Remediation:** Remove the endpoint; store secrets in environment variables or a vault.

### 4. Weak Password Storage
- **Location:** `users` table (`password` column) – passwords stored in plain text.
- **Description:** Passwords are saved without hashing or salting.
- **Risk Level:** **High** (OWASP‑A02).
- **Impact:** If the database is leaked, all user passwords are immediately compromised.
- **Exploitation Example:** Query the DB directly or via the SQL‑Injection bug to read `password` values.
- **Remediation:** Hash passwords with a strong algorithm (e.g., `bcrypt` via `werkzeug.security.generate_password_hash`).

### 5. Insecure File Upload
- **Location:** `upload` route (`/upload`).
- **Description:** Uploaded file name is trusted; no validation, path traversal, or content‑type checks.
- **Risk Level:** **High** (OWASP‑A08 – Insecure Deserialization / Unsafe Storage).
- **Impact:** An attacker can upload a malicious script (e.g., a web‑shell) and execute it via `/uploads/<filename>`.
- **Exploitation Example:** Upload a file named `../../app.py` to overwrite application code.
- **Remediation:** Validate filename using `werkzeug.utils.secure_filename`, restrict allowed extensions, store outside the web root, and scan files.

### 6. Command Injection
- **Location:** `ping` route (`/ping?host=`).
- **Description:** User‑controlled `host` value is passed directly to `subprocess.check_output` without sanitisation.
- **Risk Level:** **Critical** (OWASP‑A01 – Injection).
- **Impact:** An attacker can execute arbitrary shell commands on the server.
- **Exploitation Example:**
  ```bash
  curl "http://127.0.0.1:5000/ping?host=127.0.0.1;cat%20/etc/passwd"
  ```
  The response includes the contents of `/etc/passwd`.
- **Remediation:** Use `subprocess.run` with a list of arguments and avoid shell=True; validate the host against a whitelist or use a library like `pythonping`.

---

## Static Analysis Results
| Tool   | Findings | Comments |
|--------|----------|----------|
| **Bandit** | 5 high‑severity issues (SQL injection, command injection, hard‑coded passwords) | Confirms manual findings. |
| **Flake8** | 2 style warnings (unused imports, missing docstrings) | Non‑security but should be cleaned. |
| **Safety** | No known vulnerable dependencies (only Flask). | Good, but keep dependencies up‑to‑date. |

---

## Conclusion & Recommendations
1. **Patch all identified vulnerabilities** – see the remediation report for secure code snippets.
2. **Adopt a security‑first development lifecycle** – integrate Bandit, Safety, and a CI pipeline.
3. **Enable HTTPS and secure headers** – use `Flask-Talisman`.
4. **Implement proper authentication/authorization** – replace hard‑coded credentials with a robust auth system.
5. **Perform regular code reviews and threat modeling**.

A full remediation plan with updated code is provided in `REMEDIATION_REPORT.md`.
