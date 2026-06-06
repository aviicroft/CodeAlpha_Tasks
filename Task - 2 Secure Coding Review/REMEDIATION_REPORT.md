# Remediation Report

**Project:** Secure Coding Review and Vulnerability Assessment
**Date:** 2026‑06‑06

This document provides **secure code replacements** for each vulnerability identified in the vulnerable Flask application (`src/app.py`). For each issue we show the original (vulnerable) snippet and the revised (secure) implementation, followed by a brief rationale.

---

## 1. SQL Injection
### Vulnerable Code (original)
```python
@app.route('/user')
def get_user():
    user_id = request.args.get('id')  # unsanitised input
    # Vulnerable string interpolation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cur = get_db().execute(query)
    row = cur.fetchone()
    ...
```
### Secure Code (remediated)
```python
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # Use a parameterised query to avoid injection
    query = "SELECT * FROM users WHERE id = ?"
    cur = get_db().execute(query, (user_id,))
    row = cur.fetchone()
    ...
```
**Why:** Parameterised queries let the DB driver safely escape user input, preventing arbitrary SQL execution.

---

## 2. Cross‑Site Scripting (XSS)
### Vulnerable Code
```python
@app.route('/search')
def search():
    q = request.args.get('q', '')
    # Directly embed user input into HTML without escaping
    html = f"<h1>Search results for: {q}</h1>"
    return html
```
### Secure Code
```python
from markupsafe import escape

@app.route('/search')
def search():
    q = request.args.get('q', '')
    # Escape user‑provided data before embedding in HTML
    safe_q = escape(q)
    html = f"<h1>Search results for: {safe_q}</h1>"
    return html
```
**Why:** `escape` converts `<`, `>`, `&`, `"`, and `'` to HTML entities, neutralising injected scripts.

---

## 3. Hard‑coded Credentials
### Vulnerable Code
```python
@app.route('/creds')
def creds():
    # In a real app credentials would be stored securely, not exposed!
    return "Admin credentials – username: admin / password: admin123"
```
### Secure Code
```python
import os

@app.route('/creds')
def creds():
    # Credentials are loaded from environment variables (or a secret manager)
    admin_user = os.getenv('ADMIN_USER')
    admin_pass = os.getenv('ADMIN_PASS')
    if not admin_user or not admin_pass:
        return "Credentials not configured", 500
    # Do NOT expose them via an endpoint – this route is removed in production.
    return "Endpoint disabled", 404
```
**Why:** Credentials are no longer hard‑coded; they are read from environment variables and the endpoint is disabled to avoid accidental exposure.

---

## 4. Weak Password Storage
### Vulnerable Code (login check)
```python
if user and user['password'] == password:  # plain‑text compare
    return f"Welcome, {username}!"
```
### Secure Code
```python
from werkzeug.security import check_password_hash, generate_password_hash

# On user registration (not shown) store a hashed password:
# hashed = generate_password_hash(password)
# db.execute('INSERT ...', (hashed,))

if user and check_password_hash(user['password'], password):
    return f"Welcome, {username}!"
```
**Why:** Passwords are stored as a bcrypt hash, making it computationally infeasible for an attacker to recover the original password from the DB.

---

## 5. Insecure File Upload
### Vulnerable Code
```python
f = request.files['file']
# Directly trust the filename – path traversal possible
save_path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
f.save(save_path)
```
### Secure Code
```python
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if request.method == 'POST':
    f = request.files['file']
    if f and allowed_file(f.filename):
        filename = secure_filename(f.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        f.save(save_path)
        return f"File saved to {save_path}"
    return "Invalid file type", 400
```
**Why:** `secure_filename` removes dangerous characters, and the whitelist enforces only expected file types, mitigating path traversal and arbitrary file execution.

---

## 6. Command Injection
### Vulnerable Code
```python
host = request.args.get('host', '127.0.0.1')
result = subprocess.check_output(['ping', '-c', '1', host])
```
### Secure Code
```python
import ipaddress

host = request.args.get('host', '127.0.0.1')
try:
    # Validate that the host is a valid IP address to limit input surface
    ipaddress.ip_address(host)
except ValueError:
    return "Invalid host", 400

# Use subprocess.run with a list to avoid shell interpretation
result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, check=True)
return f"<pre>{result.stdout}</pre>"
```
**Why:** Input validation ensures only legitimate IP addresses are accepted, and using a list of arguments prevents shell injection.

---

## Summary of Remediation Steps
1. Replace string‑interpolated SQL with parameterised queries.
2. Escape all user‑generated content before rendering HTML.
3. Remove any endpoint that discloses credentials; load secrets from environment variables.
4. Store passwords using a strong hash (`bcrypt` via Werkzeug).
5. Validate file uploads, sanitize filenames, and restrict extensions.
6. Validate host input for the ping feature and avoid shell‑level execution.

All changes have been applied to `src/app.py`. The updated file now passes **Bandit** (no high‑severity issues) and **Safety** (no vulnerable dependencies).
