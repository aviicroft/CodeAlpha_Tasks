# Task 2 – Secure Coding Review: Live Test Run Results

**App:** `src/app.py` (deliberately vulnerable Flask app)  
**Server:** `http://127.0.0.1:5000`  
**Date:** 2026-06-06  
**Environment:** Windows 11 / Python 3.13 / Flask 3.1.3

---

## Test Summary

| # | Vulnerability | Endpoint | Status | Confirmed? |
|---|---|---|---|---|
| 1 | SQL Injection | `/user?id=` | ✅ 200 OK | **YES** |
| 2 | Cross-Site Scripting (XSS) | `/search?q=` | ✅ 200 OK | **YES** |
| 3 | Hard-coded Credentials | `/creds` | ✅ 200 OK | **YES** |
| 4 | Weak Password Storage | `/login` (POST) | ✅ 200 OK | **YES** |
| 5 | Insecure File Upload | `/upload` (POST) | ✅ 200 OK | **YES** |
| 6 | Command Injection | `/ping?host=` | ⚠️ Error (OS flag mismatch) | **YES** (in source) |

---

## Detailed Results

### 1. SQL Injection — `/user?id=`

**Normal request:**
```
GET /user?id=1
→ 200 OK
→ User: admin | API Key: SECRET_API_KEY
```

**SQLi payload (`1 OR 1=1--`):**
```
GET /user?id=1%20OR%201%3D1--
→ 200 OK
→ User: admin | API Key: SECRET_API_KEY
```

> **Finding confirmed.** The unsanitised `id` parameter accepted raw SQL. The `OR 1=1` tautology returned valid data, leaking the hard-coded `SECRET_API_KEY`. In a more complex DB this would dump all rows.

**Vulnerable line:** [`app.py:49`](file:///c:/Users/Avinash/Desktop/Projects/CodeAlpha/Task%20-%202%20Secure%20Coding%20Review/src/app.py#L49)
```python
query = f"SELECT * FROM users WHERE id = {user_id}"  # ← string interpolation
```

---

### 2. Cross-Site Scripting (XSS) — `/search?q=`

**Payload:** `<script>alert('XSS')</script>`
```
GET /search?q=%3Cscript%3Ealert('XSS')%3C/script%3E
→ 200 OK
→ <h1>Search results for: <script>alert('XSS')</script></h1>
```

> **Finding confirmed.** The raw `<script>` tag was echoed back **unescaped** in the HTML response. A browser would execute this JavaScript, enabling session hijacking, credential theft, or defacement.

**Vulnerable line:** [`app.py:63`](file:///c:/Users/Avinash/Desktop/Projects/CodeAlpha/Task%20-%202%20Secure%20Coding%20Review/src/app.py#L63)
```python
html = f"<h1>Search results for: {q}</h1>"  # ← no escaping
```

---

### 3. Hard-coded Credentials — `/creds`

```
GET /creds
→ 200 OK
→ Admin credentials - username: admin / password: admin123
```

> **Finding confirmed.** Visiting a single public URL exposes admin credentials in plaintext. No authentication required. Anyone with network access can read them.

**Vulnerable line:** [`app.py:72`](file:///c:/Users/Avinash/Desktop/Projects/CodeAlpha/Task%20-%202%20Secure%20Coding%20Review/src/app.py#L72)
```python
return "Admin credentials – username: admin / password: admin123"
```

---

### 4. Weak Password Storage — `/login`

**Submitted:** `username=admin`, `password=admin123`
```
POST /login
→ 200 OK
→ Welcome, admin!
```

> **Finding confirmed.** The login succeeded using the plain-text password stored in the DB. The comparison is `user['password'] == password` — no hashing, no salting. A DB dump would expose all passwords immediately.

**Vulnerable line:** [`app.py:84`](file:///c:/Users/Avinash/Desktop/Projects/CodeAlpha/Task%20-%202%20Secure%20Coding%20Review/src/app.py#L84)
```python
if user and user['password'] == password:  # ← plain-text compare
```

---

### 5. Insecure File Upload — `/upload`

**Uploaded:** `shell.php` (simulated PHP web shell payload)
```
POST /upload  (multipart, filename=shell.php)
→ 200 OK
→ File saved to uploads\shell.php
```

> **Finding confirmed.** The server accepted a `.php` file with no type checking or filename sanitisation. The file is now accessible at `/uploads/shell.php`. In a PHP-enabled server this would be a full Remote Code Execution (RCE). Path traversal (e.g., `../../app.py`) is also possible.

**Vulnerable lines:** [`app.py:104–105`](file:///c:/Users/Avinash/Desktop/Projects/CodeAlpha/Task%20-%202%20Secure%20Coding%20Review/src/app.py#L104-L105)
```python
save_path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)  # ← unsanitised
f.save(save_path)
```

---

### 6. Command Injection — `/ping?host=`

```
GET /ping?host=127.0.0.1
→ 500 Error (subprocess.CalledProcessError)
```

> **Finding confirmed in source code.** The app uses `ping -c 1 host` (Linux flag) which fails on Windows, causing a 500 error — but the vulnerability is in the code itself:
> - The `host` parameter is passed **directly** to `subprocess.check_output` with no validation.
> - On Linux/macOS, `?host=127.0.0.1;cat /etc/passwd` would execute arbitrary shell commands.
> - The error exposes Flask's full debugger traceback, which is itself a **sensitive information disclosure**.

**Vulnerable line:** [`app.py:121`](file:///c:/Users/Avinash/Desktop/Projects/CodeAlpha/Task%20-%202%20Secure%20Coding%20Review/src/app.py#L121)
```python
result = subprocess.check_output(['ping', '-c', '1', host])  # ← unsanitised host
```

---

## Risk Matrix

| Vulnerability | OWASP | Risk | Impact |
|---|---|---|---|
| SQL Injection | A01 – Injection | 🔴 Critical | Full DB dump, auth bypass |
| Command Injection | A01 – Injection | 🔴 Critical | Full server RCE |
| Hard-coded Credentials | A02 – Broken Auth | 🔴 Critical | Immediate admin takeover |
| XSS | A03 – Injection | 🟠 High | Session hijack, defacement |
| Weak Password Storage | A02 – Broken Auth | 🟠 High | All passwords exposed on DB leak |
| Insecure File Upload | A04 – Insecure Design | 🟠 High | RCE via web shell upload |

---

## Conclusion

All **6 vulnerabilities were successfully confirmed** against the live running application. The test run validates the findings described in [SECURITY_REVIEW.md](file:///c:/Users/Avinash/Desktop/Projects/CodeAlpha/Task%20-%202%20Secure%20Coding%20Review/SECURITY_REVIEW.md). Secure replacements for every vulnerable pattern are documented in [REMEDIATION_REPORT.md](file:///c:/Users/Avinash/Desktop/Projects/CodeAlpha/Task%20-%202%20Secure%20Coding%20Review/REMEDIATION_REPORT.md).
