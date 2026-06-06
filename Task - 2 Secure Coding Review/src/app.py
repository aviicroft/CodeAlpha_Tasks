# Author: Avinash K
# app.py - Deliberately vulnerable Flask application

"""
This Flask app showcases common web security flaws for educational
purposes. Do NOT deploy to production.
"""

from flask import Flask, request, render_template_string, redirect, url_for, send_from_directory
import sqlite3
import os
import subprocess

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

# ------------------------------------------------------------
# Helper: simple SQLite DB (in‑memory for demo)
# ------------------------------------------------------------

def get_db():
    conn = sqlite3.connect('vuln.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialise a tiny users table with insecure password storage
def init_db():
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,   -- plain‑text password (weak storage)
            api_key TEXT     -- hard‑coded credential example
        )
    ''')
    # Insert a demo user (hard‑coded credentials)
    db.execute("INSERT OR IGNORE INTO users (username, password, api_key) VALUES ('admin', 'admin123', 'SECRET_API_KEY')")
    db.commit()

init_db()

# ------------------------------------------------------------
# 1. SQL Injection (GET parameter 'id')
# ------------------------------------------------------------
@app.route('/user')
def get_user():
    user_id = request.args.get('id')  # unsanitised input
    # Vulnerable string interpolation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cur = get_db().execute(query)
    row = cur.fetchone()
    if row:
        return f"User: {row['username']} | API Key: {row['api_key']}"
    return 'User not found', 404

# ------------------------------------------------------------
# 2. Cross‑Site Scripting (XSS) – reflected via query param
# ------------------------------------------------------------
@app.route('/search')
def search():
    q = request.args.get('q', '')
    # Directly embed user input into HTML without escaping
    html = f"<h1>Search results for: {q}</h1>"
    return html

# ------------------------------------------------------------
# 3. Hard‑coded Credentials – exposed via endpoint
# ------------------------------------------------------------
@app.route('/creds')
def creds():
    # In a real app credentials would be stored securely, not exposed!
    return "Admin credentials – username: admin / password: admin123"

# ------------------------------------------------------------
# 4. Weak Password Storage – plain‑text password check
# ------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cur = get_db().execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        if user and user['password'] == password:  # plain‑text compare
            return f"Welcome, {username}!"
        return 'Invalid credentials', 401
    # Simple login form (no CSRF protection)
    return '''
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

# ------------------------------------------------------------
# 5. Insecure File Upload – no validation, saves to static folder
# ------------------------------------------------------------
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        f = request.files['file']
        # Directly trust the filename – path traversal possible
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
        f.save(save_path)
        return f"File saved to {save_path}"
    return '''
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file"><br>
            <input type="submit" value="Upload">
        </form>
    '''

# ------------------------------------------------------------
# 6. Command Injection – unsanitised shell command
# ------------------------------------------------------------
@app.route('/ping')
def ping():
    host = request.args.get('host', '127.0.0.1')
    # Dangerous: user‑controlled input passed to shell
    result = subprocess.check_output(['ping', '-c', '1', host])
    return f"<pre>{result.decode()}</pre>"

# ------------------------------------------------------------
# Static file serving for uploaded files (insecure)
# ------------------------------------------------------------
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ------------------------------------------------------------
# Home page – index of all vulnerable endpoints
# ------------------------------------------------------------
@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Vulnerable Flask App – CodeAlpha Task 2</title>
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0f1117; color: #e2e8f0; font-family: "Segoe UI", sans-serif; min-height: 100vh; padding: 40px 20px; }
        h1 { font-size: 1.8rem; color: #f97316; margin-bottom: 6px; }
        .subtitle { color: #94a3b8; margin-bottom: 32px; font-size: 0.9rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; max-width: 960px; margin: 0 auto; }
        .card { background: #1e2330; border: 1px solid #2d3748; border-radius: 12px; padding: 20px; transition: border-color 0.2s, transform 0.2s; }
        .card:hover { border-color: #f97316; transform: translateY(-2px); }
        .badge { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 0.72rem; font-weight: 700; margin-bottom: 10px; }
        .critical { background: #7f1d1d; color: #fca5a5; }
        .high { background: #78350f; color: #fcd34d; }
        h2 { font-size: 1rem; margin-bottom: 6px; color: #f1f5f9; }
        p { font-size: 0.82rem; color: #94a3b8; margin-bottom: 14px; line-height: 1.5; }
        a.btn { display: inline-block; background: #f97316; color: #0f1117; padding: 6px 16px; border-radius: 6px; text-decoration: none; font-size: 0.82rem; font-weight: 700; }
        a.btn:hover { background: #ea580c; }
        .header { text-align: center; margin-bottom: 36px; }
        .warning { background: #1a1a2e; border: 1px solid #f97316; border-radius: 8px; padding: 12px 20px; text-align: center; margin-bottom: 28px; font-size: 0.82rem; color: #fb923c; max-width: 960px; margin-left: auto; margin-right: auto; margin-bottom: 28px; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>&#128272; Vulnerable Flask App</h1>
        <p class="subtitle">CodeAlpha Task 2 &mdash; Secure Coding Review &amp; Vulnerability Assessment</p>
      </div>
      <div class="warning">&#9888;&#65039; This app is <strong>intentionally vulnerable</strong> for educational purposes. Do NOT deploy to production.</div>
      <div class="grid">
        <div class="card">
          <span class="badge critical">CRITICAL &bull; OWASP A01</span>
          <h2>1. SQL Injection</h2>
          <p>User-controlled <code>id</code> parameter is interpolated directly into the SQL query string.</p>
          <a class="btn" href="/user?id=1">Test /user?id=1</a>
        </div>
        <div class="card">
          <span class="badge high">HIGH &bull; OWASP A03</span>
          <h2>2. Cross-Site Scripting (XSS)</h2>
          <p>Query param <code>q</code> is reflected raw into HTML without escaping, allowing script injection.</p>
          <a class="btn" href="/search?q=<script>alert('XSS')</script>">Test /search XSS</a>
        </div>
        <div class="card">
          <span class="badge critical">CRITICAL &bull; OWASP A02</span>
          <h2>3. Hard-coded Credentials</h2>
          <p>Admin username and password are hard-coded and exposed via a public endpoint.</p>
          <a class="btn" href="/creds">Test /creds</a>
        </div>
        <div class="card">
          <span class="badge high">HIGH &bull; OWASP A02</span>
          <h2>4. Weak Password Storage</h2>
          <p>Passwords are stored and compared in plain text with no hashing or salting.</p>
          <a class="btn" href="/login">Test /login</a>
        </div>
        <div class="card">
          <span class="badge high">HIGH &bull; OWASP A04</span>
          <h2>5. Insecure File Upload</h2>
          <p>Uploaded filenames are trusted blindly &mdash; no type check, no sanitisation, path traversal possible.</p>
          <a class="btn" href="/upload">Test /upload</a>
        </div>
        <div class="card">
          <span class="badge critical">CRITICAL &bull; OWASP A01</span>
          <h2>6. Command Injection</h2>
          <p>User-supplied <code>host</code> value is passed unsanitised to <code>subprocess</code>, enabling OS command execution.</p>
          <a class="btn" href="/ping?host=127.0.0.1">Test /ping</a>
        </div>
      </div>
    </body>
    </html>
    '''

if __name__ == '__main__':
    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
