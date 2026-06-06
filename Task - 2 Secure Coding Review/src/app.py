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

if __name__ == '__main__':
    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
