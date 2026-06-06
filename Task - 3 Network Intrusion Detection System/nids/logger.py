# *Author: Avinash K*
"""Simple CSV logger for NIDS alerts.
Writes alerts to the path defined in config.yaml.
Optionally can send email alerts (disabled by default)."""
import csv
import os
import threading
from datetime import datetime
from .config_loader import load_config

CONFIG = load_config()
CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", CONFIG['logging']['csv_path'])

# Ensure directory exists
os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)

_lock = threading.Lock()

def _ensure_header():
    if not os.path.exists(CSV_PATH):
        with open(CSV_PATH, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'category', 'message'])

def log_alert(category: str, message: str):
    """Append an alert entry to the CSV log.
    Args:
        category: Short label for the type of alert (e.g., 'Port Scan').
        message: Human‑readable description.
    """
    _ensure_header()
    timestamp = datetime.utcnow().isoformat() + 'Z'
    with _lock:
        with open(CSV_PATH, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, category, message])
    # Email handling could be added here based on CONFIG['email']['enabled']
