# *Author: Avinash K*
"""Flask dashboard for Network Intrusion Detection System.
Displays real‑time stats from the CSV alerts log.
"""
import os
import pandas as pd
from flask import Flask, render_template, jsonify

app = Flask(__name__)

# Path to CSV (relative to project root)
CSV_PATH = os.path.join(os.path.dirname(__file__), '..', 'logs', 'alerts.csv')

def load_alerts():
    if not os.path.exists(CSV_PATH):
        # Return empty DataFrame with expected columns
        return pd.DataFrame(columns=["timestamp", "type", "alert"])
    df = pd.read_csv(CSV_PATH, parse_dates=["timestamp"])
    return df

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    df = load_alerts()
    total_alerts = len(df)
    alerts_by_type = df['type'].value_counts().to_dict()
    return jsonify({
        "total_alerts": total_alerts,
        "alerts_by_type": alerts_by_type
    })

@app.route('/api/timeline')
def api_timeline():
    df = load_alerts()
    if df.empty:
        return jsonify([])
    # Group by minute for a simple timeline
    df['minute'] = df['timestamp'].dt.floor('T')
    timeline = df.groupby('minute').size().reset_index(name='count')
    timeline['minute'] = timeline['minute'].astype(str)
    return jsonify(timeline.to_dict(orient='records'))

if __name__ == '__main__':
    # Debug mode disabled for production; use env var if needed.
    app.run(host='0.0.0.0', port=5000)
