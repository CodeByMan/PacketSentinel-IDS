# dashboard.py
# Flask web server backing the live dashboard. Endpoints:
#   GET /              – the dashboard page
#   GET /api/alerts    – current alerts as JSON (newest first)
#   GET /api/stats     – live traffic stats + alert breakdowns for the charts
#   GET /api/export    – download the full alert history as a CSV file
#
# The page polls /api/alerts and /api/stats every couple of seconds and redraws
# the table and charts client-side, so it updates without a full reload.

import csv
import io
from collections import Counter

from flask import Flask, jsonify, render_template, Response

from alerts import alert_store, alert_lock
from stats import stats
from config import config

app = Flask(__name__)

# Set by start_dashboard() so the export endpoint can read full DB history.
_database = None


def _csv_cell(value):
    """Prevent spreadsheet formula execution when exported data is opened."""
    text = str(value or "")
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def get_alerts():
    """All in-memory alerts, newest first."""
    with alert_lock:
        data = list(reversed(alert_store))
    return jsonify(data)


@app.route("/api/stats")
def get_stats():
    """
    Live traffic stats plus aggregate breakdowns the dashboard charts need:
    counts per severity, per attack type, and the busiest source IPs.
    """
    with alert_lock:
        alerts = list(alert_store)

    severity = Counter(a["severity"] for a in alerts)
    by_type = Counter(a["attack_type"] for a in alerts)
    top_ips = Counter(a["attacker_ip"] for a in alerts).most_common(5)

    return jsonify({
        "traffic": stats.snapshot(),
        "total_alerts": len(alerts),
        "severity": severity,
        "by_type": by_type,
        "top_attackers": top_ips,
    })


@app.route("/api/export")
def export_csv():
    """Download every recorded alert as a CSV (from the DB when available)."""
    if _database is not None:
        rows = _database.recent(limit=100000)
    else:
        with alert_lock:
            rows = list(reversed(alert_store))

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["timestamp", "attacker_ip", "attack_type", "severity", "details"])
    for r in rows:
        writer.writerow([_csv_cell(r.get(column, "")) for column in (
            "timestamp", "attacker_ip", "attack_type", "severity", "details",
        )])

    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=ids_alerts.csv"},
    )


def start_dashboard(host=None, port=None, database=None):
    """Start the Flask dev server (reloader off so it works inside a thread)."""
    global _database
    _database = database
    selected_host = config.dashboard_host if host is None else host
    selected_port = config.dashboard_port if port is None else port
    if selected_host not in {"127.0.0.1", "localhost", "0.0.0.0"}:
        raise ValueError("dashboard host must be localhost or 0.0.0.0")
    if isinstance(selected_port, bool) or not isinstance(selected_port, int) or not 1 <= selected_port <= 65535:
        raise ValueError("dashboard port must be between 1 and 65535")
    if selected_host == "0.0.0.0":
        print("!" * 72)
        print("WARNING: dashboard has no authentication and is exposed to the LAN.")
        print("Use 127.0.0.1 unless broad binding is explicitly required.")
        print("!" * 72)
    app.run(
        host=selected_host,
        port=selected_port,
        debug=False,
        use_reloader=False,
    )
