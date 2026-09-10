import csv
import io
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dashboard
from alerts import alert_lock, alert_store


def setup_function():
    dashboard._database = None
    with alert_lock:
        alert_store.clear()


def test_dashboard_endpoints_with_empty_and_populated_state():
    client = dashboard.app.test_client()
    assert client.get("/").status_code == 200
    assert client.get("/api/alerts").get_json() == []
    assert client.get("/api/stats").get_json()["total_alerts"] == 0

    with alert_lock:
        alert_store.append({
            "timestamp": "2026-01-01 00:00:00", "attacker_ip": "192.0.2.1",
            "attack_type": "Port Scan", "severity": "MEDIUM",
            "details": "=unsafe", "mitre": "T1046 Network Service Discovery",
        })
    assert len(client.get("/api/alerts").get_json()) == 1
    assert client.get("/api/stats").get_json()["severity"] == {"MEDIUM": 1}

    response = client.get("/api/export")
    assert response.status_code == 200
    rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
    assert rows[0] == ["timestamp", "attacker_ip", "attack_type", "severity", "details"]
    assert rows[1][-1] == "'=unsafe"


def test_dashboard_uses_text_nodes_for_alert_fields():
    template = Path(__file__).parents[1] / "templates" / "index.html"
    source = template.read_text(encoding="utf-8")

    assert "tbody.innerHTML = rows.map" not in source
    assert "cell.textContent" in source
    assert "tbody.replaceChildren" in source


def test_dashboard_rejects_non_loopback_binding():
    try:
        dashboard.start_dashboard(host="0.0.0.0", port=5000)
    except ValueError as exc:
        assert "loopback" in str(exc).lower()
    else:
        raise AssertionError("Unauthenticated dashboard accepted a non-loopback bind")
