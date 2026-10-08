import pytest
from fastapi.testclient import TestClient
from api.main import app
from api.db import init_db

client = TestClient(app)
VALID_API_KEY = "sentinel-secret-key-1"


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def test_health_check():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["db_connected"] is True


def test_unauthorized_access():
    # Attempting POST without X-API-Key header
    resp = client.post("/ingest/agent", json={"events": []})
    assert resp.status_code == 401
    assert "Unauthorized" in resp.json()["detail"]


def test_ingest_agent_and_alert_generation():
    headers = {"X-API-Key": VALID_API_KEY}
    payload = {
        "events": [
            {
                "action": "process_start",
                "host": "test-workstation",
                "name": "powershell.exe",
                "parent_name": "winword.exe",
                "rule_hits": [
                    {"id": "EP-PROC-001", "name": "Office spawning shell", "severity": 85}
                ],
                "attrs": {"cmdline": "powershell.exe -enc ..."},
            }
        ]
    }

    resp = client.post("/ingest/agent", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["received"] == 1
    assert data["new_alerts"] == 1

    # Verify alert appears in /alerts
    alerts_resp = client.get("/alerts")
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    assert len(alerts) > 0
    target_alert = alerts[0]
    assert target_alert["rule_id"] == "EP-PROC-001"
    assert target_alert["score"] >= 50.0
    assert target_alert["severity"] == "MEDIUM"


def test_alert_suppression():
    headers = {"X-API-Key": VALID_API_KEY}
    payload = {
        "events": [
            {
                "action": "process_start",
                "host": "test-workstation-2",
                "name": "cmd.exe",
                "target": "cmd.exe",
                "rule_hits": [
                    {"id": "EP-PROC-001", "name": "Office spawning shell", "severity": 85}
                ],
            }
        ]
    }

    # First send: creates new alert
    r1 = client.post("/ingest/agent", json=payload, headers=headers)
    assert r1.json()["new_alerts"] == 1

    # Immediate second send of identical alert: should be suppressed (0 new alerts)
    r2 = client.post("/ingest/agent", json=payload, headers=headers)
    assert r2.json()["new_alerts"] == 0


def test_update_alert_patch():
    # Fetch existing alerts
    alerts = client.get("/alerts").json()
    if alerts:
        a_id = alerts[0]["alert_id"]
        patch_resp = client.patch(
            f"/alerts/{a_id}",
            json={"status": "acknowledged", "comment": "Analyst reviewed"},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["new_status"] == "acknowledged"


def test_metrics_endpoint():
    resp = client.get("/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_events_ingested" in data
    assert "open_security_alerts" in data
