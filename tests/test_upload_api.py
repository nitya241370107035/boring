"""
SentinelLog API: Tests for Real-World Log Upload and Sample Ingestion Endpoints.
"""

from io import BytesIO
from fastapi.testclient import TestClient
import pytest

from api.db import init_db
from api.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_list_sample_logs():
    resp = client.get("/api/sample-logs")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 3
    sample_ids = [s["id"] for s in data]
    assert "apache_web_attacks" in sample_ids
    assert "nginx_production_traffic" in sample_ids


def test_analyze_sample_log():
    resp = client.post("/api/sample-logs/apache_web_attacks/analyze")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["parsed_rows"] > 0
    assert data["total_attacks"] > 0
    assert "severity_distribution" in data
    assert "top_ips" in data
    assert "events" in data


def test_upload_log_raw_json():
    raw_log = (
        '203.0.113.1 - - [10/Oct/2026:14:00:00 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0"\n'
        '198.51.100.9 - - [10/Oct/2026:14:00:05 +0000] "GET /products.php?id=1%27%20OR%201=1-- HTTP/1.1" 200 1024 "-" "sqlmap/1.7"\n'
    )
    resp = client.post(
        "/api/upload-log-raw",
        json={"content": raw_log, "filename": "test.log", "ingest_to_db": False},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["parsed_rows"] == 2
    assert data["total_attacks"] == 1


def test_upload_log_file_multipart():
    raw_log = (
        '198.51.100.12 - - [10/Oct/2026:14:01:00 +0000] "GET /../../etc/passwd HTTP/1.1" 404 196 "-" "curl/7.88.1"\n'
    )
    files = {"file": ("access.log", BytesIO(raw_log.encode("utf-8")), "text/plain")}
    resp = client.post("/api/upload-log", files=files, data={"ingest_to_db": "false"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["parsed_rows"] == 1
    assert data["total_attacks"] == 1
    assert data["events"][0]["label"] in ("path_traversal", "traversal")


def test_upload_log_with_db_ingest():
    raw_log = (
        '198.51.100.99 - - [10/Oct/2026:14:02:00 +0000] "GET /products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1" 200 4096 "-" "sqlmap/1.7"\n'
    )
    resp = client.post(
        "/api/upload-log-raw",
        json={"content": raw_log, "filename": "db_test.log", "ingest_to_db": True},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["ingest_to_db"] is True
    assert data["events_ingested"] == 1
    assert data["alerts_created"] >= 1

