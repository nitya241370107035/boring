from pathlib import Path
import tempfile
import pytest
import requests
from agent.sender import Sender


def test_sender_buffer_and_flush(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_buffer.db"
        sender = Sender(api_url="http://mock-api:8000/ingest", api_key="secret", db_path=db_path)

        # Enqueue events
        sender.enqueue({"action": "test_event_1", "val": 100})
        sender.enqueue({"action": "test_event_2", "val": 200})
        assert sender.pending_count() == 2

        # Mock successful response
        class MockResponse:
            status_code = 200

        monkeypatch.setattr(requests, "post", lambda *args, **kwargs: MockResponse())

        sent = sender.flush(batch_size=10)
        assert sent == 2
        assert sender.pending_count() == 0


def test_sender_network_failure_keeps_buffer(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_buffer.db"
        sender = Sender(api_url="http://mock-api:8000/ingest", api_key="secret", db_path=db_path)

        sender.enqueue({"action": "offline_event"})
        assert sender.pending_count() == 1

        # Mock network failure
        def mock_failed_post(*args, **kwargs):
            raise requests.ConnectionError("Host unreachable")

        monkeypatch.setattr(requests, "post", mock_failed_post)

        sent = sender.flush(batch_size=10)
        assert sent == 0
        # Remains safely preserved in SQLite buffer
        assert sender.pending_count() == 1
