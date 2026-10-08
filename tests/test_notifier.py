import os
import pytest
import requests
from api.notifier import dispatch_alert, send_telegram_alert, send_windows_toast


def test_telegram_without_credentials():
    # When tokens are not in env, should gracefully return False without crashing
    res = send_telegram_alert(
        severity="CRITICAL",
        score=95.0,
        host="test-host",
        rule_id="EP-PROC-001",
        target="powershell.exe",
        reasons=["Office spawning powershell"],
    )
    assert res is False


def test_telegram_with_mock_credentials(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "mock-token-123")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "mock-chat-456")

    class MockResponse:
        status_code = 200

    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: MockResponse())

    res = send_telegram_alert(
        severity="CRITICAL",
        score=90.0,
        host="test-host",
        rule_id="EP-PROC-001",
        target="powershell.exe",
        reasons=["Office spawning powershell"],
    )
    assert res is True


def test_windows_toast():
    res = send_windows_toast("Test Alert", "Sample Message")
    assert res is True


def test_dispatch_alert_filtering():
    # Low severity alert should not spam notifications
    dispatch_alert(
        severity="LOW",
        score=20.0,
        host="test-host",
        rule_id="INFO-001",
        target="get /",
        reasons=["Normal traffic"],
    )
    # Passes without exceptions
