from pathlib import Path
import pytest
from agent.collectors.network import active_connections
from agent.collectors.processes import diff_new_processes, redact_cmdline, snapshot


def test_redact_cmdline():
    raw_cmd = "mytool.exe --user admin --password=SuperSecretPassword123! --host example.com"
    redacted = redact_cmdline(raw_cmd)
    assert "SuperSecretPassword123!" not in redacted
    assert "password=***REDACTED***" in redacted

    # Long command line truncation check
    huge_cmd = "a" * 800
    truncated = redact_cmdline(huge_cmd, max_chars=500)
    assert len(truncated) <= 520
    assert "...[TRUNCATED]" in truncated


def test_process_diffing():
    prev = {
        100: {"pid": 100, "ppid": 1, "name": "explorer.exe", "create_time": 1000.0}
    }
    cur = {
        100: {"pid": 100, "ppid": 1, "name": "explorer.exe", "create_time": 1000.0},
        101: {
            "pid": 101,
            "ppid": 100,
            "name": "powershell.exe",
            "exe": "C:\\Windows\\System32\\powershell.exe",
            "cmdline": ["powershell.exe", "-NoProfile"],
            "username": "tester",
            "create_time": 1005.0,
        },
    }

    events = diff_new_processes(prev, cur, host="test-host")
    assert len(events) == 1
    ev = events[0]
    assert ev["action"] == "process_start"
    assert ev["name"] == "powershell.exe"
    assert ev["parent_name"] == "explorer.exe"
    assert ev["pid"] == 101
    assert ev["ppid"] == 100


def test_snapshot_non_empty():
    snap = snapshot()
    assert len(snap) > 0
    # Current python process should exist in snapshot
    assert any(info.get("name") and "python" in info["name"].lower() for info in snap.values())
