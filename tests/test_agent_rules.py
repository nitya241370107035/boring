from pathlib import Path
import pytest
from agent.rules import EndpointRuleEngine

RULES_PATH = Path("rules/endpoint_rules.yaml")


@pytest.fixture
def engine():
    return EndpointRuleEngine(RULES_PATH)


def test_office_spawning_powershell(engine):
    event = {
        "action": "process_start",
        "name": "powershell.exe",
        "parent_name": "winword.exe",
        "cmdline": "powershell.exe -NoProfile",
        "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    }
    matches, max_sev = engine.evaluate_event(event)
    assert any(m["id"] == "EP-PROC-001" for m in matches)
    assert max_sev >= 85


def test_encoded_powershell(engine):
    event = {
        "action": "process_start",
        "name": "powershell.exe",
        "parent_name": "explorer.exe",
        "cmdline": "powershell.exe -NoProfile -enc ZQBjAGgAbwAgACIAdABlAHMAdAAiAA==",
        "exe": "C:\\Windows\\System32\\powershell.exe",
    }
    matches, max_sev = engine.evaluate_event(event)
    assert any(m["id"] == "EP-PROC-002" for m in matches)
    assert max_sev >= 80


def test_rare_c2_port(engine):
    event = {
        "action": "conn_open",
        "remote_ip": "198.51.100.4",
        "remote_port": 4444,
        "process": "cmd.exe",
    }
    matches, max_sev = engine.evaluate_event(event)
    assert any(m["id"] == "EP-NET-001" for m in matches)
    assert max_sev >= 55


def test_file_churn_detection(engine):
    event = {
        "action": "file_churn",
        "target": "C:\\Users\\test\\Desktop\\doc1.locked",
        "count": 55,
    }
    matches, max_sev = engine.evaluate_event(event)
    assert any(m["id"] == "EP-FILE-001" for m in matches)
    assert max_sev >= 90


def test_failed_logon_burst(engine):
    # Send 5 failed logon events in sequence
    for i in range(4):
        engine.evaluate_event({"action": "logon_failed", "actor": "admin"})

    # 5th event should trigger EP-AUTH-001
    matches, max_sev = engine.evaluate_event({"action": "logon_failed", "actor": "admin"})
    assert any(m["id"] == "EP-AUTH-001" for m in matches)
    assert max_sev >= 70
