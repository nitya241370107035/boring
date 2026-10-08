"""
SentinelLog Agent: Process Telemetry Collector.
Captures snapshots of running processes, detects newly launched processes,
tracks parent-child trees, and redacts sensitive credentials.
"""

from datetime import datetime, timezone
import re
import time
from typing import Any
import psutil

SECRET_MASK_RE = re.compile(r"(?i)(password|token|secret|key|passwd|apikey)\s*[:=]\s*\S+")


def redact_cmdline(cmdline: str, max_chars: int = 500) -> str:
    """Masks authentication secrets and enforces character length limits."""
    if not cmdline:
        return ""
    masked = SECRET_MASK_RE.sub(r"\1=***REDACTED***", cmdline)
    if len(masked) > max_chars:
        return masked[:max_chars] + "...[TRUNCATED]"
    return masked


def snapshot() -> dict[int, dict[str, Any]]:
    """
    Captures a point-in-time snapshot of all running processes.
    Gracefully handles AccessDenied and NoSuchProcess exceptions on Windows.
    """
    out = {}
    for p in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
    ):
        try:
            info = p.info
            out[info["pid"]] = info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return out


def diff_new_processes(
    prev_snapshot: dict[int, dict[str, Any]],
    cur_snapshot: dict[int, dict[str, Any]],
    host: str = "localhost",
) -> list[dict[str, Any]]:
    """
    Compares two process snapshots and generates events for newly spawned processes.
    """
    events = []
    for pid, info in cur_snapshot.items():
        is_new = pid not in prev_snapshot or prev_snapshot[pid].get("create_time") != info.get("create_time")
        if is_new:
            parent_info = cur_snapshot.get(info.get("ppid"), {})
            cmd_list = info.get("cmdline") or []
            raw_cmd = " ".join(cmd_list) if isinstance(cmd_list, list) else str(cmd_list)
            clean_cmd = redact_cmdline(raw_cmd)

            name = (info.get("name") or "").lower()
            parent_name = (parent_info.get("name") or "").lower()
            exe = (info.get("exe") or "").lower()

            event = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "source": "agent_process",
                "host": host,
                "actor": info.get("username") or "SYSTEM",
                "action": "process_start",
                "target": clean_cmd or name,
                "name": name,
                "pid": pid,
                "ppid": info.get("ppid", 0),
                "parent_name": parent_name,
                "exe": exe,
                "cmdline": clean_cmd,
                "user": info.get("username") or "SYSTEM",
            }
            events.append(event)
    return events
