"""
SentinelLog Agent: Network Telemetry Collector.
Inspects active established network sockets and maps connections to owning process names.
"""

from datetime import datetime, timezone
from typing import Any
import psutil


def active_connections(
    proc_map: dict[int, str] | None = None,
    host: str = "localhost",
) -> list[dict[str, Any]]:
    """
    Captures established TCP network connections and associates them with process names.
    Gracefully handles Windows permission boundaries.
    """
    events = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return []

    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
            continue

        pid = c.pid
        proc_name = "unknown"
        if proc_map and pid in proc_map:
            proc_name = proc_map[pid]
        elif pid:
            try:
                proc_name = psutil.Process(pid).name().lower()
            except Exception:
                proc_name = "unknown"

        remote_ip = c.raddr.ip
        remote_port = c.raddr.port
        laddr_str = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "0.0.0.0:0"
        raddr_str = f"{remote_ip}:{remote_port}"

        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "source": "agent_net",
            "host": host,
            "actor": f"{proc_name} (pid:{pid})",
            "action": "conn_open",
            "target": raddr_str,
            "pid": pid,
            "process": proc_name,
            "laddr": laddr_str,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
        }
        events.append(event)

    return events
