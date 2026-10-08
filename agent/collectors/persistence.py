"""
SentinelLog Agent: Persistence Mechanism Telemetry Collector.
Audits Windows Registry Run/RunOnce keys, Startup directories, and scheduled tasks
to detect unauthorized persistence footholds.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any

try:
    import winreg
except ImportError:
    winreg = None  # Non-Windows fallback

RUN_KEYS = [
    ("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ("HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
]


def check_registry_persistence(host: str = "localhost") -> list[dict[str, Any]]:
    """Inspects Windows Registry Run and RunOnce keys."""
    if not winreg:
        return []

    events = []
    hive_map = {
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
    }

    for hive_str, subkey in RUN_KEYS:
        hive = hive_map[hive_str]
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                num_values = winreg.QueryInfoKey(key)[1]
                for i in range(num_values):
                    name, val, _ = winreg.EnumValue(key, i)
                    val_str = str(val).lower()
                    is_suspicious = (
                        "\\appdata\\" in val_str
                        or "\\temp\\" in val_str
                        or "powershell" in val_str
                        or "wscript" in val_str
                    )

                    events.append({
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "source": "agent_persist",
                        "host": host,
                        "actor": "registry_audit",
                        "action": "persistence_entry",
                        "target": f"{hive_str}\\{subkey}\\{name}",
                        "name": name,
                        "command": str(val),
                        "is_suspicious": is_suspicious,
                    })
        except Exception:
            continue

    return events


def check_startup_folder(host: str = "localhost") -> list[dict[str, Any]]:
    """Inspects files present in the current user Startup folder."""
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return []

    startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    if not startup_dir.exists():
        return []

    events = []
    try:
        for item in startup_dir.iterdir():
            if item.is_file():
                events.append({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "source": "agent_persist",
                    "host": host,
                    "actor": "startup_folder_audit",
                    "action": "startup_file",
                    "target": str(item.resolve()),
                    "name": item.name,
                })
    except Exception:
        pass

    return events
