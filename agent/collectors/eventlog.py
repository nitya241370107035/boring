"""
SentinelLog Agent: Windows Security Event Log Collector.
Queries the Security log for Event IDs 4624, 4625, 4688, 4720, 4732 via wevtutil XML.
Includes graceful error handling and non-elevated permission fallbacks.
"""

from datetime import datetime, timezone
import subprocess
from typing import Any
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def query_security_events(
    channel: str = "Security",
    event_ids: tuple[int, ...] = (4624, 4625, 4688, 4720, 4732),
    since_seconds: int = 30,
    count: int = 200,
    host: str = "localhost",
) -> list[dict[str, Any]]:
    """
    Executes wevtutil querying Windows Security channel and parses XML event nodes.
    Returns normalized telemetry dictionaries.
    """
    ids_query = " or ".join(f"EventID={i}" for i in event_ids)
    ms_limit = since_seconds * 1000
    xpath = f"*[System[({ids_query}) and TimeCreated[timediff(@SystemTime) <= {ms_limit}]]]"

    cmd = ["wevtutil", "qe", channel, f"/q:{xpath}", f"/c:{count}", "/rd:true", "/f:xml"]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if res.returncode != 0 or not res.stdout.strip():
            return []
        raw_xml = "<Events>" + res.stdout + "</Events>"
        root = ET.fromstring(raw_xml)
    except Exception:
        # Gracefully handle missing privileges or XML parsing failures
        return []

    events = []
    for ev in root.findall("e:Event", NS):
        try:
            sys_node = ev.find("e:System", NS)
            if sys_node is None:
                continue
            eid_node = sys_node.find("e:EventID", NS)
            eid = int(eid_node.text) if eid_node is not None and eid_node.text else 0

            time_node = sys_node.find("e:TimeCreated", NS)
            ts = time_node.get("SystemTime") if time_node is not None else datetime.now(timezone.utc).isoformat()

            data_map = {}
            data_nodes = ev.findall("e:EventData/e:Data", NS)
            for d in data_nodes:
                d_name = d.get("Name")
                if d_name:
                    data_map[d_name] = d.text or ""

            action_name = "eventlog_entry"
            if eid == 4625:
                action_name = "logon_failed"
            elif eid == 4624:
                action_name = "logon_success"
            elif eid == 4688:
                action_name = "process_created_audit"
            elif eid == 4720:
                action_name = "user_account_created"
            elif eid == 4732:
                action_name = "group_member_added"

            events.append({
                "ts": ts,
                "source": "agent_auth",
                "host": host,
                "actor": data_map.get("TargetUserName") or data_map.get("SubjectUserName") or "SYSTEM",
                "action": action_name,
                "target": f"EventID:{eid}",
                "event_id": eid,
                "attrs": data_map,
            })
        except Exception:
            continue

    return events
