"""
SentinelLog Agent: Local Rule Engine.
Evaluates local host telemetry against rules/endpoint_rules.yaml,
tagging matched rule signatures and MITRE ATT&CK technique IDs.
"""

from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import re
import time
from typing import Any
import yaml


class EndpointRuleEngine:
    """Evaluates host events against endpoint detection signatures."""

    def __init__(self, rules_path: str | Path = "rules/endpoint_rules.yaml"):
        self.rules_path = Path(rules_path)
        self.rules = self._load_rules()
        self.event_history = deque()  # for temporal rules like failed logon bursts

    def _load_rules(self) -> list[dict[str, Any]]:
        if not self.rules_path.exists():
            return []
        with open(self.rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        rules = data.get("rules", [])
        for r in rules:
            when = r.get("when", {})
            if "cmdline_regex" in when:
                when["_cmdline_re"] = re.compile(when["cmdline_regex"])
            if "exe_path_regex" in when:
                when["_exe_re"] = re.compile(when["exe_path_regex"])
            if "path_regex" in when:
                when["_path_re"] = re.compile(when["path_regex"])
        return rules

    def evaluate_event(self, event: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
        """
        Evaluates a single telemetry event.
        Returns:
            tuple of (matching_rules, max_severity)
        """
        matches = []
        now = time.time()
        self.event_history.append((now, event))

        # Evict history older than 5 minutes
        while self.event_history and now - self.event_history[0][0] > 300:
            self.event_history.popleft()

        for r in self.rules:
            when = r.get("when", {})
            matched = True

            # 1. Action match
            if "action" in when and event.get("action") != when["action"]:
                matched = False

            # 2. Process name in
            if matched and "name_in" in when:
                proc_name = (event.get("name") or "").lower()
                if proc_name not in [n.lower() for n in when["name_in"]]:
                    matched = False

            # 3. Parent process name in
            if matched and "parent_name_in" in when:
                parent_name = (event.get("parent_name") or "").lower()
                if parent_name not in [pn.lower() for pn in when["parent_name_in"]]:
                    matched = False

            # 4. Command line regex
            if matched and "_cmdline_re" in when:
                cmdline = event.get("cmdline") or ""
                if not when["_cmdline_re"].search(cmdline):
                    matched = False

            # 5. Exe path regex
            if matched and "_exe_re" in when:
                exe_path = event.get("exe") or ""
                if not when["_exe_re"].search(exe_path):
                    matched = False

            # 6. Remote port in
            if matched and "remote_port_in" in when:
                remote_port = event.get("remote_port")
                if remote_port not in when["remote_port_in"]:
                    matched = False

            # 7. Burst temporal match (e.g. logon failed bursts)
            if matched and "event" in when and "count_gte" in when:
                target_action = when["event"]
                window_s = when.get("within_seconds", 60)
                relevant_count = sum(
                    1
                    for t, e in self.event_history
                    if now - t <= window_s and e.get("action") == target_action
                )
                if relevant_count < when["count_gte"]:
                    matched = False

            if matched:
                matches.append({
                    "id": r["id"],
                    "name": r["name"],
                    "severity": r.get("severity", 50),
                    "mitre": r.get("mitre", ""),
                })

        max_sev = max((m["severity"] for m in matches), default=0)
        return matches, max_sev
