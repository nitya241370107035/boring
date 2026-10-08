"""
SentinelLog Windows Endpoint Agent: Main Orchestrator Service.
Coordinates telemetry collectors, local rule engine, SQLite buffering,
and heartbeats with bounded CPU/RAM footprint and privacy protections.
"""

from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import platform
import threading
import time
from typing import Any
import psutil
import yaml

from agent.collectors.eventlog import query_security_events
from agent.collectors.files import start_file_monitor
from agent.collectors.network import active_connections
from agent.collectors.persistence import check_registry_persistence, check_startup_folder
from agent.collectors.processes import diff_new_processes, snapshot
from agent.rules import EndpointRuleEngine
from agent.sender import Sender

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
)
logger = logging.getLogger("sentinellog.agent")


class SentinelAgent:
    """Enterprise Windows telemetry agent."""

    def __init__(self, config_path: str | Path = "agent/config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.host = self.config.get("hostname", platform.node())
        self.agent_id = self.config.get("agent_id", "agent-win-default")

        # Initialize local rule engine and resilient sender
        rule_path = self.config.get("rules_path", "rules/endpoint_rules.yaml")
        self.rule_engine = EndpointRuleEngine(rule_path)

        server_cfg = self.config.get("server", {})
        self.sender = Sender(
            api_url=server_cfg.get("api_url", "http://127.0.0.1:8000/ingest/agent"),
            api_key=server_cfg.get("api_key", "sentinel-secret-key-agent"),
            db_path=server_cfg.get("buffer_db", "agent_buffer.db"),
        )

        self.running = False
        self.threads: list[threading.Thread] = []
        self.file_observer = None
        self.start_time = time.time()
        self.prev_proc_snapshot = {}

    def _load_config(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {}
        with open(self.config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def emit_event(self, event: dict[str, Any]):
        """Evaluates local rules, attaches metadata, and buffers event."""
        matches, max_sev = self.rule_engine.evaluate_event(event)
        event["rule_hits"] = matches
        event["local_severity"] = max_sev
        event["agent_id"] = self.agent_id
        if "host" not in event:
            event["host"] = self.host
        if "ts" not in event:
            event["ts"] = datetime.now(timezone.utc).isoformat()

        if matches:
            logger.warning(
                "🚨 LOCAL RULE TRIGGERED on %s: %s (Severity: %d)",
                event.get("action"),
                [m["id"] for m in matches],
                max_sev,
            )

        self.sender.enqueue(event)

    def _proc_loop(self):
        interval = self.config.get("intervals", {}).get("processes_seconds", 5)
        self.prev_proc_snapshot = snapshot()
        while self.running:
            time.sleep(interval)
            try:
                cur = snapshot()
                new_events = diff_new_processes(self.prev_proc_snapshot, cur, host=self.host)
                for ev in new_events:
                    self.emit_event(ev)
                self.prev_proc_snapshot = cur
            except Exception as e:
                logger.error("Process collector loop error: %s", e)

    def _net_loop(self):
        interval = self.config.get("intervals", {}).get("network_seconds", 10)
        while self.running:
            time.sleep(interval)
            try:
                proc_map = {pid: info.get("name") for pid, info in self.prev_proc_snapshot.items()}
                conns = active_connections(proc_map=proc_map, host=self.host)
                for ev in conns:
                    self.emit_event(ev)
            except Exception as e:
                logger.error("Network collector loop error: %s", e)

    def _eventlog_loop(self):
        interval = self.config.get("intervals", {}).get("eventlog_seconds", 15)
        while self.running:
            time.sleep(interval)
            try:
                sec_events = query_security_events(since_seconds=interval + 5, host=self.host)
                for ev in sec_events:
                    self.emit_event(ev)
            except Exception as e:
                logger.error("EventLog collector loop error: %s", e)

    def _persistence_loop(self):
        interval = self.config.get("intervals", {}).get("persistence_seconds", 60)
        while self.running:
            time.sleep(interval)
            try:
                reg_events = check_registry_persistence(host=self.host)
                startup_events = check_startup_folder(host=self.host)
                for ev in reg_events + startup_events:
                    self.emit_event(ev)
            except Exception as e:
                logger.error("Persistence collector loop error: %s", e)

    def _send_heartbeat(self):
        try:
            proc = psutil.Process()
            cpu_pct = proc.cpu_percent(interval=None)
            ram_mb = proc.memory_info().rss / (1024 * 1024)
            heartbeat = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "source": "agent_heartbeat",
                "host": self.host,
                "agent_id": self.agent_id,
                "action": "heartbeat",
                "actor": "agent_service",
                "target": "server",
                "attrs": {
                    "uptime_seconds": round(time.time() - self.start_time, 1),
                    "cpu_percent": round(cpu_pct, 2),
                    "ram_mb": round(ram_mb, 2),
                    "pending_buffered_events": self.sender.pending_count(),
                    "os": platform.platform(),
                },
            }
            self.emit_event(heartbeat)
            self.sender.flush(batch_size=10)
        except Exception as e:
            logger.error("Error sending heartbeat: %s", e)

    def _heartbeat_loop(self):
        interval = self.config.get("intervals", {}).get("heartbeat_seconds", 30)
        while self.running:
            time.sleep(interval)
            self._send_heartbeat()

    def _flush_loop(self):
        flush_interval = self.config.get("server", {}).get("flush_interval_seconds", 5)
        batch_size = self.config.get("server", {}).get("batch_size", 100)
        while self.running:
            time.sleep(flush_interval)
            try:
                sent = self.sender.flush(batch_size=batch_size)
                if sent > 0:
                    logger.debug("Flushed %d buffered events to API.", sent)
            except Exception as e:
                logger.error("Flush loop error: %s", e)

    def start(self):
        """Starts all background collectors and sender workers."""
        self.running = True
        logger.info("=" * 60)
        logger.info(" SentinelLog Windows Endpoint Telemetry Agent v1.0")
        logger.info(" Host: %s | Agent ID: %s", self.host, self.agent_id)
        logger.info(" Privacy Notice: Minimum necessary telemetry collected.")
        logger.info(" No file contents, browser history, or passwords captured.")
        logger.info("=" * 60)

        # File observer
        file_cfg = self.config.get("file_monitor", {})
        if file_cfg.get("enabled", True):
            paths = file_cfg.get("watch_paths", ["C:\\Users\\Public"])
            self.file_observer = start_file_monitor(
                paths,
                emit_callback=self.emit_event,
                window=file_cfg.get("churn_window_seconds", 10),
                threshold=file_cfg.get("churn_threshold", 40),
                host=self.host,
            )

        # Spawn threads
        targets = [
            ("ProcessCollector", self._proc_loop),
            ("NetworkCollector", self._net_loop),
            ("EventLogCollector", self._eventlog_loop),
            ("PersistenceCollector", self._persistence_loop),
            ("HeartbeatWorker", self._heartbeat_loop),
            ("SenderWorker", self._flush_loop),
        ]

        for name, fn in targets:
            t = threading.Thread(target=fn, name=name, daemon=True)
            t.start()
            self.threads.append(t)

        # Emit and flush immediate heartbeat on startup
        self._send_heartbeat()
        logger.info("All collectors and background workers started successfully.")

    def stop(self):
        """Gracefully shuts down agent and closes file observers."""
        logger.info("Stopping SentinelLog agent...")
        self.running = False
        if self.file_observer:
            try:
                self.file_observer.stop()
                self.file_observer.join(timeout=2)
            except Exception:
                pass
        logger.info("Agent stopped cleanly.")


def main():
    agent = SentinelAgent()
    agent.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
