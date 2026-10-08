"""
SentinelLog Agent: Reliable Offline Buffer & Batch Sender.
Stores telemetry events in a local SQLite database queue, flushing to the central API
in batches with exponential backoff on network disconnections.
"""

from datetime import datetime
import json
import logging
from pathlib import Path
import sqlite3
import time
from typing import Any
import requests

logger = logging.getLogger("sentinellog.agent.sender")


class Sender:
    """Offline resilient telemetry sender backed by SQLite FIFO queue."""

    def __init__(
        self,
        api_url: str = "http://127.0.0.1:8000/ingest/agent",
        api_key: str = "sentinel-secret-key-agent",
        db_path: str | Path = "agent_buffer.db",
        timeout: int = 5,
    ):
        self.api_url = api_url
        self.api_key = api_key
        self.db_path = Path(db_path)
        self.timeout = timeout
        self.backoff_seconds = 1.0
        self.max_backoff = 60.0

        self._init_db()

    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS event_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL,
                    body TEXT
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def enqueue(self, event: dict[str, Any]):
        """Persists an event to the local SQLite buffer."""
        body_json = json.dumps(event)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        try:
            conn.execute(
                "INSERT INTO event_queue (ts, body) VALUES (?, ?)",
                (time.time(), body_json),
            )
            conn.commit()
        finally:
            conn.close()

    def flush(self, batch_size: int = 100) -> int:
        """
        Attempts to transmit queued batches to the central Ingestion API.
        Returns number of successfully sent events.
        """
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        try:
            rows = conn.execute(
                "SELECT id, body FROM event_queue ORDER BY id ASC LIMIT ?",
                (batch_size,),
            ).fetchall()
        finally:
            conn.close()

        if not rows:
            return 0

        event_payload = [json.loads(r[1]) for r in rows]
        last_id = rows[-1][0]

        try:
            resp = requests.post(
                self.api_url,
                json={"events": event_payload},
                headers={"X-API-Key": self.api_key},
                timeout=self.timeout,
            )

            if resp.status_code in (200, 201):
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                try:
                    conn.execute("DELETE FROM event_queue WHERE id <= ?", (last_id,))
                    conn.commit()
                finally:
                    conn.close()
                self.backoff_seconds = 1.0
                return len(event_payload)
            else:
                logger.warning("API returned HTTP %d: %s", resp.status_code, resp.text)
                self._apply_backoff()
                return 0

        except (requests.RequestException, Exception) as e:
            logger.debug("Network transmission error: %s (events remain buffered)", e)
            self._apply_backoff()
            return 0

    def _apply_backoff(self):
        time.sleep(min(self.backoff_seconds, 2.0))
        self.backoff_seconds = min(self.backoff_seconds * 2, self.max_backoff)

    def pending_count(self) -> int:
        """Returns the number of buffered events awaiting delivery."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        try:
            cnt = conn.execute("SELECT COUNT(*) FROM event_queue").fetchone()[0]
        finally:
            conn.close()
        return cnt
