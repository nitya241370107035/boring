"""
SentinelLog Agent: File Churn & Ransomware Telemetry Collector.
Uses watchdog filesystem observers to monitor high-frequency modifications/renames,
detecting ransomware activity in a sliding temporal window.
"""

from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
import threading
import time
from typing import Any, Callable
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class ChurnHandler(FileSystemEventHandler):
    """
    Sliding window file modification tracker.
    Emits a file_churn alert when event volume exceeds threshold within the sliding window.
    """

    def __init__(
        self,
        emit_callback: Callable[[dict[str, Any]], None],
        window: float = 10.0,
        threshold: int = 40,
        host: str = "localhost",
    ):
        super().__init__()
        self.emit = emit_callback
        self.window = window
        self.threshold = threshold
        self.host = host
        self.events = deque()
        self.lock = threading.Lock()

    def on_any_event(self, event):
        if event.is_directory:
            return

        now = time.time()
        with self.lock:
            self.events.append((now, event.event_type, event.src_path))

            # Evict events outside the sliding window
            while self.events and now - self.events[0][0] > self.window:
                self.events.popleft()

            # Threshold breached: trigger file churn alert
            if len(self.events) >= self.threshold:
                kinds = Counter(e[1] for e in self.events)
                sample_file = self.events[-1][2]
                churn_event = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "source": "agent_file",
                    "host": self.host,
                    "actor": "filesystem_observer",
                    "action": "file_churn",
                    "target": sample_file,
                    "count": len(self.events),
                    "event_breakdown": dict(kinds),
                    "window_seconds": self.window,
                }
                self.emit(churn_event)
                self.events.clear()


def start_file_monitor(
    paths: list[str | Path],
    emit_callback: Callable[[dict[str, Any]], None],
    window: float = 10.0,
    threshold: int = 40,
    host: str = "localhost",
) -> Observer | None:
    """Schedules recursive watchdog observers across watched directories."""
    valid_paths = [Path(p) for p in paths if Path(p).exists()]
    if not valid_paths:
        return None

    observer = Observer()
    handler = ChurnHandler(emit_callback, window=window, threshold=threshold, host=host)

    for p in valid_paths:
        try:
            observer.schedule(handler, str(p), recursive=True)
        except Exception:
            continue

    observer.daemon = True
    observer.start()
    return observer
