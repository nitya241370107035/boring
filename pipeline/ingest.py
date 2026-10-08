"""
SentinelLog Pipeline: Ingestion Module (GTU Practical 1).
Provides memory-safe streaming, reservoir sampling, format detection, and log file summarization.
"""

from collections import deque
import os
from pathlib import Path
import random
import re
from typing import Any, Generator, Iterable

COMBINED_HINT_RE = re.compile(
    r'^\S+ \S+ \S+ \[.*?\] "[A-Z]+ \S+.*?" \d{3} \S+ ".*?" ".*?"'
)
COMMON_HINT_RE = re.compile(
    r'^\S+ \S+ \S+ \[.*?\] "[A-Z]+ \S+.*?" \d{3} \S+'
)


def stream_lines(path: str | Path) -> Generator[str, None, None]:
    """
    Stream lines one by one with encoding resilience.
    Uses errors='replace' to safely handle non-UTF8/binary payloads in attack logs.
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\r\n")


def sample_lines(path: str | Path, k: int = 10, seed: int = 42) -> list[str]:
    """
    Reservoir sampling algorithm: select exactly k random lines in O(N) time
    and O(k) memory, without loading the full file into RAM.
    """
    random.seed(seed)
    reservoir: list[str] = []

    for i, line in enumerate(stream_lines(path)):
        # Skip empty lines in reservoir sampling
        if not line.strip():
            continue
        if len(reservoir) < k:
            reservoir.append(line)
        else:
            j = random.randint(0, i)
            if j < k:
                reservoir[j] = line

    return reservoir


def count_lines(path: str | Path) -> int:
    """
    High-speed binary line counting using a 1MB chunked buffer.
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")

    count = 0
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            count += chunk.count(b"\n")
    return count


def detect_format(lines: Iterable[str]) -> str:
    """
    Heuristically detects log structure: 'combined', 'common', or 'unknown'.
    """
    combined_hits = 0
    common_hits = 0
    total = 0

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        total += 1
        if COMBINED_HINT_RE.search(stripped):
            combined_hits += 1
        elif COMMON_HINT_RE.search(stripped):
            common_hits += 1

    if total == 0:
        return "unknown"

    if combined_hits / total >= 0.5:
        return "combined"
    if (combined_hits + common_hits) / total >= 0.5:
        return "common"
    return "unknown"


def format_bytes(size: int) -> str:
    """Convert raw byte count to human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def get_file_summary(path: str | Path) -> dict[str, Any]:
    """
    Generate an exhaustive summary for Practical 1 submission:
    file size, line count, first 5 lines, last 5 lines, and format detection.
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")

    file_size = os.path.getsize(filepath)
    first_lines: list[str] = []
    last_lines: deque[str] = deque(maxlen=5)
    sample_candidate_lines: list[str] = []

    line_count = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            clean = line.rstrip("\r\n")
            if not clean.strip() or clean.startswith("#"):
                continue
            line_count += 1
            if len(first_lines) < 5:
                first_lines.append(clean)
            last_lines.append(clean)
            if len(sample_candidate_lines) < 50:
                sample_candidate_lines.append(clean)

    detected_format = detect_format(sample_candidate_lines)

    return {
        "filepath": str(filepath.resolve()),
        "file_size_bytes": file_size,
        "file_size_formatted": format_bytes(file_size),
        "total_lines": line_count,
        "detected_format": detected_format,
        "first_5_lines": first_lines,
        "last_5_lines": list(last_lines),
    }
