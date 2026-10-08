"""
SentinelLog Pipeline: Parser Module (GTU Practical 2).
Converts unstructured Apache / Nginx combined log files into structured Pandas DataFrames.
Supports chunked processing, Parquet serialization, and reject stream auditing.
"""

from pathlib import Path
import re
from typing import Any
import pandas as pd

# Regex supporting IPv4, IPv6, optional protocol, optional quotes on referrer/ua, and dash bytes
LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+(?P<proto>[^"]*))?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?.*$'
)

TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(line: str) -> dict[str, Any] | None:
    """
    Parses a single log line into a dictionary.
    Returns None if line does not match the standard log format.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    match = LOG_RE.match(stripped)
    if not match:
        return None
    return match.groupdict()


def parse_file(
    path: str | Path,
    chunk_size: int = 200_000,
    rejects_path: str | Path | None = None,
    output_parquet: str | Path | None = None,
) -> tuple[pd.DataFrame, list[tuple[int, str]]]:
    """
    Parses an entire access log file.
    
    Args:
        path: Path to raw access log file.
        chunk_size: Batch size for memory-constrained parsing.
        rejects_path: Optional path to store rejected lines.
        output_parquet: Optional path to write output DataFrame as Parquet.
        
    Returns:
        tuple of (parsed_df, rejects_list) where rejects_list contains (line_num, raw_line).
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")

    rows: list[dict[str, Any]] = []
    rejects: list[tuple[int, str]] = []
    parquet_chunks: list[pd.DataFrame] = []

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            raw = line.rstrip("\r\n")
            if not raw.strip() or raw.startswith("#"):
                continue

            parsed = parse_line(raw)
            if parsed:
                rows.append(parsed)
            else:
                rejects.append((line_num, raw))

            # Memory safeguard: process in batches if exceeding chunk_size
            if len(rows) >= chunk_size:
                chunk_df = _finalize_dataframe(rows)
                parquet_chunks.append(chunk_df)
                rows = []

    if rows:
        chunk_df = _finalize_dataframe(rows)
        parquet_chunks.append(chunk_df)

    if parquet_chunks:
        df = pd.concat(parquet_chunks, ignore_index=True)
    else:
        df = pd.DataFrame(
            columns=["ip", "user", "ts", "method", "url", "proto", "status", "bytes", "referrer", "ua"]
        )

    # Save rejects if requested
    if rejects_path and rejects:
        rej_file = Path(rejects_path)
        rej_file.parent.mkdir(parents=True, exist_ok=True)
        with open(rej_file, "w", encoding="utf-8") as f:
            for lnum, lcontent in rejects:
                f.write(f"Line {lnum}: {lcontent}\n")

    # Save to Parquet if requested
    if output_parquet and not df.empty:
        out_p = Path(output_parquet)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        df.to_parquet(out_p, index=False)

    return df, rejects


def _finalize_dataframe(rows: list[dict[str, Any]]) -> pd.DataFrame:
    """Type-casts and normalizes raw dictionary rows into an optimized DataFrame."""
    df = pd.DataFrame(rows)
    if df.empty:
        return df

    # Datetime parse to timezone-aware UTC
    df["ts"] = pd.to_datetime(df["ts"], format=TS_FORMAT, utc=True, errors="coerce")

    # Numeric status code (16-bit int)
    df["status"] = pd.to_numeric(df["status"], errors="coerce").fillna(0).astype("int16")

    # Bytes sent (dash replaced with 0, 64-bit int)
    df["bytes"] = (
        pd.to_numeric(df["bytes"].replace("-", "0"), errors="coerce")
        .fillna(0)
        .astype("int64")
    )

    # Fill optional missing fields
    for col in ["referrer", "ua", "proto", "user"]:
        if col in df.columns:
            df[col] = df[col].fillna("-")
        else:
            df[col] = "-"

    return df


def parse_report(total_attempted: int, parsed_count: int, rejected_count: int) -> dict[str, Any]:
    """Generates parser performance and quality metrics."""
    success_rate = (parsed_count / total_attempted * 100.0) if total_attempted > 0 else 0.0
    return {
        "total_attempted": total_attempted,
        "successfully_parsed": parsed_count,
        "rejected_count": rejected_count,
        "parse_success_rate_percent": round(success_rate, 2),
    }
