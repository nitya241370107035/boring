"""
SentinelLog Pipeline: Cleaner & Preprocessor Module (GTU Practical 3).
Performs multi-pass URL decoding (evasion prevention), path normalization,
missing-value tokens, timestamp validation, and data-quality reporting.
"""

from pathlib import Path
import re
from typing import Any
from urllib.parse import unquote_plus, urlsplit
import pandas as pd


def deep_decode(s: str, max_iter: int = 3) -> str:
    """
    Repeatedly decodes URL-encoded strings (up to max_iter iterations).
    Neutralizes double/triple-encoding evasion techniques (e.g. %2527 -> %27 -> ').
    """
    if not isinstance(s, str) or not s:
        return ""
    cur = s
    for _ in range(max_iter):
        decoded = unquote_plus(cur)
        if decoded == cur:
            break
        cur = decoded
    return cur


def compute_encoding_depth(s: str, max_iter: int = 3) -> int:
    """Returns the number of decoding passes needed until idempotence."""
    if not isinstance(s, str) or not s:
        return 0
    cur = s
    depth = 0
    for _ in range(max_iter):
        decoded = unquote_plus(cur)
        if decoded == cur:
            break
        depth += 1
        cur = decoded
    return depth


def normalize_path(path: str) -> str:
    """
    Normalizes a URL path strictly for aggregated analysis.
    Preserves root consistency without deleting directory traversal indicators in raw/decoded columns.
    """
    if not isinstance(path, str) or not path.strip():
        return "/"
    p = path.lower().strip()
    # Collapse multiple consecutive slashes
    p = re.sub(r"/{2,}", "/", p)
    # Strip control chars / null bytes
    p = re.sub(r"[\x00-\x1f\x7f]", "", p)
    # Standardize default root pages
    if p in ("/index", "/index.html", "/index.htm", "/index.php", "/default.aspx"):
        return "/"
    return p.rstrip("/") or "/"


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans and pre-processes the parsed log DataFrame.
    
    1. Preserves raw_url and adds decoded_url (multi-pass decoded).
    2. Separates path_raw, query, and normalized path.
    3. Handles missing values: '-' in referrer to NA, empty UA to 'EMPTY_UA'.
    4. Normalizes HTTP methods to uppercase.
    5. Sorts chronologically by ts.
    """
    if df.empty:
        return df.copy()

    df = df.copy()

    # 1. URLs
    df["raw_url"] = df["url"].astype(str)
    df["decoded_url"] = df["raw_url"].map(deep_decode)
    df["encoding_depth"] = df["raw_url"].map(compute_encoding_depth)

    # 2. Split path and query
    split_parts = df["decoded_url"].map(urlsplit)
    df["path_raw"] = split_parts.map(lambda u: u.path)
    df["query"] = split_parts.map(lambda u: u.query)
    df["path"] = df["path_raw"].map(normalize_path)

    # 3. Referrer & User-Agent
    df["referrer"] = df["referrer"].replace("-", pd.NA).replace("", pd.NA)
    df["ua"] = (
        df["ua"]
        .fillna("EMPTY_UA")
        .replace("-", "EMPTY_UA")
        .replace("", "EMPTY_UA")
        .astype(str)
        .str.strip()
    )

    # 4. Method normalization
    df["method"] = df["method"].astype(str).str.upper().str.strip()

    # 5. Drop exact duplicates if any
    df = df.drop_duplicates()

    # 6. Chronological ordering
    if "ts" in df.columns:
        df = df.sort_values("ts").reset_index(drop=True)

    return df


def data_quality_report(df: pd.DataFrame) -> dict[str, Any]:
    """
    Generates a data quality summary audit:
    Record count, missing fields, unique IPs, methods, and date range.
    """
    if df.empty:
        return {"total_records": 0, "status": "empty"}

    date_min = df["ts"].min().isoformat() if "ts" in df.columns and pd.notna(df["ts"].min()) else None
    date_max = df["ts"].max().isoformat() if "ts" in df.columns and pd.notna(df["ts"].max()) else None

    return {
        "total_records": len(df),
        "unique_ips": int(df["ip"].nunique()) if "ip" in df.columns else 0,
        "unique_paths": int(df["path"].nunique()) if "path" in df.columns else 0,
        "missing_referrers": int(df["referrer"].isna().sum()) if "referrer" in df.columns else 0,
        "empty_user_agents": int((df["ua"] == "EMPTY_UA").sum()) if "ua" in df.columns else 0,
        "methods_distribution": df["method"].value_counts().to_dict() if "method" in df.columns else {},
        "status_code_distribution": df["status"].value_counts().to_dict() if "status" in df.columns else {},
        "start_time": date_min,
        "end_time": date_max,
    }
