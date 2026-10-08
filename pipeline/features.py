"""
SentinelLog Pipeline: Feature Engineering Module (GTU Practical 5).
Extracts dual-level anomaly detection features:
1. Request-level syntactic and entropy signals.
2. IP-level time-window aggregation signals (scanning bursts, regularity, 404 ratios).
"""

from collections import Counter
import math
from pathlib import Path
import re
from typing import Any
import numpy as np
import pandas as pd

# Regex patterns for UA classification and syntax hints
BOT_RE = re.compile(r"(?i)bot|crawler|spider|slurp|bingpreview|googlebot")
TOOL_RE = re.compile(
    r"(?i)sqlmap|nikto|nmap|curl|wget|python-requests|gobuster|hydra|dirbuster|masscan|wpscan"
)
SQL_KW_RE = re.compile(r"(?i)\b(?:union|select|insert|update|delete|drop|information_schema|sleep|benchmark)\b")
SCRIPT_RE = re.compile(r"(?i)(?:<script|javascript:|onerror|onload|alert\(|<svg)")
TRAV_RE = re.compile(r"(?i)(?:\.\./|\.\.\\|%2e%2e|/etc/passwd|win\.ini)")
CMD_RE = re.compile(r"(?i)(?:;\s*(?:cat|whoami|id|ls)|\|\s*whoami|&&\s*id|/bin/sh)")


def shannon_entropy(s: str) -> float:
    """
    Computes Shannon entropy: H(X) = -sum(P(x) * log2(P(x))).
    Higher entropy indicates random/obfuscated/encoded attack payloads.
    """
    if not isinstance(s, str) or not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def classify_ua(ua: str) -> str:
    """Categorizes User-Agent string into: browser, tool, bot, or empty."""
    if not isinstance(ua, str) or ua in ("EMPTY_UA", "-", ""):
        return "empty"
    if TOOL_RE.search(ua):
        return "tool"
    if BOT_RE.search(ua):
        return "bot"
    return "browser"


def add_request_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Engineers granular request-level features from URLs, HTTP status, and headers.
    """
    if df.empty:
        return df.copy()

    df = df.copy()
    url_target = df["decoded_url"].astype(str) if "decoded_url" in df.columns else df["url"].astype(str)
    query_target = df["query"].fillna("").astype(str) if "query" in df.columns else pd.Series([""] * len(df))

    # Lengths
    df["url_length"] = url_target.str.len()
    df["query_length"] = query_target.str.len()
    df["num_params"] = query_target.apply(lambda q: (q.count("&") + 1) if q else 0)

    # Character distributions & ratios
    df["special_chars"] = url_target.str.count(r"[\'\"<>;%()=\-]")
    df["special_ratio"] = df["special_chars"] / df["url_length"].clip(lower=1)
    df["digit_count"] = url_target.str.count(r"\d")
    df["digit_ratio"] = df["digit_count"] / df["url_length"].clip(lower=1)
    df["upper_count"] = url_target.str.count(r"[A-Z]")
    df["upper_ratio"] = df["upper_count"] / df["url_length"].clip(lower=1)

    # Obfuscation & Entropy
    df["url_entropy"] = url_target.map(shannon_entropy)
    if "encoding_depth" not in df.columns:
        df["encoding_depth"] = 0

    # Keyword indicators
    df["has_sql_kw"] = url_target.str.contains(SQL_KW_RE, regex=True).astype(int)
    df["has_script_tag"] = url_target.str.contains(SCRIPT_RE, regex=True).astype(int)
    df["has_traversal"] = url_target.str.contains(TRAV_RE, regex=True).astype(int)
    df["has_cmd_kw"] = url_target.str.contains(CMD_RE, regex=True).astype(int)

    # HTTP method signals
    method_upper = df["method"].astype(str).str.upper()
    df["method_is_post"] = (method_upper == "POST").astype(int)
    df["is_rare_method"] = (~method_upper.isin(["GET", "POST", "HEAD"])).astype(int)

    # Status code indicators
    status_num = df["status"].astype(int)
    df["is_4xx"] = status_num.between(400, 499).astype(int)
    df["is_404"] = (status_num == 404).astype(int)
    df["is_5xx"] = (status_num >= 500).astype(int)

    # User Agent classification
    if "ua" in df.columns:
        df["ua_class"] = df["ua"].astype(str).map(classify_ua)
    else:
        df["ua_class"] = "browser"

    return df


def add_window_features(df: pd.DataFrame, window: str = "5min") -> pd.DataFrame:
    """
    Engineers sliding time-window features per client IP.
    Captures scanning activity, credential brute-forcing, and machine-like request periodicity.
    """
    if df.empty or "ts" not in df.columns or "ip" not in df.columns:
        return df.copy()

    df = df.copy()
    # Ensure chronological sorting
    df = df.sort_values("ts").reset_index(drop=True)

    # Inter-request time difference in seconds per IP
    df["inter_request_gap"] = (
        df.groupby("ip")["ts"]
        .diff()
        .dt.total_seconds()
        .fillna(0.0)
    )

    # Window aggregations via time-indexed dataframe
    time_indexed = df.set_index("ts")
    grouped = time_indexed.groupby("ip")

    # Rolling counts and error rates
    req_count = grouped["url_length"].rolling(window).count().reset_index(drop=True)
    ratio_404 = grouped["is_404"].rolling(window).mean().reset_index(drop=True)
    ratio_4xx = grouped["is_4xx"].rolling(window).mean().reset_index(drop=True)
    gap_mean = grouped["inter_request_gap"].rolling(window).mean().reset_index(drop=True)
    gap_std = grouped["inter_request_gap"].rolling(window).std().fillna(0.0).reset_index(drop=True)

    df["win_req_count"] = req_count.values
    df["win_ratio_404"] = ratio_404.values
    df["win_ratio_4xx"] = ratio_4xx.values
    df["win_gap_mean"] = gap_mean.values
    df["win_gap_std"] = gap_std.values

    # Unique path scanning count using resample window bucket
    time_indexed["path_id"] = time_indexed["path"].factorize()[0] if "path" in time_indexed.columns else 0
    uniq_paths = (
        time_indexed.groupby("ip")["path_id"]
        .resample(window)
        .nunique()
        .rename("win_unique_paths")
        .reset_index()
    )
    df["win_bucket"] = df["ts"].dt.floor(window)
    uniq_paths = uniq_paths.rename(columns={"ts": "win_bucket"})

    merged = df.merge(uniq_paths, on=["ip", "win_bucket"], how="left")
    merged["win_unique_paths"] = merged["win_unique_paths"].fillna(1).astype(int)
    merged = merged.drop(columns=["win_bucket"])

    # Unique path ratio
    merged["win_path_scan_ratio"] = (
        merged["win_unique_paths"] / merged["win_req_count"].clip(lower=1)
    )

    return merged


def generate_feature_catalogue(
    output_path: str | Path = "data/processed/feature_catalogue.csv",
) -> pd.DataFrame:
    """
    Exports a comprehensive master catalogue detailing all engineered features.
    """
    catalogue_data = [
        {"feature": "url_length", "level": "request", "type": "int", "description": "Character length of decoded URL", "rationale": "Exploit payloads (SQLi, XSS) are significantly longer than standard endpoints."},
        {"feature": "query_length", "level": "request", "type": "int", "description": "Character length of query string", "rationale": "Payloads are concentrated in HTTP query parameters."},
        {"feature": "num_params", "level": "request", "type": "int", "description": "Number of query parameters (& + 1)", "rationale": "Fuzzers and parameter scanners inject across numerous parameters."},
        {"feature": "special_chars", "level": "request", "type": "int", "description": "Count of punctuation and meta-characters ('\";%()=-)", "rationale": "Syntax manipulation in injections requires special characters."},
        {"feature": "special_ratio", "level": "request", "type": "float", "description": "Ratio of special characters to total URL length", "rationale": "Normalizes special character density against overall string size."},
        {"feature": "url_entropy", "level": "request", "type": "float", "description": "Shannon information entropy H(X) of URL", "rationale": "Randomized shellcode and base64 strings exhibit elevated entropy."},
        {"feature": "digit_ratio", "level": "request", "type": "float", "description": "Ratio of numeric digits to URL length", "rationale": "Hex-encoded and timestamped payloads display high digit ratios."},
        {"feature": "encoding_depth", "level": "request", "type": "int", "description": "Number of decode passes until idempotence", "rationale": "Double/triple URL encoding indicates WAF evasion attempts."},
        {"feature": "has_sql_kw", "level": "request", "type": "binary", "description": "Contains SQL keywords (union, select, sleep, etc.)", "rationale": "Primary indicator of SQL injection activity."},
        {"feature": "has_script_tag", "level": "request", "type": "binary", "description": "Contains HTML/JS tags (<script, javascript:, alert)", "rationale": "Primary indicator of Cross-Site Scripting (XSS)."},
        {"feature": "has_traversal", "level": "request", "type": "binary", "description": "Contains path traversal sequences (../, etc/passwd)", "rationale": "Primary indicator of arbitrary file read/traversal."},
        {"feature": "ua_class", "level": "request", "type": "category", "description": "User agent classification (browser, tool, bot, empty)", "rationale": "Automated attack tools identify themselves or lack UAs."},
        {"feature": "is_404", "level": "request", "type": "binary", "description": "Response status code equals 404", "rationale": "Directory scanning triggers rapid sequences of 404 Not Found."},
        {"feature": "win_req_count", "level": "window", "type": "int", "description": "Request count per IP in 5-minute rolling window", "rationale": "Captures traffic surges and DoS/brute-force bursts."},
        {"feature": "win_ratio_404", "level": "window", "type": "float", "description": "Proportion of 404 responses per IP in window", "rationale": "High 404 ratios differentiate scanners from legitimate users."},
        {"feature": "win_unique_paths", "level": "window", "type": "int", "description": "Distinct endpoints requested by IP in window", "rationale": "Path fuzzers systematically crawl non-existent resources."},
        {"feature": "win_gap_std", "level": "window", "type": "float", "description": "Std dev of inter-arrival gaps per IP in window", "rationale": "Automated scripts exhibit unnatural timing uniformity (low std dev)."},
    ]
    catalogue_df = pd.DataFrame(catalogue_data)
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    catalogue_df.to_csv(out_file, index=False)
    return catalogue_df
