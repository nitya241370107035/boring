"""
SentinelLog Pipeline: Data Wrangling Module (GTU Practical 7).
Implements aggregation, time-series resampling, pivot tables,
noise filtering (internal IPs & bots), and GeoIP threat intelligence enrichment.
"""

import ipaddress
from pathlib import Path
import re
from typing import Any
import pandas as pd
import yaml


RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


def is_internal(ip: str) -> bool:
    """Checks whether an IP address belongs to RFC 1918 private (10/8, 172.16/12, 192.168/16) or loopback ranges."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in RFC1918_NETWORKS)
    except ValueError:
        return False


def filter_noise(
    df: pd.DataFrame,
    allowlist_path: str | Path = "rules/allowlist.yaml",
) -> pd.DataFrame:
    """
    Filters out noise:
    1. Internal/private subnets.
    2. Verified legitimate crawlers (Googlebot, Bingbot, DuckDuckBot).
    """
    if df.empty:
        return df.copy()

    df = df.copy()
    cfg_file = Path(allowlist_path)
    allowed_crawlers_re = None

    if cfg_file.exists():
        with open(cfg_file, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
            crawlers = cfg.get("allowed_crawlers", [])
            if crawlers:
                clean_patterns = [
                    re.sub(r"^\(\?i\)", "", c["ua_regex"]) for c in crawlers if "ua_regex" in c
                ]
                if clean_patterns:
                    allowed_crawlers_re = re.compile("|".join(f"(?:{p})" for p in clean_patterns), re.IGNORECASE)

    # Filter private IPs
    if "ip" in df.columns:
        is_priv = df["ip"].astype(str).map(is_internal)
    else:
        is_priv = pd.Series([False] * len(df))

    # Filter crawlers
    if allowed_crawlers_re and "ua" in df.columns:
        is_crawler = df["ua"].astype(str).str.contains(allowed_crawlers_re, regex=True)
    else:
        is_crawler = pd.Series([False] * len(df))

    # Retain perimeter public requests and unverified agents
    filtered_df = df[~(is_priv | is_crawler)].copy()
    return filtered_df.reset_index(drop=True)


def ip_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregates per-IP statistics:
    Request count, attack count, attack ratio, unique paths, first seen, last seen.
    """
    if df.empty or "ip" not in df.columns:
        return pd.DataFrame()

    has_label = "label" in df.columns
    has_path = "path" in df.columns
    has_ts = "ts" in df.columns

    grouped = df.groupby("ip")

    agg_dict: dict[str, tuple[str, Any]] = {
        "requests": ("ip", "count"),
    }
    if has_path:
        agg_dict["unique_paths"] = ("path", "nunique")
    if has_ts:
        agg_dict["first_seen"] = ("ts", "min")
        agg_dict["last_seen"] = ("ts", "max")

    res = grouped.agg(**agg_dict)

    if has_label:
        attacks = grouped["label"].apply(lambda s: (s != "benign").sum())
        res["attacks"] = attacks
        res["attack_ratio"] = (res["attacks"] / res["requests"]).round(4)
        distinct_labels = grouped["label"].apply(lambda s: sorted(list(set(s))))
        res["distinct_labels"] = distinct_labels
    else:
        res["attacks"] = 0
        res["attack_ratio"] = 0.0

    return res.sort_values(by="attacks", ascending=False).reset_index()


def resample_traffic(df: pd.DataFrame, freq: str = "1h") -> pd.DataFrame:
    """
    Resamples event time-series by specified frequency (e.g. 1h, 1D),
    broken down by attack label.
    """
    if df.empty or "ts" not in df.columns:
        return pd.DataFrame()

    d = df.dropna(subset=["ts"]).copy()
    label_col = "label" if "label" in d.columns else None

    if label_col:
        resampled = (
            d.groupby([pd.Grouper(key="ts", freq=freq), label_col])
            .size()
            .unstack(level=label_col, fill_value=0)
        )
    else:
        resampled = (
            d.groupby(pd.Grouper(key="ts", freq=freq))
            .size()
            .to_frame(name="total_requests")
        )

    return resampled


def create_pivots(df: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """
    Creates security cross-tabulation pivot tables:
    1. HTTP Method vs Attack Label
    2. HTTP Status Code vs Attack Label
    3. Hour of Day vs Attack Label
    """
    if df.empty:
        return {}

    pivots = {}
    label_col = "label" if "label" in df.columns else None

    if label_col and "method" in df.columns:
        pivots["method_by_label"] = pd.pivot_table(
            df, index="method", columns=label_col, values="url", aggfunc="count", fill_value=0
        )

    if label_col and "status" in df.columns:
        pivots["status_by_label"] = pd.pivot_table(
            df, index="status", columns=label_col, values="url", aggfunc="count", fill_value=0
        )

    if label_col and "ts" in df.columns:
        d = df.copy()
        d["hour"] = d["ts"].dt.hour
        pivots["hour_by_label"] = pd.pivot_table(
            d, index="hour", columns=label_col, values="url", aggfunc="count", fill_value=0
        )

    return pivots


def enrich_geoip(
    df: pd.DataFrame,
    mmdb_path: str | Path | None = None,
) -> pd.DataFrame:
    """
    Enriches IP addresses with Country and Continent data.
    Gracefully falls back to deterministic subnet resolution if MaxMind MMDB is not provided.
    """
    if df.empty or "ip" not in df.columns:
        return df.copy()

    df = df.copy()
    country_map: dict[str, str] = {}
    iso_map: dict[str, str] = {}

    reader = None
    if mmdb_path and Path(mmdb_path).exists():
        try:
            import geoip2.database
            reader = geoip2.database.Reader(str(mmdb_path))
        except Exception:
            reader = None

    unique_ips = df["ip"].unique()
    for ip_str in unique_ips:
        if is_internal(ip_str):
            country_map[ip_str] = "Internal / Private"
            iso_map[ip_str] = "INT"
            continue

        if reader:
            try:
                resp = reader.city(ip_str)
                country_map[ip_str] = resp.country.name or "Unknown"
                iso_map[ip_str] = resp.country.iso_code or "UNK"
                continue
            except Exception:
                pass

        # Deterministic testnet/documentation fallback mapping
        if ip_str.startswith("198.51.100."):
            country_map[ip_str] = "Attacker Lab / External"
            iso_map[ip_str] = "ATT"
        elif ip_str.startswith("203.0.113."):
            country_map[ip_str] = "United States"
            iso_map[ip_str] = "USA"
        elif ip_str.startswith("192.0.2."):
            country_map[ip_str] = "BruteForce Source / External"
            iso_map[ip_str] = "BFR"
        elif ":" in ip_str:
            country_map[ip_str] = "IPv6 Global"
            iso_map[ip_str] = "IP6"
        else:
            country_map[ip_str] = "Unknown Origin"
            iso_map[ip_str] = "UNK"

    if reader:
        try:
            reader.close()
        except Exception:
            pass

    df["geo_country"] = df["ip"].map(country_map)
    df["geo_iso"] = df["ip"].map(iso_map)
    return df
