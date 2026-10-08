from pathlib import Path
import pandas as pd
import pytest
from pipeline.cleaner import clean
from pipeline.labeler import label_requests, load_rules
from pipeline.parser import parse_file
from pipeline.wrangle import (
    create_pivots,
    enrich_geoip,
    filter_noise,
    ip_summary,
    is_internal,
    resample_traffic,
)

FIXTURE_PATH = Path("tests/fixtures/sample_access.log")
ALLOWLIST_PATH = Path("rules/allowlist.yaml")


@pytest.fixture
def sample_df():
    df, _ = parse_file(FIXTURE_PATH)
    cleaned = clean(df)
    rules = load_rules("rules/web_rules.yaml")
    return label_requests(cleaned, rules)


def test_is_internal():
    assert is_internal("127.0.0.1") is True
    assert is_internal("192.168.1.100") is True
    assert is_internal("10.0.0.5") is True
    assert is_internal("172.16.50.2") is True
    assert is_internal("203.0.113.5") is False
    assert is_internal("invalid_ip") is False


def test_filter_noise(sample_df):
    filtered = filter_noise(sample_df, allowlist_path=ALLOWLIST_PATH)
    # Ensure no internal IPs remain
    for ip_str in filtered["ip"]:
        assert not is_internal(ip_str)


def test_ip_summary(sample_df):
    summary = ip_summary(sample_df)
    assert not summary.empty
    assert "ip" in summary.columns
    assert "requests" in summary.columns
    assert "attacks" in summary.columns
    assert "attack_ratio" in summary.columns
    # Check top attacker ordering
    assert summary.iloc[0]["attacks"] >= summary.iloc[-1]["attacks"]


def test_resample_traffic(sample_df):
    resampled = resample_traffic(sample_df, freq="1h")
    assert not resampled.empty
    assert isinstance(resampled.index, pd.DatetimeIndex)


def test_create_pivots(sample_df):
    pivots = create_pivots(sample_df)
    assert "method_by_label" in pivots
    assert "status_by_label" in pivots
    assert "hour_by_label" in pivots


def test_enrich_geoip(sample_df):
    enriched = enrich_geoip(sample_df)
    assert "geo_country" in enriched.columns
    assert "geo_iso" in enriched.columns
    assert enriched["geo_country"].notna().all()
