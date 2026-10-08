from pathlib import Path
import tempfile
import pandas as pd
import pytest
from pipeline.cleaner import clean
from pipeline.features import (
    add_request_features,
    add_window_features,
    classify_ua,
    generate_feature_catalogue,
    shannon_entropy,
)
from pipeline.parser import parse_file

FIXTURE_PATH = Path("tests/fixtures/sample_access.log")


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    # Randomized high-entropy string should be significantly higher
    low_ent = shannon_entropy("/index.html")
    high_ent = shannon_entropy("/items.php?cat=shoes%2527%20OR%201%3D1--")
    assert high_ent > low_ent


def test_classify_ua():
    assert classify_ua("sqlmap/1.7") == "tool"
    assert classify_ua("Nikto/2.1.6") == "tool"
    assert classify_ua("Googlebot/2.1 (+http://www.google.com/bot.html)") == "bot"
    assert classify_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64)") == "browser"
    assert classify_ua("EMPTY_UA") == "empty"
    assert classify_ua("-") == "empty"


def test_add_request_features():
    df, _ = parse_file(FIXTURE_PATH)
    cleaned = clean(df)
    feat_df = add_request_features(cleaned)

    # Check request-level columns
    expected_cols = [
        "url_length", "query_length", "num_params", "special_chars",
        "special_ratio", "digit_ratio", "upper_ratio", "url_entropy",
        "has_sql_kw", "has_script_tag", "has_traversal", "has_cmd_kw",
        "method_is_post", "is_rare_method", "is_4xx", "is_404", "ua_class",
    ]
    for col in expected_cols:
        assert col in feat_df.columns, f"Missing feature: {col}"

    # Verify SQL keyword detection flag
    sqli_rows = feat_df[feat_df["raw_url"].str.contains("UNION%20SELECT")]
    assert not sqli_rows.empty
    assert sqli_rows.iloc[0]["has_sql_kw"] == 1


def test_add_window_features():
    df, _ = parse_file(FIXTURE_PATH)
    cleaned = clean(df)
    req_feat = add_request_features(cleaned)
    win_feat = add_window_features(req_feat, window="5min")

    expected_window_cols = [
        "win_req_count", "win_ratio_404", "win_ratio_4xx",
        "win_gap_mean", "win_gap_std", "win_unique_paths", "win_path_scan_ratio",
    ]
    for col in expected_window_cols:
        assert col in win_feat.columns, f"Missing window feature: {col}"

    # Rolling count should be at least 1
    assert (win_feat["win_req_count"] >= 1).all()


def test_generate_feature_catalogue():
    with tempfile.TemporaryDirectory() as tmpdir:
        cat_file = Path(tmpdir) / "catalogue.csv"
        df = generate_feature_catalogue(cat_file)
        assert cat_file.exists()
        assert len(df) >= 15
        assert "feature" in df.columns
        assert "rationale" in df.columns
