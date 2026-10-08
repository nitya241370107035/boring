from pathlib import Path
import pandas as pd
import pytest
from pipeline.cleaner import clean, compute_encoding_depth, data_quality_report, deep_decode, normalize_path
from pipeline.parser import parse_file

FIXTURE_PATH = Path("tests/fixtures/sample_access.log")


def test_deep_decode():
    # Double-encoded quote: %2527 -> %27 -> '
    assert deep_decode("cat%2527s") == "cat's"
    assert deep_decode("%2e%2e%2f") == "../"
    assert compute_encoding_depth("cat%2527s") == 2
    assert compute_encoding_depth("plain_text") == 0


def test_normalize_path():
    assert normalize_path("/INDEX.HTML") == "/"
    assert normalize_path("//api///v1//users/") == "/api/v1/users"
    assert normalize_path("/products.php") == "/products.php"
    assert normalize_path("") == "/"


def test_clean_pipeline():
    raw_df, _ = parse_file(FIXTURE_PATH)
    cleaned_df = clean(raw_df)

    assert "raw_url" in cleaned_df.columns
    assert "decoded_url" in cleaned_df.columns
    assert "path" in cleaned_df.columns
    assert "query" in cleaned_df.columns
    assert "encoding_depth" in cleaned_df.columns

    # Verify traversal is NOT destroyed in decoded_url
    trav_row = cleaned_df[cleaned_df["raw_url"].str.contains("etc/passwd")]
    assert not trav_row.empty
    assert "../" in trav_row.iloc[0]["decoded_url"]

    # Verify EMPTY_UA token assignment
    assert "EMPTY_UA" in cleaned_df["ua"].values

    # Verify referrer NA replacement
    assert cleaned_df["referrer"].isna().sum() > 0

    # Data quality report
    report = data_quality_report(cleaned_df)
    assert report["total_records"] == len(cleaned_df)
    assert report["unique_ips"] > 0
