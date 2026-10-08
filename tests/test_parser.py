from pathlib import Path
import tempfile
import pandas as pd
import pytest
from pipeline.parser import parse_file, parse_line, parse_report

FIXTURE_PATH = Path("tests/fixtures/sample_access.log")


def test_parse_line_standard():
    line = '203.0.113.5 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "http://ref" "Mozilla/5.0"'
    res = parse_line(line)
    assert res is not None
    assert res["ip"] == "203.0.113.5"
    assert res["method"] == "GET"
    assert res["url"] == "/index.html"
    assert res["status"] == "200"
    assert res["bytes"] == "2326"
    assert res["referrer"] == "http://ref"
    assert res["ua"] == "Mozilla/5.0"


def test_parse_line_ipv6_and_dash_bytes():
    line = '2001:db8::1 - - [10/Oct/2026:13:57:30 +0000] "GET /ipv6-test HTTP/1.1" 200 - "-" "-"'
    res = parse_line(line)
    assert res is not None
    assert res["ip"] == "2001:db8::1"
    assert res["url"] == "/ipv6-test"
    assert res["bytes"] == "-"


def test_parse_file_with_rejects_and_parquet():
    with tempfile.TemporaryDirectory() as tmpdir:
        rej_file = Path(tmpdir) / "rejects.txt"
        parquet_file = Path(tmpdir) / "out.parquet"

        df, rejects = parse_file(
            FIXTURE_PATH,
            chunk_size=10,
            rejects_path=rej_file,
            output_parquet=parquet_file,
        )

        assert not df.empty
        assert "ip" in df.columns
        assert "status" in df.columns
        assert df["status"].dtype == "int16"
        assert df["bytes"].dtype == "int64"

        # Check rejects were caught
        assert len(rejects) >= 2
        assert rej_file.exists()
        assert parquet_file.exists()

        # Check loaded parquet matches dataframe
        loaded_df = pd.read_parquet(parquet_file)
        assert len(loaded_df) == len(df)


def test_parse_report():
    report = parse_report(total_attempted=100, parsed_count=95, rejected_count=5)
    assert report["parse_success_rate_percent"] == 95.0
