from pathlib import Path
import pytest
from pipeline.ingest import count_lines, detect_format, get_file_summary, sample_lines, stream_lines

FIXTURE_PATH = Path("tests/fixtures/sample_access.log")


def test_stream_lines():
    lines = list(stream_lines(FIXTURE_PATH))
    assert len(lines) > 20
    assert any("GET /index.html" in l for l in lines)


def test_sample_lines():
    k = 5
    sampled = sample_lines(FIXTURE_PATH, k=k, seed=42)
    assert len(sampled) == k
    # Check reproducibility with same seed
    sampled_again = sample_lines(FIXTURE_PATH, k=k, seed=42)
    assert sampled == sampled_again


def test_count_lines():
    cnt = count_lines(FIXTURE_PATH)
    assert cnt > 20


def test_detect_format():
    sample = [
        '203.0.113.5 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"',
        '203.0.113.6 - - [10/Oct/2026:13:55:45 +0000] "GET /about.html HTTP/1.1" 200 3120 "http://ref" "Mozilla/5.0"',
    ]
    fmt = detect_format(sample)
    assert fmt == "combined"

    common_sample = [
        '203.0.113.5 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326',
    ]
    assert detect_format(common_sample) == "common"
    assert detect_format(["random gibberish"]) == "unknown"


def test_get_file_summary():
    summary = get_file_summary(FIXTURE_PATH)
    assert summary["total_lines"] > 20
    assert summary["detected_format"] == "combined"
    assert len(summary["first_5_lines"]) == 5
    assert len(summary["last_5_lines"]) == 5
