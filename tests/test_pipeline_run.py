import json
from pathlib import Path
import tempfile
import pandas as pd
import pytest
from pipeline.run import run_pipeline

FIXTURE_PATH = Path("tests/fixtures/sample_access.log")
RULES_PATH = Path("rules/web_rules.yaml")


def test_run_pipeline_end_to_end():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_parquet = Path(tmpdir) / "output.parquet"
        out_summary = Path(tmpdir) / "summary.json"

        df, summary = run_pipeline(
            logfile=FIXTURE_PATH,
            rules_path=RULES_PATH,
            out_path=out_parquet,
            summary_path=out_summary,
        )

        # Check return types
        assert not df.empty
        assert isinstance(summary, dict)

        # Check file outputs
        assert out_parquet.exists()
        assert out_summary.exists()

        # Check Parquet content
        loaded_df = pd.read_parquet(out_parquet)
        assert len(loaded_df) == len(df)
        assert "label" in loaded_df.columns
        assert "url_entropy" in loaded_df.columns

        # Check Summary content
        with open(out_summary, "r", encoding="utf-8") as f:
            sum_data = json.load(f)
        assert sum_data["total_parsed_rows"] == len(df)
        assert sum_data["total_attacks"] > 0
        assert "sqli" in sum_data["attack_distribution"]
