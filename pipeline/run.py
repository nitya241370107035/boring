"""
SentinelLog Pipeline: Reusable CLI Runner & Streaming Engine (GTU Practical 10).
Chains parsing, cleaning, labeling, and feature engineering into an end-to-end execution pipeline.
Supports one-shot batch execution and live streaming log tailing (--follow).
"""

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import time
from typing import Any
import pandas as pd
import requests

from pipeline import cleaner, features, labeler, parser

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
)
logger = logging.getLogger("sentinellog.pipeline")


def run_pipeline(
    logfile: str | Path,
    rules_path: str | Path = "rules/web_rules.yaml",
    out_path: str | Path | None = "data/processed/out.parquet",
    summary_path: str | Path | None = "run_summary.json",
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """
    Executes the complete one-shot batch data science pipeline:
    Parsing -> Cleaning -> Rule Labeling -> Request Features -> Window Features.
    """
    t0 = time.time()
    log_file = Path(logfile)
    if not log_file.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    logger.info("Starting SentinelLog pipeline for: %s", log_file)

    # 1. Parsing
    raw_df, rejects = parser.parse_file(log_file)
    logger.info("Parsed %d rows, %d rejected lines.", len(raw_df), len(rejects))

    # 2. Cleaning
    clean_df = cleaner.clean(raw_df)
    logger.info("Cleaned dataset containing %d rows.", len(clean_df))

    # 3. Rules & Labeling
    rules = labeler.load_rules(rules_path)
    labeled_df = labeler.label_requests(clean_df, rules)
    attack_count = int((labeled_df["label"] != "benign").sum())
    logger.info("Assigned labels: %d attacks detected.", attack_count)

    # 4. Feature Engineering
    req_feat = features.add_request_features(labeled_df)
    final_df = features.add_window_features(req_feat)
    logger.info("Engineered %d features.", len(final_df.columns))

    duration_sec = round(time.time() - t0, 3)

    # 5. Output Parquet
    if out_path:
        out_p = Path(out_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        final_df.to_parquet(out_p, index=False)
        logger.info("Exported Parquet dataset to: %s", out_p)

    # 6. Run Summary
    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "input_logfile": str(log_file.resolve()),
        "output_parquet": str(Path(out_path).resolve()) if out_path else None,
        "duration_seconds": duration_sec,
        "total_parsed_rows": len(final_df),
        "total_rejects": len(rejects),
        "total_attacks": attack_count,
        "attack_distribution": final_df["label"].value_counts().to_dict() if not final_df.empty else {},
    }

    if summary_path:
        sum_p = Path(summary_path)
        sum_p.parent.mkdir(parents=True, exist_ok=True)
        with open(sum_p, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        logger.info("Saved pipeline run summary to: %s", sum_p)

    logger.info("Pipeline completed successfully in %.2f seconds.", duration_sec)
    return final_df, summary


def stream_tail_pipeline(
    logfile: str | Path,
    rules_path: str | Path = "rules/web_rules.yaml",
    api_url: str | None = None,
    api_key: str = "sentinel-secret-key-1",
    poll_interval: float = 1.0,
    batch_size: int = 20,
):
    """
    Live streaming mode: tails an active log file on Windows,
    micro-batches arriving events, processes features, and optionally POSTs to the API.
    """
    log_file = Path(logfile)
    if not log_file.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    rules = labeler.load_rules(rules_path)
    logger.info("Tailing %s in follow mode. Press Ctrl+C to stop.", log_file)

    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
        # Seek to the end of the file
        f.seek(0, 2)
        buffer = []

        try:
            while True:
                line = f.readline()
                if line:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        parsed = parser.parse_line(stripped)
                        if parsed:
                            buffer.append(parsed)

                    if len(buffer) >= batch_size:
                        _process_and_forward_microbatch(buffer, rules, api_url, api_key)
                        buffer = []
                else:
                    if buffer:
                        _process_and_forward_microbatch(buffer, rules, api_url, api_key)
                        buffer = []
                    time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("Stream follow stopped by user.")


def _process_and_forward_microbatch(
    raw_rows: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    api_url: str | None,
    api_key: str,
):
    """Processes a micro-batch of newly arrived lines and transmits to the ingestion API."""
    df = parser._finalize_dataframe(raw_rows)
    cleaned = cleaner.clean(df)
    labeled = labeler.label_requests(cleaned, rules)
    final = features.add_request_features(labeled)
    logger.info("Stream micro-batch: processed %d lines (%d attacks)", len(final), (final["label"] != "benign").sum())

    if api_url:
        try:
            payload = final.to_dict(orient="records")
            resp = requests.post(
                api_url,
                json={"events": payload},
                headers={"X-API-Key": api_key},
                timeout=5,
            )
            logger.info("Forwarded micro-batch to API: HTTP %d", resp.status_code)
        except Exception as e:
            logger.warning("Failed to forward micro-batch to API: %s", e)


def main():
    parser_cli = argparse.ArgumentParser(description="SentinelLog Reusable Data Pipeline CLI")
    parser_cli.add_argument("logfile", help="Path to raw access log file to process")
    parser_cli.add_argument("--rules", default="rules/web_rules.yaml", help="Path to rules YAML")
    parser_cli.add_argument("--out", default="data/processed/out.parquet", help="Output Parquet path")
    parser_cli.add_argument("--summary", default="run_summary.json", help="Path to summary JSON")
    parser_cli.add_argument("--follow", action="store_true", help="Tail file in continuous streaming mode")
    parser_cli.add_argument("--api-url", default=None, help="Optional ingestion API URL for streaming")

    args = parser_cli.parse_args()

    if args.follow:
        stream_tail_pipeline(args.logfile, rules_path=args.rules, api_url=args.api_url)
    else:
        run_pipeline(args.logfile, rules_path=args.rules, out_path=args.out, summary_path=args.summary)


if __name__ == "__main__":
    main()
