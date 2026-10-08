"""
SentinelLog Pipeline: Labeling Module (GTU Practical 4).
Applies rule-based signatures from YAML, behavioral sliding-window brute-force detection,
and ground-truth verification from controlled lab attack logs.
"""

from pathlib import Path
import re
from typing import Any
import pandas as pd
import yaml


def load_rules(path: str | Path = "rules/web_rules.yaml") -> list[dict[str, Any]]:
    """
    Loads YAML signature rules and compiles regex expressions.
    Sorts rules in descending order of severity so specific high-risk threats
    (SQLi, Cmd Injection) take precedence over general scanner detections.
    """
    rule_file = Path(path)
    if not rule_file.exists():
        raise FileNotFoundError(f"Rules YAML file not found: {rule_file}")

    with open(rule_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    rules = data.get("rules", [])
    for r in rules:
        r["_compiled_re"] = re.compile(r["regex"])

    # Sort descending by severity
    rules.sort(key=lambda x: x.get("severity", 0), reverse=True)
    return rules


def label_requests(
    df: pd.DataFrame,
    rules: list[dict[str, Any]] | None = None,
    rules_path: str | Path = "rules/web_rules.yaml",
    bf_threshold: int = 5,
    bf_window: str = "1min",
) -> pd.DataFrame:
    """
    Labels access requests as benign or specific attack classes.
    
    1. Evaluates regex rules against decoded_url, raw_url, and ua.
    2. Records all fired rule IDs in 'rule_ids' list for explainability.
    3. Runs a sliding-window behavioral detector for credential brute-force attacks.
    """
    if df.empty:
        df["label"] = pd.Series(dtype=str)
        df["rule_ids"] = pd.Series(dtype=object)
        return df

    if rules is None:
        rules = load_rules(rules_path)

    df = df.copy()
    n_rows = len(df)
    df["label"] = "benign"
    df["rule_ids"] = [[] for _ in range(n_rows)]

    # 1. Signature Rule Evaluation
    for r in rules:
        target_col = r.get("target", "decoded_url")
        if target_col not in df.columns:
            continue

        pattern: re.Pattern = r["_compiled_re"]
        target_series = df[target_col].fillna("").astype(str)
        mask = target_series.map(lambda val: bool(pattern.search(val)))

        # Update rule_ids for all hits (explainability)
        for idx in df.index[mask]:
            df.at[idx, "rule_ids"].append(r["id"])

        # Update label if currently benign (since rules are sorted by severity)
        df.loc[mask & (df["label"] == "benign"), "label"] = r["label"]

    # 2. Behavioral Brute-Force Detection (POST bursts to authentication endpoints)
    if "path" in df.columns and "method" in df.columns and "ip" in df.columns and "ts" in df.columns:
        auth_mask = (
            df["path"].str.contains(r"(?i)(?:login|signin|auth|session)", regex=True)
            & (df["method"] == "POST")
        )
        if auth_mask.any():
            auth_df = df[auth_mask]
            # Group by IP and time window
            counts = (
                auth_df.groupby(["ip", pd.Grouper(key="ts", freq=bf_window)])
                .size()
                .rename("bf_count")
                .reset_index()
            )
            suspicious_windows = counts[counts["bf_count"] >= bf_threshold]

            for _, row in suspicious_windows.iterrows():
                win_start = row["ts"]
                win_end = win_start + pd.Timedelta(bf_window)
                in_window = (
                    auth_mask
                    & (df["ip"] == row["ip"])
                    & (df["ts"] >= win_start)
                    & (df["ts"] < win_end)
                )
                df.loc[in_window, "label"] = "brute_force"
                for idx in df.index[in_window]:
                    if "BEH-AUTH-BF" not in df.at[idx, "rule_ids"]:
                        df.at[idx, "rule_ids"].append("BEH-AUTH-BF")

    return df


def ground_truth_label(
    df: pd.DataFrame,
    attacks_df_or_path: pd.DataFrame | str | Path,
) -> pd.DataFrame:
    """
    Labels requests using independent ground-truth attack run records
    (attacker_ip, start_ts, end_ts, attack_type).
    Eliminates circular evaluation by providing an objective reference.
    """
    df = df.copy()
    df["ground_truth"] = "benign"

    if isinstance(attacks_df_or_path, (str, Path)):
        attacks = pd.read_csv(attacks_df_or_path)
    else:
        attacks = attacks_df_or_path.copy()

    attacks["start_ts"] = pd.to_datetime(attacks["start_ts"], utc=True)
    attacks["end_ts"] = pd.to_datetime(attacks["end_ts"], utc=True)

    for _, att in attacks.iterrows():
        mask = (
            (df["ip"] == att["attacker_ip"])
            & (df["ts"] >= att["start_ts"])
            & (df["ts"] <= att["end_ts"])
        )
        df.loc[mask, "ground_truth"] = att.get("attack_type", "attack")

    return df


def evaluate_labeling(
    df: pd.DataFrame,
    pred_col: str = "label",
    true_col: str = "ground_truth",
) -> dict[str, Any]:
    """
    Computes agreement metrics between rule-generated labels and ground-truth records.
    """
    if pred_col not in df.columns or true_col not in df.columns:
        raise ValueError(f"Columns {pred_col} and {true_col} must exist in DataFrame")

    confusion = pd.crosstab(df[true_col], df[pred_col], margins=True)
    binary_true = (df[true_col] != "benign").astype(int)
    binary_pred = (df[pred_col] != "benign").astype(int)

    tp = int(((binary_true == 1) & (binary_pred == 1)).sum())
    fp = int(((binary_true == 0) & (binary_pred == 1)).sum())
    fn = int(((binary_true == 1) & (binary_pred == 0)).sum())
    tn = int(((binary_true == 0) & (binary_pred == 0)).sum())

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0

    return {
        "confusion_matrix": confusion.to_dict(),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
    }
