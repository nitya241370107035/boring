from pathlib import Path
import pandas as pd
import pytest
from pipeline.cleaner import clean
from pipeline.labeler import evaluate_labeling, ground_truth_label, label_requests, load_rules
from pipeline.parser import parse_file

FIXTURE_PATH = Path("tests/fixtures/sample_access.log")
RULES_PATH = Path("rules/web_rules.yaml")


@pytest.fixture
def cleaned_df():
    df, _ = parse_file(FIXTURE_PATH)
    return clean(df)


def test_load_rules():
    rules = load_rules(RULES_PATH)
    assert len(rules) >= 5
    # Check severity sort order
    severities = [r["severity"] for r in rules]
    assert severities == sorted(severities, reverse=True)


def test_label_requests_attacks_and_benign(cleaned_df):
    rules = load_rules(RULES_PATH)
    labeled = label_requests(cleaned_df, rules, bf_threshold=5)

    assert "label" in labeled.columns
    assert "rule_ids" in labeled.columns

    # Verify SQLi detected
    sqli_hits = labeled[labeled["label"] == "sqli"]
    assert not sqli_hits.empty
    assert any("WEB-SQLI-001" in rids for rids in sqli_hits["rule_ids"])

    # Verify Traversal detected
    trav_hits = labeled[labeled["label"] == "path_traversal"]
    assert not trav_hits.empty

    # Verify XSS detected
    xss_hits = labeled[labeled["label"] == "xss"]
    assert not xss_hits.empty

    # Verify Command Injection detected
    cmd_hits = labeled[labeled["label"] == "cmd_injection"]
    assert not cmd_hits.empty

    # Verify Scanner UA detected
    scan_hits = labeled[labeled["label"] == "scanner"]
    assert not scan_hits.empty


def test_false_positive_trap(cleaned_df):
    """
    CRITICAL TEST: Ensures harmless search query for 'union station'
    is NOT falsely flagged as SQL injection.
    """
    rules = load_rules(RULES_PATH)
    labeled = label_requests(cleaned_df, rules)

    union_station = labeled[labeled["raw_url"].str.contains("union\\+station")]
    assert not union_station.empty
    assert union_station.iloc[0]["label"] == "benign"


def test_brute_force_detection(cleaned_df):
    rules = load_rules(RULES_PATH)
    labeled = label_requests(cleaned_df, rules, bf_threshold=5, bf_window="1min")

    bf_hits = labeled[labeled["label"] == "brute_force"]
    assert not bf_hits.empty
    # Verify that the brute-force IP (192.0.2.44) was flagged
    assert "192.0.2.44" in bf_hits["ip"].values


def test_ground_truth_and_evaluation(cleaned_df):
    rules = load_rules(RULES_PATH)
    labeled = label_requests(cleaned_df, rules)

    # Synthetic ground truth
    gt_df = pd.DataFrame([
        {
            "attacker_ip": "198.51.100.7",
            "start_ts": "2026-10-10T13:56:00Z",
            "end_ts": "2026-10-10T13:56:20Z",
            "attack_type": "sqli",
        }
    ])
    fused = ground_truth_label(labeled, gt_df)
    assert "ground_truth" in fused.columns

    eval_res = evaluate_labeling(fused, pred_col="label", true_col="ground_truth")
    assert "precision" in eval_res
    assert "recall" in eval_res
    assert "f1_score" in eval_res
    assert eval_res["tp"] > 0
