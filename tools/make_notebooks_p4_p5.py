import json
from pathlib import Path


def make_nb(cells):
    return {
        "cells": cells,
        "metadata": {
            "language_info": {"name": "python", "version": "3.11"},
            "kernelspec": {"name": "python3", "display_name": "Python 3"}
        },
        "nbformat": 4,
        "nbformat_minor": 5
    }


def md_cell(source):
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": source.splitlines(keepends=True) if isinstance(source, str) else source
    }


def code_cell(source):
    return {
        "cell_type": "code",
        "metadata": {},
        "execution_count": None,
        "outputs": [],
        "source": source.splitlines(keepends=True) if isinstance(source, str) else source
    }


def build_all():
    # --- Notebook 04 ---
    nb04_cells = [
        md_cell(
            "# Practical 4: Label Requests as Benign or Attack\n"
            "**Course:** BE05000231 - PDS (Semester V, GTU GSET)\n"
            "**Course Outcome:** CO2\n\n"
            "### Objective:\n"
            "Label HTTP requests as benign or specific attack classes (SQLi, XSS, Path Traversal, Scanners, Brute Force) "
            "using YAML signature rules mapped to OWASP Top 10 and MITRE ATT&CK, coupled with behavioral sliding-window detection "
            "and ground-truth verification."
        ),
        md_cell("## 1. Imports and Setup"),
        code_cell(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.append('..')\n"
            "import pandas as pd\n\n"
            "from pipeline.parser import parse_file\n"
            "from pipeline.cleaner import clean\n"
            "from pipeline.labeler import load_rules, label_requests, ground_truth_label, evaluate_labeling\n\n"
            "LOG_PATH = Path('../tests/fixtures/sample_access.log')\n"
            "RULES_PATH = Path('../rules/web_rules.yaml')\n"
        ),
        md_cell("## 2. Ingest, Parse, and Clean Access Logs"),
        code_cell(
            "raw_df, _ = parse_file(LOG_PATH)\n"
            "cleaned_df = clean(raw_df)\n"
            "print(f'Total cleaned records: {len(cleaned_df)}')\n"
        ),
        md_cell("## 3. Load Detection Rules & Map to Threat Frameworks"),
        code_cell(
            "rules = load_rules(RULES_PATH)\n"
            "print(f'Loaded {len(rules)} signature rules:')\n"
            "for r in rules:\n"
            "    print(f\"  [{r['id']}] {r['name']} -> Label: {r['label']}, Severity: {r['severity']}, OWASP: {r.get('owasp')}, MITRE: {r.get('mitre')}\")\n"
        ),
        md_cell("## 4. Run Rule Matching & Sliding-Window Brute Force Detection"),
        code_cell(
            "labeled_df = label_requests(cleaned_df, rules, bf_threshold=5, bf_window='1min')\n"
            "print('Class Distribution:')\n"
            "print(labeled_df['label'].value_counts())\n"
        ),
        md_cell(
            "## 5. False Positive Trap Verification\n"
            "A critical check in cyber-security log analysis: ensure harmless search queries containing keywords like "
            "`union station` do NOT get falsely labeled as SQL injection."
        ),
        code_cell(
            "trap_row = labeled_df[labeled_df['raw_url'].str.contains('union\\+station')]\n"
            "print('Search query trap row:')\n"
            "print(trap_row[['ip', 'raw_url', 'label', 'rule_ids']].to_dict(orient='records'))\n"
        ),
        md_cell(
            "## 6. Explainability: Inspect Rule Firing Traces\n"
            "Every detected alert records the exact rule IDs that triggered it in `rule_ids`."
        ),
        code_cell(
            "sample_attacks = labeled_df[labeled_df['label'] != 'benign'][['ip', 'method', 'raw_url', 'label', 'rule_ids']].head(10)\n"
            "sample_attacks\n"
        ),
        md_cell("## 7. Ground Truth Fusion and Evaluation"),
        code_cell(
            "# Simulated ground truth from controlled lab capture\n"
            "gt_records = pd.DataFrame([\n"
            "    {'attacker_ip': '198.51.100.7', 'start_ts': '2026-10-10T13:56:00Z', 'end_ts': '2026-10-10T13:56:20Z', 'attack_type': 'sqli'},\n"
            "    {'attacker_ip': '198.51.100.12', 'start_ts': '2026-10-10T13:56:20Z', 'end_ts': '2026-10-10T13:56:32Z', 'attack_type': 'path_traversal'},\n"
            "    {'attacker_ip': '192.0.2.44', 'start_ts': '2026-10-10T13:57:00Z', 'end_ts': '2026-10-10T13:57:30Z', 'attack_type': 'brute_force'},\n"
            "])\n"
            "fused_df = ground_truth_label(labeled_df, gt_records)\n"
            "metrics = evaluate_labeling(fused_df, pred_col='label', true_col='ground_truth')\n"
            "print(f\"Precision: {metrics['precision']:.4f}\")\n"
            "print(f\"Recall:    {metrics['recall']:.4f}\")\n"
            "print(f\"F1-Score:  {metrics['f1_score']:.4f}\")\n"
            "print(f\"Confusion Matrix:\\n{pd.DataFrame(metrics['confusion_matrix'])}\")\n"
        ),
        md_cell(
            "### Conclusion:\n"
            "Practical 4 demonstrated explainable signature-based and behavioral labeling mapped to industry standard "
            "OWASP Top 10 and MITRE ATT&CK taxonomies, avoiding circular reasoning by validating against independent ground-truth data."
        ),
    ]

    with open("notebooks/04_labeling.ipynb", "w", encoding="utf-8") as f:
        json.dump(make_nb(nb04_cells), f, indent=2)

    # --- Notebook 05 ---
    nb05_cells = [
        md_cell(
            "# Practical 5: Feature Engineering for Anomaly Detection\n"
            "**Course:** BE05000231 - PDS (Semester V, GTU GSET)\n"
            "**Course Outcome:** CO3\n\n"
            "### Objective:\n"
            "Extract dual-level numeric and categorical features for machine learning: request-level syntactic, "
            "statistical, and Shannon entropy indicators, plus IP-level sliding time-window features (1m and 5m)."
        ),
        md_cell("## 1. Imports and Setup"),
        code_cell(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.append('..')\n"
            "import pandas as pd\n\n"
            "from pipeline.parser import parse_file\n"
            "from pipeline.cleaner import clean\n"
            "from pipeline.labeler import load_rules, label_requests\n"
            "from pipeline.features import add_request_features, add_window_features, generate_feature_catalogue, shannon_entropy\n\n"
            "LOG_PATH = Path('../tests/fixtures/sample_access.log')\n"
            "RULES_PATH = Path('../rules/web_rules.yaml')\n"
        ),
        md_cell("## 2. Ingest, Parse, Clean, and Label Base Logs"),
        code_cell(
            "raw_df, _ = parse_file(LOG_PATH)\n"
            "cleaned_df = clean(raw_df)\n"
            "rules = load_rules(RULES_PATH)\n"
            "labeled_df = label_requests(cleaned_df, rules)\n"
            "print(f'Input records: {len(labeled_df)}')\n"
        ),
        md_cell("## 3. Shannon Information Entropy Demonstration"),
        code_cell(
            "urls = [\n"
            "    '/index.html',\n"
            "    '/products.php?id=1',\n"
            "    '/search?q=shoes',\n"
            "    '/products.php?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--',\n"
            "    '/items.php?cat=shoes%2527%20OR%201%3D1--'\n"
            "]\n"
            "for u in urls:\n"
            "    print(f'Entropy: {shannon_entropy(u):.4f} | URL: {u}')\n"
        ),
        md_cell("## 4. Engineer Request-Level Features"),
        code_cell(
            "req_feat = add_request_features(labeled_df)\n"
            "request_cols = [\n"
            "    'url_length', 'query_length', 'special_chars', 'special_ratio',\n"
            "    'url_entropy', 'digit_ratio', 'has_sql_kw', 'has_traversal',\n"
            "    'ua_class', 'is_404', 'method_is_post'\n"
            "]\n"
            "req_feat[request_cols].head(8)\n"
        ),
        md_cell("## 5. Engineer IP-Level Sliding Time-Window Features (5-minute window)"),
        code_cell(
            "win_feat = add_window_features(req_feat, window='5min')\n"
            "window_cols = [\n"
            "    'ip', 'ts', 'win_req_count', 'win_ratio_404', 'win_unique_paths',\n"
            "    'win_path_scan_ratio', 'win_gap_mean', 'win_gap_std'\n"
            "]\n"
            "win_feat[window_cols].tail(10)\n"
        ),
        md_cell("## 6. Feature Comparison Across Attack Categories"),
        code_cell(
            "print('Mean URL Length by Label:')\n"
            "print(win_feat.groupby('label')['url_length'].mean())\n\n"
            "print('\\nMean URL Entropy by Label:')\n"
            "print(win_feat.groupby('label')['url_entropy'].mean())\n\n"
            "print('\\nMean 404 Ratio in Window by Label:')\n"
            "print(win_feat.groupby('label')['win_ratio_404'].mean())\n"
        ),
        md_cell("## 7. Master Feature Catalogue Export"),
        code_cell(
            "cat_path = Path('../data/processed/feature_catalogue.csv')\n"
            "catalogue = generate_feature_catalogue(cat_path)\n"
            "print(f'Feature Catalogue exported to {cat_path} with {len(catalogue)} features:')\n"
            "catalogue[['feature', 'level', 'type', 'description']]\n"
        ),
        md_cell(
            "### Conclusion:\n"
            "Practical 5 extracted 20+ features across request and temporal sliding window levels, providing "
            "signals that clearly separate scanning, brute force, and injection attacks from normal web browsing."
        ),
    ]

    with open("notebooks/05_feature_engineering.ipynb", "w", encoding="utf-8") as f:
        json.dump(make_nb(nb05_cells), f, indent=2)

    print("Notebooks 04 and 05 created successfully.")


if __name__ == "__main__":
    build_all()
