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
    # --- Notebook 06 ---
    nb06_cells = [
        md_cell(
            "# Practical 6: Balance the Dataset for ML/DL Training\n"
            "**Course:** BE05000231 - PDS (Semester V, GTU GSET)\n"
            "**Course Outcome:** CO3\n\n"
            "### Objective:\n"
            "Analyze class imbalance in real-world security logs, enforce strict train/test separation "
            "to prevent data leakage, and evaluate Random Under-Sampling, Random Over-Sampling, SMOTE, and class weights."
        ),
        md_cell("## 1. Imports and Setup"),
        code_cell(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.append('..')\n"
            "import pandas as pd\n"
            "import matplotlib.pyplot as plt\n\n"
            "from pipeline.parser import parse_file\n"
            "from pipeline.cleaner import clean\n"
            "from pipeline.labeler import load_rules, label_requests\n"
            "from pipeline.features import add_request_features\n"
            "from models.balance import compare_balancing_methods, balance_dataset\n\n"
            "LOG_PATH = Path('../tests/fixtures/sample_access.log')\n"
            "RULES_PATH = Path('../rules/web_rules.yaml')\n"
        ),
        md_cell("## 2. Ingest, Clean, Label & Extract Features"),
        code_cell(
            "raw_df, _ = parse_file(LOG_PATH)\n"
            "cleaned_df = clean(raw_df)\n"
            "rules = load_rules(RULES_PATH)\n"
            "labeled_df = label_requests(cleaned_df, rules)\n"
            "feat_df = add_request_features(labeled_df)\n\n"
            "feature_cols = ['url_length', 'query_length', 'special_chars', 'special_ratio', 'url_entropy', 'digit_ratio']\n"
            "X = feat_df[feature_cols]\n"
            "# Binary target for modeling evaluation: benign vs attack\n"
            "y = (feat_df['label'] != 'benign').astype(int).map({0: 'benign', 1: 'attack'})\n"
            "print('Class Distribution (Raw Data):')\n"
            "print(y.value_counts(normalize=True).round(4) * 100)\n"
        ),
        md_cell(
            "## 3. Why Accuracy is a Misleading Metric in Cybersecurity\n"
            "In real production web logs, 99% of requests are benign. A trivial model predicting 'benign' "
            "for 100% of cases would achieve 99% accuracy while missing every single intrusion! "
            "Therefore, Precision, Recall, F1-score, and PR-AUC must be used."
        ),
        code_cell(
            "comp_df, artifacts = compare_balancing_methods(\n"
            "    X, y, test_size=0.25, random_state=42,\n"
            "    output_parquet='../data/processed/train_balanced.parquet'\n"
            ")\n"
            "print('Balancing Strategy Comparison Table:')\n"
            "comp_df\n"
        ),
        md_cell(
            "## 4. SMOTE Interpolation Caveat (Viva Critical Insight)\n"
            "SMOTE generates synthetic samples by interpolating between nearest neighbors in continuous vector space. "
            "It is mathematically sound for numeric features (e.g. entropy, lengths), but invalid for raw strings or categorical flags."
        ),
        code_cell(
            "X_train, y_train = artifacts['X_train'], artifacts['y_train']\n"
            "X_smote, y_smote = balance_dataset(X_train, y_train, method='smote')\n"
            "print('Before SMOTE: ', dict(y_train.value_counts()))\n"
            "print('After SMOTE:  ', dict(y_smote.value_counts()))\n"
        ),
        md_cell(
            "### Conclusion:\n"
            "Practical 6 proved the necessity of train-before-resample data hygiene to avoid data leakage, "
            "and established that over-sampling and SMOTE significantly improve recall on minority attack vectors."
        ),
    ]

    with open("notebooks/06_balance.ipynb", "w", encoding="utf-8") as f:
        json.dump(make_nb(nb06_cells), f, indent=2)

    # --- Notebook 07 ---
    nb07_cells = [
        md_cell(
            "# Practical 7: Data Wrangling for Aggregated Analysis\n"
            "**Course:** BE05000231 - PDS (Semester V, GTU GSET)\n"
            "**Course Outcome:** CO4\n\n"
            "### Objective:\n"
            "Wrangle security logs through IP aggregation, time-series resampling, multi-dimensional pivot tables, "
            "noise filtering (internal RFC 1918 IPs and verified search bots), and GeoIP threat intelligence enrichment."
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
            "from pipeline.wrangle import filter_noise, ip_summary, resample_traffic, create_pivots, enrich_geoip\n\n"
            "LOG_PATH = Path('../tests/fixtures/sample_access.log')\n"
            "RULES_PATH = Path('../rules/web_rules.yaml')\n"
            "ALLOWLIST_PATH = Path('../rules/allowlist.yaml')\n"
        ),
        md_cell("## 2. Ingest, Clean, and Label Telemetry"),
        code_cell(
            "raw_df, _ = parse_file(LOG_PATH)\n"
            "cleaned_df = clean(raw_df)\n"
            "rules = load_rules(RULES_PATH)\n"
            "df = label_requests(cleaned_df, rules)\n"
            "print(f'Total Ingested Records: {len(df)}')\n"
        ),
        md_cell("## 3. Perimeter Noise Filtering"),
        code_cell(
            "filtered_df = filter_noise(df, allowlist_path=ALLOWLIST_PATH)\n"
            "print(f'Retained Perimeter Events: {len(filtered_df)} (excluded internal RFC 1918 IPs and search spiders)')\n"
        ),
        md_cell("## 4. Per-IP Aggregation Summary"),
        code_cell(
            "summary = ip_summary(filtered_df)\n"
            "print('Top Attacking IPs:')\n"
            "summary.head(8)\n"
        ),
        md_cell("## 5. Time-Series Resampling (Traffic Rhythm)"),
        code_cell(
            "resampled = resample_traffic(filtered_df, freq='1min')\n"
            "print('Resampled 1-Minute Traffic:')\n"
            "resampled.head(10)\n"
        ),
        md_cell("## 6. Security Cross-Tabulation Pivot Tables"),
        code_cell(
            "pivots = create_pivots(filtered_df)\n"
            "print('HTTP Method by Attack Label:')\n"
            "print(pivots.get('method_by_label'))\n\n"
            "print('\\nHTTP Status Code by Attack Label:')\n"
            "print(pivots.get('status_by_label'))\n"
        ),
        md_cell("## 7. GeoIP Threat Intelligence Enrichment"),
        code_cell(
            "enriched_df = enrich_geoip(filtered_df)\n"
            "print('Enriched Geographic Attribution:')\n"
            "enriched_df[['ip', 'geo_country', 'geo_iso', 'label']].drop_duplicates(subset=['ip']).head(8)\n"
        ),
        md_cell(
            "### Conclusion:\n"
            "Practical 7 demonstrated aggregations, noise filtering, and geo-enrichment, transforming "
            "raw line-by-line log data into actionable security intelligence."
        ),
    ]

    with open("notebooks/07_wrangle.ipynb", "w", encoding="utf-8") as f:
        json.dump(make_nb(nb07_cells), f, indent=2)

    # --- Notebook 08 ---
    nb08_cells = [
        md_cell(
            "# Practical 8: Data Visualization and Exploratory Data Analysis\n"
            "**Course:** BE05000231 - PDS (Semester V, GTU GSET)\n"
            "**Course Outcome:** CO4\n\n"
            "### Objective:\n"
            "Produce comprehensive graphical visualizations and exploratory data analysis of security telemetry: "
            "traffic rhythms, attack campaign timelines, status distributions, behavioral signatures, and feature separation."
        ),
        md_cell("## 1. Imports and Setup"),
        code_cell(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.append('..')\n"
            "import pandas as pd\n"
            "import matplotlib.pyplot as plt\n"
            "import seaborn as sns\n\n"
            "from pipeline.parser import parse_file\n"
            "from pipeline.cleaner import clean\n"
            "from pipeline.labeler import load_rules, label_requests\n"
            "from pipeline.features import add_request_features, add_window_features\n"
            "from pipeline.wrangle import ip_summary, resample_traffic, enrich_geoip\n\n"
            "LOG_PATH = Path('../tests/fixtures/sample_access.log')\n"
            "RULES_PATH = Path('../rules/web_rules.yaml')\n"
        ),
        md_cell("## 2. Ingest and Prepare Dataset"),
        code_cell(
            "raw_df, _ = parse_file(LOG_PATH)\n"
            "cleaned_df = clean(raw_df)\n"
            "rules = load_rules(RULES_PATH)\n"
            "labeled_df = label_requests(cleaned_df, rules)\n"
            "req_feat = add_request_features(labeled_df)\n"
            "df = add_window_features(req_feat)\n"
            "df = enrich_geoip(df)\n"
            "print(f'Prepared {len(df)} records for visual EDA.')\n"
        ),
        md_cell("## 3. Visualization 1: Top 10 Attacking IPs"),
        code_cell(
            "summary = ip_summary(df)\n"
            "top10 = summary[summary['attacks'] > 0].head(10)\n\n"
            "plt.figure(figsize=(9, 4))\n"
            "sns.barplot(data=top10, x='attacks', y='ip', palette='Reds_r')\n"
            "plt.title('Top Adversarial IPs by Attack Volume')\n"
            "plt.xlabel('Total Attack Requests')\n"
            "plt.ylabel('Client IP Address')\n"
            "plt.tight_layout()\n"
            "plt.show()\n"
            "print('Insight: A tiny fraction of IP addresses generates the vast majority of threats.')\n"
        ),
        md_cell("## 4. Visualization 2: Status Code Distribution by Label"),
        code_cell(
            "plt.figure(figsize=(9, 4))\n"
            "sns.countplot(data=df, x='status', hue='label')\n"
            "plt.title('HTTP Status Codes Segmented by Attack Category')\n"
            "plt.xlabel('HTTP Status')\n"
            "plt.ylabel('Event Count')\n"
            "plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')\n"
            "plt.tight_layout()\n"
            "plt.show()\n"
            "print('Insight: Scanning probes trigger 404 clusters, brute force triggers 401s, while SQLi attempts often return 200.')\n"
        ),
        md_cell("## 5. Visualization 3: Feature Separation (Shannon Entropy vs URL Length)"),
        code_cell(
            "plt.figure(figsize=(9, 5))\n"
            "sns.scatterplot(data=df, x='url_length', y='url_entropy', hue='label', s=90)\n"
            "plt.title('Feature Separation: Shannon Entropy vs URL Length')\n"
            "plt.xlabel('URL Length')\n"
            "plt.ylabel('Shannon Information Entropy H(X)')\n"
            "plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')\n"
            "plt.tight_layout()\n"
            "plt.show()\n"
            "print('Insight: SQL injection and obfuscated commands clearly cluster in the upper-right quadrant.')\n"
        ),
        md_cell("## 6. Visualization 4: Attacker Activity Profile Heatmap"),
        code_cell(
            "ct = pd.crosstab(df['ip'], df['label'])\n"
            "plt.figure(figsize=(10, 5))\n"
            "sns.heatmap(ct, annot=True, fmt='d', cmap='YlOrRd')\n"
            "plt.title('Attacker Behavioral Signature Heatmap (IP vs Attack Category)')\n"
            "plt.xlabel('Threat Category')\n"
            "plt.ylabel('Client IP')\n"
            "plt.tight_layout()\n"
            "plt.show()\n"
            "print('Insight: Displays behavioral specialization per attacker IP.')\n"
        ),
        md_cell(
            "### Conclusion:\n"
            "Practical 8 delivered intuitive visual evidence confirming that cyber attacks "
            "exhibit distinct temporal, topological, and information-theoretic signatures."
        ),
    ]

    with open("notebooks/08_eda.ipynb", "w", encoding="utf-8") as f:
        json.dump(make_nb(nb08_cells), f, indent=2)

    print("Notebooks 06, 07, and 08 created successfully.")


if __name__ == "__main__":
    build_all()
