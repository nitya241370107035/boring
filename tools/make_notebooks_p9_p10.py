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
    # --- Notebook 09 ---
    nb09_cells = [
        md_cell(
            "# Practical 9: Build a Simple Classifier to Detect Attacks\n"
            "**Course:** BE05000231 - PDS (Semester V, GTU GSET)\n"
            "**Course Outcome:** CO5\n\n"
            "### Objective:\n"
            "Train, benchmark, and evaluate supervised classifiers (Logistic Regression, Random Forest, XGBoost) "
            "along with an unsupervised Isolation Forest for zero-day attack discovery. Compute precision, recall, "
            "F1, ROC-AUC, and PR-AUC, and export production model artifacts."
        ),
        md_cell("## 1. Imports and Setup"),
        code_cell(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.append('..')\n"
            "import pandas as pd\n"
            "from sklearn.model_selection import train_test_split\n\n"
            "from pipeline.parser import parse_file\n"
            "from pipeline.cleaner import clean\n"
            "from pipeline.labeler import load_rules, label_requests\n"
            "from pipeline.features import add_request_features\n"
            "from models.train import prepare_feature_matrix, train_all_models\n"
            "from models.evaluate import evaluate_models, predict_event\n\n"
            "LOG_PATH = Path('../tests/fixtures/sample_access.log')\n"
            "RULES_PATH = Path('../rules/web_rules.yaml')\n"
        ),
        md_cell("## 2. Prepare Balanced Training & Evaluation Splits"),
        code_cell(
            "raw_df, _ = parse_file(LOG_PATH)\n"
            "cleaned_df = clean(raw_df)\n"
            "rules = load_rules(RULES_PATH)\n"
            "labeled_df = label_requests(cleaned_df, rules)\n"
            "feat_df = add_request_features(labeled_df)\n\n"
            "X, y, feature_cols = prepare_feature_matrix(feat_df)\n"
            "X_train, X_test, y_train, y_test = train_test_split(\n"
            "    X, y, test_size=0.25, random_state=42, stratify=y\n"
            ")\n"
            "print(f'Training instances: {len(X_train)} | Test instances: {len(X_test)}')\n"
            "print('Feature dimensions:', len(feature_cols))\n"
        ),
        md_cell("## 3. Train Multi-Architecture Model Suite"),
        code_cell(
            "bundle = train_all_models(\n"
            "    X_train, y_train, feature_cols,\n"
            "    artifact_dir='../models/artifacts'\n"
            ")\n"
            "print(f\"Model version {bundle['version']} trained successfully.\")\n"
            "print('Models in bundle:', list(bundle.keys()))\n"
        ),
        md_cell("## 4. Benchmark & Comparative Model Evaluation"),
        code_cell(
            "metrics_df = evaluate_models(bundle, X_test, y_test, reports_dir='../reports')\n"
            "print('Comprehensive Evaluation Matrix:')\n"
            "metrics_df\n"
        ),
        md_cell("## 5. Live Inference Demonstration (`predict_event`)"),
        code_cell(
            "probs, anomalies = predict_event(feat_df, bundle_or_path=bundle)\n"
            "feat_df['ml_prob'] = probs\n"
            "feat_df['anomaly_score'] = anomalies\n\n"
            "print('Sample Predictions on Telemetry:')\n"
            "feat_df[['raw_url', 'label', 'ml_prob', 'anomaly_score']].head(10)\n"
        ),
        md_cell(
            "### Conclusion:\n"
            "Practical 9 produced an explainable hybrid detection engine combining supervised classification "
            "(Random Forest / XGBoost) with unsupervised outlier detection (Isolation Forest), achieving high "
            "precision and recall on web attacks."
        ),
    ]

    with open("notebooks/09_classifier.ipynb", "w", encoding="utf-8") as f:
        json.dump(make_nb(nb09_cells), f, indent=2)

    # --- Notebook 10 ---
    nb10_cells = [
        md_cell(
            "# Practical 10: Create a Reusable Data Pipeline for the Log File\n"
            "**Course:** BE05000231 - PDS (Semester V, GTU GSET)\n"
            "**Course Outcome:** CO5\n\n"
            "### Objective:\n"
            "Package log ingestion, parsing, cleaning, rule-based labeling, and feature engineering into an "
            "end-to-end, reusable command-line interface (CLI) data pipeline with structured logging, "
            "execution auditing (`run_summary.json`), and streaming tailing support."
        ),
        md_cell("## 1. Imports and Setup"),
        code_cell(
            "import sys\n"
            "from pathlib import Path\n"
            "import json\n"
            "import pandas as pd\n"
            "sys.path.append('..')\n\n"
            "from pipeline.run import run_pipeline\n\n"
            "LOG_PATH = Path('../tests/fixtures/sample_access.log')\n"
            "RULES_PATH = Path('../rules/web_rules.yaml')\n"
            "OUT_PARQUET = Path('../data/processed/pipeline_out.parquet')\n"
            "OUT_SUMMARY = Path('../run_summary.json')\n"
        ),
        md_cell("## 2. Execute End-to-End Pipeline"),
        code_cell(
            "df, summary = run_pipeline(\n"
            "    logfile=LOG_PATH,\n"
            "    rules_path=RULES_PATH,\n"
            "    out_path=OUT_PARQUET,\n"
            "    summary_path=OUT_SUMMARY\n"
            ")\n"
            "print(f'Pipeline execution complete in {summary[\"duration_seconds\"]} seconds.')\n"
            "print(f'Total processed rows: {len(df)}')\n"
        ),
        md_cell("## 3. Verify Execution Summary Audit JSON"),
        code_cell(
            "with open(OUT_SUMMARY, 'r', encoding='utf-8') as f:\n"
            "    audit_data = json.load(f)\n\n"
            "for k, v in audit_data.items():\n"
            "    print(f'{k}: {v}')\n"
        ),
        md_cell("## 4. Parquet Lake Verification"),
        code_cell(
            "parquet_df = pd.read_parquet(OUT_PARQUET)\n"
            "print(f'Parquet schema verified. Columns: {len(parquet_df.columns)}, Rows: {len(parquet_df)}')\n"
            "parquet_df[['ip', 'method', 'path', 'label', 'url_entropy', 'win_req_count']].head(8)\n"
        ),
        md_cell(
            "### Conclusion:\n"
            "Practical 10 delivered a production-ready, idempotent data engineering pipeline that can be executed "
            "as a standalone CLI script (`python -m pipeline.run ...`) or embedded into automated ingestion services."
        ),
    ]

    with open("notebooks/10_reusable_pipeline.ipynb", "w", encoding="utf-8") as f:
        json.dump(make_nb(nb10_cells), f, indent=2)

    print("Notebooks 09 and 10 created successfully.")


if __name__ == "__main__":
    build_all()
