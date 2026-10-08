"""
SentinelLog: Cross-Dataset Real-World Evaluation Benchmark.
Evaluates current trained model artifacts against the public CSIC 2010 Real-World HTTP Dataset.
Computes Accuracy, Precision, Recall, F1, ROC-AUC, and Confusion Matrix.
"""

import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import re
import urllib.parse
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from pipeline.features import add_request_features


def parse_csic_request(raw_str: str) -> dict | None:
    raw_str = raw_str.strip()
    if not raw_str:
        return None
    lines = raw_str.splitlines()
    first_line = lines[0].strip()
    parts = first_line.split()
    if len(parts) < 2:
        return None
    method = parts[0].upper()
    raw_url = parts[1]
    
    p = urllib.parse.urlparse(raw_url)
    path = p.path
    query = p.query
    
    ua = "Mozilla/5.0"
    for line in lines[1:]:
        if line.lower().startswith("user-agent:"):
            ua = line.split(":", 1)[1].strip()
            break
            
    body = ""
    parts_body = re.split(r"\r?\n\r?\n", raw_str, maxsplit=1)
    if len(parts_body) > 1:
        body = parts_body[1].strip()
        
    full_query = query
    if method == "POST" and body:
        full_query = (query + "&" + body) if query else body
        
    target_url = path + ("?" + full_query if full_query else "")
    decoded_url = urllib.parse.unquote_plus(target_url)
    
    return {
        "method": method,
        "url": target_url,
        "decoded_url": decoded_url,
        "query": full_query,
        "status": 200,
        "ua": ua,
    }


def evaluate_on_real_data(
    model_path: str = "models/artifacts/rf_v1.joblib",
    normal_path: str = "data/external/csic_2010/normal.txt",
    anomalous_path: str = "data/external/csic_2010/anomalous.txt",
    sample_size: int = 5000,
):
    print("=================================================================")
    print("   SENTINELLOG: EVALUATION ON REAL-WORLD HTTP ATTACK DATA")
    print("   Dataset: CSIC 2010 (Real HTTP Web Application Traffic)")
    print("=================================================================")

    bundle = joblib.load(model_path)
    feature_cols = bundle.get("features")
    rf_model = bundle.get("model")
    xgb_model = bundle.get("xgb_model")
    lr_model = bundle.get("lr_baseline")

    print(f"[*] Loading raw real requests (sample size: {sample_size} normal, {sample_size} attacks)...")
    with open(normal_path, "r", encoding="utf-8", errors="replace") as f:
        norm_raw = re.split(r"\n(?=(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+)", f.read())[:sample_size]

    with open(anomalous_path, "r", encoding="utf-8", errors="replace") as f:
        anom_raw = re.split(r"\n(?=(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+)", f.read())[:sample_size]

    norm_records = [parse_csic_request(r) for r in norm_raw if parse_csic_request(r)]
    anom_records = [parse_csic_request(r) for r in anom_raw if parse_csic_request(r)]

    df_norm = pd.DataFrame(norm_records)
    df_norm["label"] = "benign"
    df_norm["is_attack"] = 0

    df_anom = pd.DataFrame(anom_records)
    df_anom["label"] = "attack"
    df_anom["is_attack"] = 1

    df = pd.concat([df_norm, df_anom], ignore_index=True)
    print(f"[*] Total real requests parsed: {len(df):,} (Benign: {(df.is_attack==0).sum():,}, Attacks: {(df.is_attack==1).sum():,})")

    print("[*] Extracting 15 security features using pipeline/features.py...")
    feat_df = add_request_features(df)
    X = feat_df[feature_cols].fillna(0.0)
    y = df["is_attack"]

    models_to_test = {
        "Random Forest (rf_v1)": rf_model,
        "XGBoost Classifier": xgb_model,
        "Logistic Regression": lr_model,
    }

    results = []
    for name, clf in models_to_test.items():
        if clf is None:
            continue
        preds = clf.predict(X)
        probs = clf.predict_proba(X)[:, 1] if hasattr(clf, "predict_proba") else preds

        acc = accuracy_score(y, preds)
        prec = precision_score(y, preds, zero_division=0)
        rec = recall_score(y, preds, zero_division=0)
        f1 = f1_score(y, preds, zero_division=0)
        roc = roc_auc_score(y, probs)
        pr_auc = average_precision_score(y, probs)
        cm = confusion_matrix(y, preds)

        results.append({
            "Model": name,
            "Accuracy": f"{acc*100:.2f}%",
            "Precision": f"{prec*100:.2f}%",
            "Recall": f"{rec*100:.2f}%",
            "F1-Score": f"{f1*100:.2f}%",
            "ROC-AUC": f"{roc:.4f}",
            "PR-AUC": f"{pr_auc:.4f}",
            "True Positives (Attacks Caught)": cm[1, 1],
            "False Negatives (Attacks Missed)": cm[1, 0],
            "False Positives": cm[0, 1],
            "True Negatives": cm[0, 0],
        })

    results_df = pd.DataFrame(results)
    print("\n=== BENCHMARK RESULTS ===")
    print(results_df[["Model", "Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC"]].to_string(index=False))

    print("\n=== DETAILED CONFUSION MATRIX COUNTS ===")
    print(results_df[["Model", "True Positives (Attacks Caught)", "False Negatives (Attacks Missed)", "False Positives", "True Negatives"]].to_string(index=False))

    # Error analysis
    df["pred"] = rf_model.predict(X)
    tp = df[(df.is_attack == 1) & (df.pred == 1)]
    fn = df[(df.is_attack == 1) & (df.pred == 0)]
    fp = df[(df.is_attack == 0) & (df.pred == 1)]

    print("\n--- SAMPLE REAL ATTACKS DETECTED (True Positives) ---")
    for u in tp["decoded_url"].head(3):
        safe_u = u[:100].encode("ascii", errors="replace").decode("ascii")
        print("  [+] CAUGHT:", safe_u)

    print("\n--- SAMPLE REAL ATTACKS MISSED (False Negatives) ---")
    for u in fn["decoded_url"].head(3):
        safe_u = u[:100].encode("ascii", errors="replace").decode("ascii")
        print("  [-] MISSED:", safe_u)

    return results_df


if __name__ == "__main__":
    evaluate_on_real_data()
