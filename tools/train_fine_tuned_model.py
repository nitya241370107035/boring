"""
SentinelLog: Fine-Tuning Module on Real Cyber Security Corpora.
Combines Real-World CSIC 2010 HTTP Attack/Normal Data with Benchmark Synthetic Data.
Trains:
1. Random Forest Classifier
2. XGBoost Classifier
3. Logistic Regression Baseline
4. Isolation Forest Novelty Detector
Saves bundle to models/artifacts/rf_v1.joblib (with automatic backup of previous weights).
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from datetime import datetime, timezone
import re
import shutil
import urllib.parse
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

from pipeline.features import add_request_features
from models.train import train_all_models, DEFAULT_FEATURE_COLS


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


def load_csic_dataset(
    normal_path: str = "data/external/csic_2010/normal.txt",
    anomalous_path: str = "data/external/csic_2010/anomalous.txt",
) -> pd.DataFrame:
    print("[*] Reading real-world CSIC 2010 raw logs...")
    with open(normal_path, "r", encoding="utf-8", errors="replace") as f:
        norm_raw = re.split(r"\n(?=(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+)", f.read())

    with open(anomalous_path, "r", encoding="utf-8", errors="replace") as f:
        anom_raw = re.split(r"\n(?=(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+)", f.read())

    norm_records = [parse_csic_request(r) for r in norm_raw if parse_csic_request(r)]
    anom_records = [parse_csic_request(r) for r in anom_raw if parse_csic_request(r)]

    df_norm = pd.DataFrame(norm_records)
    df_norm["is_attack"] = 0
    df_norm["label"] = "benign"

    df_anom = pd.DataFrame(anom_records)
    df_anom["is_attack"] = 1
    df_anom["label"] = "attack"

    df = pd.concat([df_norm, df_anom], ignore_index=True)
    print(f"[+] Loaded {len(df):,} real HTTP requests (Normal: {len(df_norm):,}, Attack: {len(df_anom):,})")
    return df


def fine_tune_and_export():
    artifacts_dir = REPO_ROOT / "models" / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    current_model_path = artifacts_dir / "rf_v1.joblib"
    backup_path = artifacts_dir / "rf_v1_synthetic_only.joblib"

    if current_model_path.exists() and not backup_path.exists():
        print(f"[*] Backing up original model to: {backup_path.name}")
        shutil.copy2(current_model_path, backup_path)

    # 1. Load Real Data and extract features
    df_csic = load_csic_dataset()
    print("[*] Extracting features for real CSIC requests...")
    feat_csic = add_request_features(df_csic)
    X_csic = feat_csic[DEFAULT_FEATURE_COLS].fillna(0.0)
    y_csic = df_csic["is_attack"]

    # 2. Load Synthetic Data
    synth_path = REPO_ROOT / "data" / "processed" / "train_balanced.parquet"
    if synth_path.exists():
        print("[*] Incorporating balanced synthetic benchmark data...")
        df_synth = pd.read_parquet(synth_path)
        X_synth = df_synth[DEFAULT_FEATURE_COLS].fillna(0.0)
        y_synth = (df_synth["label"] != "benign").astype(int)
    else:
        X_synth, y_synth = pd.DataFrame(), pd.Series()

    # Stratified Splits (Zero-Leakage)
    X_csic_tr, X_csic_te, y_csic_tr, y_csic_te = train_test_split(
        X_csic, y_csic, test_size=0.2, stratify=y_csic, random_state=42
    )

    if not X_synth.empty:
        X_syn_tr, X_syn_te, y_syn_tr, y_syn_te = train_test_split(
            X_synth, y_synth, test_size=0.2, stratify=y_synth, random_state=42
        )
        # Sample synthetic partition to balance proportionally with real data
        sample_size = min(len(X_syn_tr), len(X_csic_tr))
        np.random.seed(42)
        syn_idx = np.random.choice(len(X_syn_tr), size=sample_size, replace=False)
        X_syn_sampled = X_syn_tr.iloc[syn_idx]
        y_syn_sampled = y_syn_tr.iloc[syn_idx]

        X_train_final = pd.concat([X_csic_tr, X_syn_sampled], ignore_index=True)
        y_train_final = pd.concat([y_csic_tr, y_syn_sampled], ignore_index=True)
    else:
        X_train_final = X_csic_tr
        y_train_final = y_csic_tr
        X_syn_te, y_syn_te = None, None

    print(f"[*] Training fine-tuned multi-tier model ensemble on {len(X_train_final):,} rows...")
    bundle = train_all_models(X_train_final, y_train_final, DEFAULT_FEATURE_COLS, artifact_dir=artifacts_dir)

    # Evaluate on Real Held-Out Test Set
    rf = bundle["model"]
    preds_csic = rf.predict(X_csic_te)
    probs_csic = rf.predict_proba(X_csic_te)[:, 1]

    acc = accuracy_score(y_csic_te, preds_csic)
    prec = precision_score(y_csic_te, preds_csic)
    rec = recall_score(y_csic_te, preds_csic)
    f1 = f1_score(y_csic_te, preds_csic)
    roc = roc_auc_score(y_csic_te, probs_csic)

    print("\n" + "="*65)
    print("   FINE-TUNED MODEL RESULTS ON HELD-OUT REAL TEST PARTITION")
    print("="*65)
    print(f"  Accuracy  : {acc*100:.2f}%")
    print(f"  Precision : {prec*100:.2f}%")
    print(f"  Recall    : {rec*100:.2f}%")
    print(f"  F1-Score  : {f1*100:.2f}%")
    print(f"  ROC-AUC   : {roc:.4f}")
    print("="*65)

    if X_syn_te is not None:
        preds_syn = rf.predict(X_syn_te)
        print(f"  Synthetic Benchmark Retention Accuracy: {accuracy_score(y_syn_te, preds_syn)*100:.2f}%")

    print(f"\n[OK] Model successfully fine-tuned and updated at: {current_model_path}")
    return bundle


if __name__ == "__main__":
    fine_tune_and_export()
