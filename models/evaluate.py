"""
SentinelLog Models: Evaluation & Inference Module (GTU Practical 9).
Evaluates classifiers across precision, recall, F1, ROC-AUC, and PR-AUC.
Exports evaluation metrics to reports/metrics.csv.
Provides real-time inference function predict_event() used by the Ingestion API.
"""

from pathlib import Path
from typing import Any
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


def evaluate_models(
    model_bundle: dict[str, Any],
    X_test: pd.DataFrame,
    y_test: pd.Series,
    reports_dir: str | Path = "reports",
) -> pd.DataFrame:
    """
    Evaluates all models in the bundle on the untouched test split.
    Outputs metrics summary table and saves reports/metrics.csv.
    """
    reports_path = Path(reports_dir)
    reports_path.mkdir(parents=True, exist_ok=True)

    models_to_test = {
        "LogisticRegression": model_bundle.get("lr_baseline"),
        "RandomForest": model_bundle.get("model"),
        "XGBoost": model_bundle.get("xgb_model"),
    }

    records = []
    for name, clf in models_to_test.items():
        if clf is None:
            continue

        y_pred = clf.predict(X_test)
        if hasattr(clf, "predict_proba"):
            y_prob = clf.predict_proba(X_test)[:, 1]
        else:
            y_prob = y_pred

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        try:
            roc = roc_auc_score(y_test, y_prob)
        except Exception:
            roc = 0.5
        try:
            pr_auc = average_precision_score(y_test, y_prob)
        except Exception:
            pr_auc = 0.0

        records.append({
            "model": name,
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc, 4),
            "pr_auc": round(pr_auc, 4),
        })

    # Isolation Forest anomaly scoring on test set
    iso = model_bundle.get("isolation_forest")
    if iso is not None:
        # Negative score_samples: higher value = more anomalous
        scores = -iso.score_samples(X_test)
        iso_pred = (scores > np.percentile(scores, 75)).astype(int)
        records.append({
            "model": "IsolationForest (Unsupervised)",
            "accuracy": round(accuracy_score(y_test, iso_pred), 4),
            "precision": round(precision_score(y_test, iso_pred, zero_division=0), 4),
            "recall": round(recall_score(y_test, iso_pred, zero_division=0), 4),
            "f1_score": round(f1_score(y_test, iso_pred, zero_division=0), 4),
            "roc_auc": round(roc_auc_score(y_test, scores), 4) if len(np.unique(y_test)) > 1 else 0.5,
            "pr_auc": round(average_precision_score(y_test, scores), 4) if len(np.unique(y_test)) > 1 else 0.0,
        })

    metrics_df = pd.DataFrame(records)
    csv_path = reports_path / "metrics.csv"
    metrics_df.to_csv(csv_path, index=False)

    return metrics_df


def predict_event(
    df: pd.DataFrame,
    bundle_or_path: dict[str, Any] | str | Path = "models/artifacts/rf_v1.joblib",
) -> tuple[np.ndarray, np.ndarray]:
    """
    Runs ML inference on a DataFrame of features.
    
    Returns:
        tuple of (ml_prob, anomaly_score):
            - ml_prob: array of attack probabilities [0.0 - 1.0] from Random Forest
            - anomaly_score: normalized anomaly scores [0.0 - 1.0] from Isolation Forest
    """
    if isinstance(bundle_or_path, (str, Path)):
        p = Path(bundle_or_path)
        if not p.exists():
            # Return zeroes if artifact not yet trained
            return np.zeros(len(df)), np.zeros(len(df))
        bundle = joblib.load(p)
    else:
        bundle = bundle_or_path

    features = bundle.get("features", [])
    model = bundle.get("model")
    iso = bundle.get("isolation_forest")

    # Align columns
    X = pd.DataFrame(index=df.index)
    for col in features:
        X[col] = df[col] if col in df.columns else 0.0
    X = X.fillna(0.0)

    # 1. Supervised probability
    if model is not None and hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)[:, 1]
    else:
        probs = np.zeros(len(df))

    # 2. Unsupervised anomaly score normalized between 0 and 1
    if iso is not None:
        raw_scores = -iso.score_samples(X)
        # Normalize: min-max scale with clipping
        min_s, max_s = -0.5, 0.5
        norm_scores = np.clip((raw_scores - min_s) / (max_s - min_s), 0.0, 1.0)
    else:
        norm_scores = np.zeros(len(df))

    return probs, norm_scores
