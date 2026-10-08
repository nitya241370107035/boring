"""
SentinelLog Models: Training Module (GTU Practical 9).
Trains supervised classifiers (Logistic Regression, Random Forest, XGBoost)
and unsupervised anomaly detector (Isolation Forest on benign traffic).
Serializes best model bundles to models/artifacts/rf_v1.joblib.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

DEFAULT_FEATURE_COLS = [
    "url_length",
    "query_length",
    "num_params",
    "special_chars",
    "special_ratio",
    "digit_ratio",
    "upper_ratio",
    "url_entropy",
    "has_sql_kw",
    "has_script_tag",
    "has_traversal",
    "has_cmd_kw",
    "method_is_post",
    "is_rare_method",
    "is_404",
]


def prepare_feature_matrix(
    df: pd.DataFrame,
    feature_cols: list[str] | None = None,
) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    """Extracts numeric feature matrix X and target y (binary attack indicator)."""
    cols = feature_cols or DEFAULT_FEATURE_COLS
    available_cols = [c for c in cols if c in df.columns]

    X = df[available_cols].copy().fillna(0.0)
    # Binary classification target: 0 = benign, 1 = attack
    if "label" in df.columns:
        y = (df["label"] != "benign").astype(int)
    elif "target_label" in df.columns:
        y = (df["target_label"] != "benign").astype(int)
    else:
        y = pd.Series([0] * len(df))

    return X, y, available_cols


def train_all_models(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    feature_cols: list[str],
    artifact_dir: str | Path = "models/artifacts",
) -> dict[str, Any]:
    """
    Trains multiple model architectures on the training partition:
    1. Scaled Logistic Regression (Linear baseline)
    2. Random Forest (Primary ensemble model)
    3. XGBoost (Gradient Boosted Trees)
    4. Isolation Forest (Unsupervised novelty detector trained on benign only)
    """
    artifacts_path = Path(artifact_dir)
    artifacts_path.mkdir(parents=True, exist_ok=True)

    # Subsample if dataset is large (e.g. 10 Lakh rows) to train rapidly without memory starvation
    if len(X_train) > 50000:
        np.random.seed(42)
        fit_idx = np.random.choice(len(X_train), size=50000, replace=False)
        X_fit = X_train.iloc[fit_idx] if hasattr(X_train, "iloc") else X_train[fit_idx]
        y_fit = y_train.iloc[fit_idx] if hasattr(y_train, "iloc") else y_train[fit_idx]
    else:
        X_fit = X_train
        y_fit = y_train

    # 1. Baseline: Logistic Regression with StandardScaler
    lr_pipeline = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=42))
    lr_pipeline.fit(X_fit, y_fit)

    # 2. Primary: Random Forest Classifier
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(X_fit, y_fit)

    # 3. XGBoost Classifier
    xgb = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        tree_method="hist",
        eval_metric="logloss",
        random_state=42,
    )
    xgb.fit(X_fit, y_fit)

    # 4. Unsupervised: Isolation Forest (trained exclusively on benign instances)
    benign_mask = (y_fit == 0)
    X_benign = X_fit[benign_mask] if benign_mask.any() else X_fit
    iso = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
    iso.fit(X_benign)

    # Package production model bundle
    bundle = {
        "model_name": "RandomForestClassifier",
        "model": rf,
        "lr_baseline": lr_pipeline,
        "xgb_model": xgb,
        "isolation_forest": iso,
        "features": feature_cols,
        "version": "1.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }

    joblib_path = artifacts_path / "rf_v1.joblib"
    joblib.dump(bundle, joblib_path)

    return bundle
