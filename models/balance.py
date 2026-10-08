"""
SentinelLog Models: Class Balancing Module (GTU Practical 6).
Addresses severe class imbalance in security datasets.
Evaluates Random Under-Sampling, Random Over-Sampling, SMOTE, and Cost-Sensitive Weighting.
Enforces strict train-test separation prior to resampling to prevent data leakage.
"""

from collections import Counter
from pathlib import Path
from typing import Any
from imblearn.over_sampling import RandomOverSampler, SMOTE
from imblearn.under_sampling import RandomUnderSampler
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split


def get_numeric_features(df: pd.DataFrame) -> list[str]:
    """Identifies numeric continuous features suitable for interpolation techniques like SMOTE."""
    exclude = {"status", "is_4xx", "is_404", "is_5xx", "has_sql_kw", "has_script_tag",
               "has_traversal", "has_cmd_kw", "method_is_post", "is_rare_method", "encoding_depth"}
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    return [c for c in numeric_cols if c not in exclude]


def balance_dataset(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    method: str = "smote",
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.Series]:
    """
    Applies resampling strictly to the training partition.
    
    Methods:
        - 'none': Untouched training data.
        - 'under': Random Under-Sampling.
        - 'over': Random Over-Sampling.
        - 'smote': Synthetic Minority Over-sampling Technique.
    """
    if method == "none" or method is None:
        return X_train.copy(), y_train.copy()

    counts = Counter(y_train)
    min_count = min(counts.values())

    if method == "under":
        rus = RandomUnderSampler(random_state=random_state)
        X_res, y_res = rus.fit_resample(X_train, y_train)
        return pd.DataFrame(X_res, columns=X_train.columns), pd.Series(y_res, name=y_train.name)

    elif method == "over":
        ros = RandomOverSampler(random_state=random_state)
        X_res, y_res = ros.fit_resample(X_train, y_train)
        return pd.DataFrame(X_res, columns=X_train.columns), pd.Series(y_res, name=y_train.name)

    elif method == "smote":
        # Adaptive k_neighbors to accommodate small class counts
        k_neighbors = max(1, min(3, min_count - 1)) if min_count > 1 else 1
        if min_count <= 1:
            # If minority class has only 1 sample, fallback to RandomOverSampler
            ros = RandomOverSampler(random_state=random_state)
            X_res, y_res = ros.fit_resample(X_train, y_train)
        else:
            sm = SMOTE(k_neighbors=k_neighbors, random_state=random_state)
            X_res, y_res = sm.fit_resample(X_train, y_train)
        return pd.DataFrame(X_res, columns=X_train.columns), pd.Series(y_res, name=y_train.name)

    else:
        raise ValueError(f"Unknown balancing method: {method}")


def compare_balancing_methods(
    X: pd.DataFrame,
    y: pd.Series,
    test_size: float = 0.25,
    random_state: int = 42,
    output_parquet: str | Path | None = "data/processed/train_balanced.parquet",
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """
    Splits data first, trains a benchmark Random Forest on each balancing strategy,
    and returns a comparative performance matrix evaluated on the untouched test split.
    """
    # 1. Strict split first to guarantee zero data leakage
    # If minority classes have only 1 sample, use regular split instead of stratify
    class_counts = Counter(y)
    can_stratify = all(c >= 2 for c in class_counts.values())
    strat = y if can_stratify else None

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=strat
    )

    methods = ["none", "under", "over", "smote", "class_weight"]
    results = []
    best_f1 = -1.0
    best_variant = (X_train, y_train)

    for m in methods:
        if m == "class_weight":
            clf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=random_state)
            clf.fit(X_train, y_train)
            X_cur, y_cur = X_train, y_train
        else:
            X_res, y_res = balance_dataset(X_train, y_train, method=m, random_state=random_state)
            clf = RandomForestClassifier(n_estimators=100, random_state=random_state)
            clf.fit(X_res, y_res)
            X_cur, y_cur = X_res, y_res

        y_pred = clf.predict(X_test)
        prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
        rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
        f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

        results.append({
            "method": m,
            "train_samples": len(X_cur),
            "test_samples": len(X_test),
            "precision_weighted": round(prec, 4),
            "recall_weighted": round(rec, 4),
            "f1_weighted": round(f1, 4),
        })

        if f1 > best_f1:
            best_f1 = f1
            best_variant = (X_cur, y_cur)

    comparison_df = pd.DataFrame(results)

    # Save best balanced training split if requested
    if output_parquet:
        out_p = Path(output_parquet)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        best_df = best_variant[0].copy()
        best_df["target_label"] = best_variant[1].values
        best_df.to_parquet(out_p, index=False)

    return comparison_df, {
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
        "best_variant": best_variant,
    }
