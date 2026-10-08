from pathlib import Path
import tempfile
import numpy as np
import pandas as pd
import pytest
from models.balance import balance_dataset, compare_balancing_methods, get_numeric_features


@pytest.fixture
def imbalanced_data():
    # 90 benign samples, 10 attack samples
    np.random.seed(42)
    n = 100
    X = pd.DataFrame({
        "url_length": np.concatenate([np.random.normal(20, 5, 90), np.random.normal(80, 15, 10)]),
        "url_entropy": np.concatenate([np.random.normal(3.0, 0.2, 90), np.random.normal(4.5, 0.3, 10)]),
        "special_chars": np.concatenate([np.random.randint(0, 3, 90), np.random.randint(5, 12, 10)]),
        "status": np.concatenate([[200] * 90, [404] * 10]),
    })
    y = pd.Series(["benign"] * 90 + ["sqli"] * 10, name="label")
    return X, y


def test_get_numeric_features(imbalanced_data):
    X, _ = imbalanced_data
    num_cols = get_numeric_features(X)
    assert "url_length" in num_cols
    assert "url_entropy" in num_cols
    assert "status" not in num_cols  # Excluded categorical status


def test_balance_dataset_methods(imbalanced_data):
    X, y = imbalanced_data
    # 1. None
    X_none, y_none = balance_dataset(X, y, method="none")
    assert len(X_none) == len(X)

    # 2. Under-sampling
    X_under, y_under = balance_dataset(X, y, method="under")
    assert (y_under == "sqli").sum() == (y_under == "benign").sum()

    # 3. Over-sampling
    X_over, y_over = balance_dataset(X, y, method="over")
    assert (y_over == "sqli").sum() == 90

    # 4. SMOTE
    X_smote, y_smote = balance_dataset(X, y, method="smote")
    assert (y_smote == "sqli").sum() == 90


def test_compare_balancing_methods_and_parquet(imbalanced_data):
    X, y = imbalanced_data
    with tempfile.TemporaryDirectory() as tmpdir:
        out_parquet = Path(tmpdir) / "train_balanced.parquet"
        comp_df, artifacts = compare_balancing_methods(
            X, y, test_size=0.2, random_state=42, output_parquet=out_parquet
        )

        assert not comp_df.empty
        assert "method" in comp_df.columns
        assert "f1_weighted" in comp_df.columns
        assert out_parquet.exists()

        loaded = pd.read_parquet(out_parquet)
        assert not loaded.empty
        assert "target_label" in loaded.columns
