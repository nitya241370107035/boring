from pathlib import Path
import tempfile
import numpy as np
import pandas as pd
import pytest
from models.evaluate import evaluate_models, predict_event
from models.train import prepare_feature_matrix, train_all_models


@pytest.fixture
def dummy_train_test():
    np.random.seed(42)
    # Generate 120 samples
    n = 120
    df = pd.DataFrame({
        "url_length": np.concatenate([np.random.normal(20, 5, 80), np.random.normal(90, 20, 40)]),
        "query_length": np.concatenate([np.random.normal(5, 2, 80), np.random.normal(50, 15, 40)]),
        "num_params": np.concatenate([np.random.randint(0, 2, 80), np.random.randint(3, 8, 40)]),
        "special_chars": np.concatenate([np.random.randint(0, 3, 80), np.random.randint(5, 12, 40)]),
        "special_ratio": np.concatenate([np.random.uniform(0, 0.1, 80), np.random.uniform(0.2, 0.5, 40)]),
        "digit_ratio": np.concatenate([np.random.uniform(0, 0.05, 80), np.random.uniform(0.1, 0.3, 40)]),
        "upper_ratio": np.concatenate([np.random.uniform(0, 0.05, 80), np.random.uniform(0.1, 0.3, 40)]),
        "url_entropy": np.concatenate([np.random.normal(3.0, 0.2, 80), np.random.normal(4.6, 0.3, 40)]),
        "has_sql_kw": np.concatenate([[0] * 80, [1] * 40]),
        "has_script_tag": np.concatenate([[0] * 80, [0] * 40]),
        "has_traversal": np.concatenate([[0] * 80, [0] * 40]),
        "has_cmd_kw": np.concatenate([[0] * 80, [0] * 40]),
        "method_is_post": np.concatenate([[0] * 80, [1] * 40]),
        "is_rare_method": np.concatenate([[0] * 80, [0] * 40]),
        "is_404": np.concatenate([[0] * 80, [1] * 40]),
        "label": ["benign"] * 80 + ["attack"] * 40,
    })
    return df


def test_train_and_evaluate_models(dummy_train_test):
    df = dummy_train_test
    X, y, feature_cols = prepare_feature_matrix(df)

    with tempfile.TemporaryDirectory() as tmpdir:
        art_dir = Path(tmpdir) / "artifacts"
        rep_dir = Path(tmpdir) / "reports"

        # 1. Train models
        bundle = train_all_models(X, y, feature_cols, artifact_dir=art_dir)
        assert (art_dir / "rf_v1.joblib").exists()
        assert bundle["model_name"] == "RandomForestClassifier"

        # 2. Evaluate models
        metrics_df = evaluate_models(bundle, X, y, reports_dir=rep_dir)
        assert not metrics_df.empty
        assert (rep_dir / "metrics.csv").exists()
        assert "RandomForest" in metrics_df["model"].values

        # 3. Predict event inference
        probs, anomalies = predict_event(df, bundle_or_path=bundle)
        assert len(probs) == len(df)
        assert len(anomalies) == len(df)
        # Attacks should have higher probabilities than benign
        assert probs[80:].mean() > probs[:80].mean()
