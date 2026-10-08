"""
SentinelLog Machine Learning & Evaluation Module.
Implements dataset balancing, model training, evaluation, and explainability for Practicals 6 and 9.
"""

from models.balance import balance_dataset, compare_balancing_methods
from models.train import prepare_feature_matrix, train_all_models
from models.evaluate import evaluate_models, predict_event

__all__ = [
    "balance_dataset",
    "compare_balancing_methods",
    "prepare_feature_matrix",
    "train_all_models",
    "evaluate_models",
    "predict_event",
]
