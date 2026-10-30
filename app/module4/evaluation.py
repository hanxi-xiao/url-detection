from __future__ import annotations

from time import perf_counter
from typing import Any

import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score


def positive_class_probability(model: Any, X: Any) -> np.ndarray:
    probabilities = np.asarray(model.predict_proba(X), dtype=float)
    classes = list(model.classes_)
    if 1 not in classes:
        raise ValueError("Model does not contain class 1 for phishing.")
    return probabilities[:, classes.index(1)]


def evaluate_binary_classifier(model: Any, X: Any, y_true: Any) -> dict[str, Any]:
    started_at = perf_counter()
    predictions = np.asarray(model.predict(X), dtype=int)
    probabilities = positive_class_probability(model, X)
    elapsed_ms = (perf_counter() - started_at) * 1000.0
    matrix = confusion_matrix(y_true, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = (
        int(matrix[0, 0]),
        int(matrix[0, 1]),
        int(matrix[1, 0]),
        int(matrix[1, 1]),
    )
    negative_total = true_negative + false_positive
    positive_total = true_positive + false_negative
    return {
        "accuracy": float(accuracy_score(y_true, predictions)),
        "precision": float(precision_score(y_true, predictions, zero_division=0)),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, probabilities)),
        "confusion_matrix": matrix.astype(int).tolist(),
        "false_positive_rate": false_positive / negative_total if negative_total else 0.0,
        "false_negative_rate": false_negative / positive_total if positive_total else 0.0,
        "average_inference_ms": elapsed_ms / max(len(predictions), 1),
    }
