from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from app.module6.evaluation import save_training_report

from .data import prepare_dataset
from .modeling import save_model_bundle, train_and_compare
from .risk import RiskThresholds


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train Module 4 phishing detection models.")
    parser.add_argument("--data", required=True, help="Prepared CSV dataset path.")
    parser.add_argument(
        "--extra-data",
        action="append",
        default=[],
        help="Optional additional prepared CSV dataset paths to append before splitting.",
    )
    parser.add_argument("--output-dir", default="artifacts", help="Output directory.")
    parser.add_argument("--validation-size", type=float, default=0.10)
    parser.add_argument("--test-size", type=float, default=0.20)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument(
        "--selection-metric",
        choices=("accuracy", "precision", "recall", "f1", "roc_auc"),
        default="f1",
    )
    parser.add_argument("--suspicious-threshold", type=float, default=0.45)
    parser.add_argument("--high-risk-threshold", type=float, default=0.90)
    parser.add_argument("--model-version", default=None)
    parser.add_argument("--dataset-version", default="unspecified")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    thresholds = RiskThresholds(
        suspicious=args.suspicious_threshold,
        high_risk=args.high_risk_threshold,
    )
    dataset = prepare_dataset(
        args.data,
        extra_csv_paths=args.extra_data,
        validation_size=args.validation_size,
        test_size=args.test_size,
        random_state=args.random_state,
    )
    outcome = train_and_compare(
        dataset.train_X,
        dataset.train_y,
        dataset.validation_X,
        dataset.validation_y,
        dataset.test_X,
        dataset.test_y,
        selection_metric=args.selection_metric,
        random_state=args.random_state,
    )
    generated_version = (
        f"{outcome.best_model_name}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    model_version = args.model_version or generated_version
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = save_model_bundle(
        output_dir / "phishing_detection_model.joblib",
        outcome=outcome,
        feature_names=dataset.feature_names,
        thresholds=thresholds,
        dataset_summary=dataset.summary(),
        selection_metric=args.selection_metric,
        random_state=args.random_state,
        model_version=model_version,
        dataset_version=args.dataset_version,
    )
    comparison_rows = []
    for name in outcome.validation_metrics:
        comparison_rows.append(
            {
                "model": name,
                "validation_accuracy": outcome.validation_metrics[name]["accuracy"],
                "validation_precision": outcome.validation_metrics[name]["precision"],
                "validation_recall": outcome.validation_metrics[name]["recall"],
                "validation_f1": outcome.validation_metrics[name]["f1"],
                "validation_roc_auc": outcome.validation_metrics[name]["roc_auc"],
                "test_accuracy": outcome.test_metrics[name]["accuracy"],
                "test_precision": outcome.test_metrics[name]["precision"],
                "test_recall": outcome.test_metrics[name]["recall"],
                "test_f1": outcome.test_metrics[name]["f1"],
                "test_roc_auc": outcome.test_metrics[name]["roc_auc"],
            }
        )
    pd.DataFrame(comparison_rows).to_csv(output_dir / "model_comparison.csv", index=False)
    report = {
        "best_model": outcome.best_model_name,
        "model_version": model_version,
        "dataset_version": args.dataset_version,
        "selection_metric": args.selection_metric,
        "model_path": str(model_path.resolve()),
        "validation_metrics": outcome.validation_metrics,
        "test_metrics": outcome.test_metrics,
        "skipped_models": outcome.skipped_models,
        "risk_thresholds": thresholds.to_dict(),
        "dataset": dataset.summary(),
    }
    (output_dir / "training_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    save_training_report(report)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
