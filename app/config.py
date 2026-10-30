from __future__ import annotations

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = BASE_DIR / "artifacts"
DEFAULT_MODEL_ARTIFACT = ARTIFACTS_DIR / "phishing_detection_model.joblib"
DATA_DIR = BASE_DIR / "data"
DEFAULT_FEEDBACK_DB = DATA_DIR / "clearurl-feedback.sqlite3"
DEFAULT_PREDICTION_LOG_DB = DATA_DIR / "prediction_logs.sqlite3"
DEFAULT_MODEL_RECORD_DB = DATA_DIR / "model_records.sqlite3"
DEFAULT_FEEDBACK_DATASET = DATA_DIR / "feedback_dataset.csv"
DEFAULT_AUTH_DB = DATA_DIR / "auth.sqlite3"
