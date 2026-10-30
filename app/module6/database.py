from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app.config import DATA_DIR, DEFAULT_MODEL_RECORD_DB, DEFAULT_PREDICTION_LOG_DB


def ensure_database_directory() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR


@contextmanager
def get_connection(database_path: Path) -> Iterator[sqlite3.Connection]:
    ensure_database_directory()
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize_databases() -> None:
    ensure_database_directory()

    with get_connection(DEFAULT_PREDICTION_LOG_DB) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS prediction_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                normalized_url TEXT NOT NULL,
                risk_score REAL NOT NULL,
                risk_label TEXT NOT NULL,
                phishing_probability REAL NOT NULL,
                model_name TEXT NOT NULL,
                model_version TEXT NOT NULL,
                response_ms REAL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_prediction_logs_created_at
            ON prediction_logs(created_at DESC)
            """
        )

    with get_connection(DEFAULT_MODEL_RECORD_DB) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS model_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL,
                version TEXT NOT NULL UNIQUE,
                dataset_version TEXT NOT NULL,
                selection_metric TEXT NOT NULL,
                accuracy REAL NOT NULL,
                precision REAL NOT NULL,
                recall REAL NOT NULL,
                f1_score REAL NOT NULL,
                roc_auc REAL NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evaluation_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL,
                version TEXT NOT NULL,
                split_name TEXT NOT NULL,
                accuracy REAL NOT NULL,
                precision REAL NOT NULL,
                recall REAL NOT NULL,
                f1_score REAL NOT NULL,
                roc_auc REAL NOT NULL,
                false_positive_rate REAL NOT NULL,
                false_negative_rate REAL NOT NULL,
                average_inference_ms REAL NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_evaluation_records_version
            ON evaluation_records(version, split_name)
            """
        )


initialize_databases()
