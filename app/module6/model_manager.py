from __future__ import annotations

import pandas as pd

from app.config import DEFAULT_MODEL_RECORD_DB
from app.module6.database import get_connection, initialize_databases


def load_model_information(limit: int | None = 20) -> pd.DataFrame:
    initialize_databases()
    query = "SELECT * FROM model_records ORDER BY created_at DESC, id DESC"
    params: list[object] = []
    if limit:
        query += " LIMIT ?"
        params.append(limit)
    with get_connection(DEFAULT_MODEL_RECORD_DB) as connection:
        return pd.read_sql_query(query, connection, params=params)


def load_evaluation_information(limit: int | None = None) -> pd.DataFrame:
    initialize_databases()
    query = "SELECT * FROM evaluation_records ORDER BY created_at DESC, id DESC"
    params: list[object] = []
    if limit:
        query += " LIMIT ?"
        params.append(limit)
    with get_connection(DEFAULT_MODEL_RECORD_DB) as connection:
        return pd.read_sql_query(query, connection, params=params)
