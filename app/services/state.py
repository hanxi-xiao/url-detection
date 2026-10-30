from __future__ import annotations

from app.config import DEFAULT_FEEDBACK_DB
from app.module5 import FeedbackRepository, M5Service


feedback_repository = FeedbackRepository(DEFAULT_FEEDBACK_DB)
m5_service = M5Service(feedback_repository)
