"""Module 5 explainability and feedback."""

from .api import FeedbackAPI
from .explanations import ExplanationService
from .feedback import FeedbackRepository
from .impact_adapter import build_feature_impacts
from .models import (
    APIResponse,
    ExplainabilityResult,
    FeatureImpact,
    PredictionContext,
    ReportWebsiteRequest,
    ReportWebsiteResult,
    RiskCategory,
)
from .service import M5Service

__all__ = [
    "APIResponse",
    "ExplainabilityResult",
    "ExplanationService",
    "FeatureImpact",
    "FeedbackAPI",
    "FeedbackRepository",
    "M5Service",
    "PredictionContext",
    "ReportWebsiteRequest",
    "ReportWebsiteResult",
    "RiskCategory",
    "build_feature_impacts",
]
