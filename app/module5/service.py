"""Application service joining explanations, persistence, and reporting."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .api import FeedbackAPI
from .explanations import ExplanationService
from .feedback import FeedbackRepository
from .models import APIResponse, ExplainabilityResult, FeatureImpact, PredictionContext


class M5Service:
    def __init__(self, repository: FeedbackRepository, explanation_service: ExplanationService | None = None) -> None:
        self.repository = repository
        self.explanation_service = explanation_service or ExplanationService()
        self.feedback_api = FeedbackAPI(repository)

    def process_prediction(
        self,
        context: PredictionContext | Mapping[str, Any],
        impacts: Iterable[FeatureImpact],
    ) -> ExplainabilityResult:
        prediction_context = PredictionContext.from_mapping(context) if isinstance(context, Mapping) else context
        if not isinstance(prediction_context, PredictionContext):
            raise TypeError("context must be PredictionContext or a mapping")
        result = self.explanation_service.explain(prediction_context, impacts)
        self.repository.save_analysis(prediction_context, result.reasons)
        return result

    def report_website(self, payload: Mapping[str, Any]) -> APIResponse:
        return self.feedback_api.post_report(payload)
