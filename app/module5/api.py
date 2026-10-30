"""Framework-neutral report controller."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .feedback import AnalysisNotFoundError, FeedbackRepository, FeedbackStorageError, ReportURLMismatchError
from .models import APIResponse, ReportWebsiteRequest


class FeedbackAPI:
    def __init__(self, repository: FeedbackRepository) -> None:
        self.repository = repository

    def post_report(self, payload: Mapping[str, Any]) -> APIResponse:
        request_id = payload.get("requestId")
        try:
            request = ReportWebsiteRequest.from_mapping(payload)
            result = self.repository.report_website(request)
        except (TypeError, ValueError) as exc:
            return self._error(400, "INVALID_REPORT_REQUEST", str(exc), request_id)
        except AnalysisNotFoundError:
            return self._error(404, "ANALYSIS_NOT_FOUND", "The related analysis record does not exist.", request_id)
        except ReportURLMismatchError:
            return self._error(409, "REPORT_URL_MISMATCH", "The URL does not match the related analysis record.", request_id)
        except FeedbackStorageError:
            return self._error(500, "FEEDBACK_STORAGE_FAILED", "The report could not be stored.", request_id)
        return APIResponse(status_code=200 if result.duplicate else 201, body=result.to_dict())

    @staticmethod
    def _error(status_code: int, code: str, message: str, request_id: Any) -> APIResponse:
        return APIResponse(
            status_code=status_code,
            body={
                "error": {
                    "code": code,
                    "message": message,
                    "requestId": request_id if isinstance(request_id, str) else None,
                }
            },
        )
