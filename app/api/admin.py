from __future__ import annotations

import json

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.module6.admin_data import (
    build_brand_impersonation_visuals,
    build_cases,
    build_model_metrics,
    build_overview,
    build_review_insights,
    paginate,
)
from app.module6.dataset_manager import export_feedback_dataset, prepare_retraining_data
from app.module6.evaluation import comparison_table
from app.module6.log_manager import get_detection_history
from app.module6.model_manager import load_model_information
from app.services.auth import AuthError, auth_repository, json_auth_error, require_role
from app.services.state import feedback_repository
from app.module5.feedback import CaseResolutionError, FeedbackStorageError


async def admin_overview(request: Request) -> JSONResponse:
    try:
        require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    return JSONResponse(build_overview())


async def admin_users(request: Request) -> JSONResponse:
    try:
        require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    page = max(1, int(request.query_params.get("page", "1")))
    page_size = max(1, min(100, int(request.query_params.get("pageSize", "20"))))
    users = auth_repository.list_users()
    if request.query_params.get("activeOnly", "false").lower() == "true":
        users = [user for user in users if user["isActive"]]
    return JSONResponse(paginate(users, page, page_size))


async def admin_user_status(request: Request) -> JSONResponse:
    try:
        session = require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(
            {"error": {"code": "INVALID_JSON", "message": "Request body must be valid JSON."}},
            status_code=400,
        )
    if not isinstance(payload, dict) or not isinstance(payload.get("isActive"), bool):
        return JSONResponse(
            {
                "error": {
                    "code": "INVALID_ACCOUNT_STATUS",
                    "message": "isActive must be a boolean.",
                }
            },
            status_code=400,
        )
    try:
        user = auth_repository.set_employee_status(
            user_id=int(request.path_params["user_id"]),
            is_active=payload["isActive"],
            acting_user_id=session.user_id,
        )
    except (AuthError, ValueError) as error:
        if isinstance(error, AuthError):
            return json_auth_error(error)
        return JSONResponse(
            {"error": {"code": "INVALID_USER_ID", "message": "The account ID is invalid."}},
            status_code=400,
        )
    return JSONResponse({"user": user})


async def admin_cases(request: Request) -> JSONResponse:
    try:
        require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    cases = build_cases()
    page = max(1, int(request.query_params.get("page", "1")))
    page_size = max(1, min(100, int(request.query_params.get("pageSize", "10"))))
    status = request.query_params.get("status")
    risk_category = request.query_params.get("riskCategory")
    review_type = request.query_params.get("reviewType")
    admin_decision = request.query_params.get("adminDecision")
    url_query = request.query_params.get("urlQuery", "").strip().lower()
    if status:
        cases = [case for case in cases if case["status"] == status]
    if risk_category:
        cases = [case for case in cases if case["riskCategory"] == risk_category]
    if review_type:
        cases = [
            case
            for case in cases
            if case.get("reports")
            and case["reports"][0].get("reviewType") == review_type
        ]
    if admin_decision == "resolved":
        cases = [case for case in cases if case.get("adminDecision")]
    elif admin_decision == "unresolved":
        cases = [case for case in cases if not case.get("adminDecision")]
    if url_query:
        cases = [case for case in cases if url_query in str(case["url"]).lower()]
    return JSONResponse(paginate(cases, page, page_size))


async def admin_models(request: Request) -> JSONResponse:
    try:
        require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    page = max(1, int(request.query_params.get("page", "1")))
    page_size = max(1, min(100, int(request.query_params.get("pageSize", "20"))))
    models = load_model_information(limit=None)
    items: list[dict[str, object]] = []
    for index, (_, row) in enumerate(models.iterrows()):
        items.append(
            {
                "version": row["version"],
                "algorithm": row["model_name"],
                "status": "ACTIVE" if index == 0 else "CANDIDATE",
                "datasetVersion": row["dataset_version"],
                "createdAt": row["created_at"],
                "metrics": {
                    "accuracy": float(row["accuracy"]),
                    "precision": float(row["precision"]),
                    "recall": float(row["recall"]),
                    "f1Score": float(row["f1_score"]),
                    "rocAuc": float(row["roc_auc"]),
                },
            }
        )
    return JSONResponse(paginate(items, page, page_size))


async def admin_scans(request: Request) -> JSONResponse:
    try:
        require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    page = max(1, int(request.query_params.get("page", "1")))
    page_size = max(1, min(100, int(request.query_params.get("pageSize", "40"))))
    history = get_detection_history(limit=None)
    items = [
        {
            "requestId": row["request_id"],
            "url": row["normalized_url"],
            "riskScore": round(float(row["risk_score"])),
            "riskCategory": row["risk_label"],
            "modelVersion": row["model_version"],
            "responseMs": round(float(row["response_ms"] or 0), 3),
            "createdAt": row["created_at"],
        }
        for _, row in history.iterrows()
    ]
    risk_category = request.query_params.get("riskCategory")
    model_source = request.query_params.get("modelSource")
    url_query = request.query_params.get("urlQuery", "").strip().lower()
    min_safety_score = request.query_params.get("minSafetyScore")
    max_safety_score = request.query_params.get("maxSafetyScore")
    if risk_category:
        items = [item for item in items if item["riskCategory"] == risk_category]
    if model_source == "policy":
        items = [
            item for item in items if str(item["modelVersion"]).startswith("policy-")
        ]
    elif model_source == "model":
        items = [
            item for item in items if not str(item["modelVersion"]).startswith("policy-")
        ]
    if min_safety_score:
        minimum = max(0.0, min(100.0, float(min_safety_score)))
        items = [
            item for item in items if 100.0 - float(item["riskScore"]) >= minimum
        ]
    if max_safety_score:
        maximum = max(0.0, min(100.0, float(max_safety_score)))
        items = [
            item for item in items if 100.0 - float(item["riskScore"]) <= maximum
        ]
    if url_query:
        items = [item for item in items if url_query in str(item["url"]).lower()]
    return JSONResponse(paginate(items, page, page_size))


async def admin_model_metrics(request: Request) -> JSONResponse:
    try:
        require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    payload = build_model_metrics(request.query_params.get("modelVersion"))
    if payload is None:
        return JSONResponse({"error": {"code": "MODEL_METRICS_NOT_FOUND", "message": "No evaluation metrics are available."}}, status_code=404)
    return JSONResponse(payload)


async def admin_feedback_dataset(request: Request) -> JSONResponse:
    try:
        require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    reviewed_only = request.query_params.get("reviewedOnly", "false").lower() == "true"
    rows = prepare_retraining_data(reviewed_only=reviewed_only)
    export_path = export_feedback_dataset(reviewed_only=reviewed_only)
    return JSONResponse(
        {
            "exportPath": str(export_path),
            "rowCount": int(len(rows)),
            "items": rows.head(20).to_dict(orient="records"),
        }
    )


async def admin_evaluations(request: Request) -> JSONResponse:
    try:
        require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    table = comparison_table()
    return JSONResponse({"items": table.to_dict(orient="records")})


async def admin_policy_entries(request: Request) -> JSONResponse:
    try:
        require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    page = max(1, int(request.query_params.get("page", "1")))
    page_size = max(1, min(100, int(request.query_params.get("pageSize", "10"))))
    entries = feedback_repository.list_policy_entries()
    list_type = request.query_params.get("listType")
    url_query = request.query_params.get("urlQuery", "").strip().lower()
    if list_type in {"allowlist", "blocklist"}:
        entries = [entry for entry in entries if entry["list_type"] == list_type]
    if url_query:
        entries = [
            entry
            for entry in entries
            if url_query in str(entry["normalized_url"]).lower()
            or url_query in str(entry["decision_reason"]).lower()
        ]
    return JSONResponse(paginate(entries, page, page_size))


async def admin_review_insights(request: Request) -> JSONResponse:
    try:
        require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    return JSONResponse(build_review_insights())


async def admin_brand_impersonation(request: Request) -> JSONResponse:
    try:
        require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    page = max(1, int(request.query_params.get("page", "1")))
    page_size = max(1, min(100, int(request.query_params.get("pageSize", "10"))))
    payload = build_brand_impersonation_visuals()
    paginated = paginate(payload["items"], page, page_size)
    return JSONResponse({**payload, **paginated})


async def admin_remove_policy_entry(request: Request) -> JSONResponse:
    try:
        require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    try:
        removed = feedback_repository.remove_policy_entry(str(request.path_params["entry_id"]))
    except FeedbackStorageError:
        return JSONResponse(
            {"error": {"code": "POLICY_REMOVE_FAILED", "message": "The policy entry could not be removed."}},
            status_code=500,
        )
    if removed is None:
        return JSONResponse(
            {"error": {"code": "POLICY_NOT_FOUND", "message": "The policy entry does not exist."}},
            status_code=404,
        )
    return JSONResponse({"removed": removed})


async def admin_case_action(request: Request) -> JSONResponse:
    try:
        session = require_role(request, "admin")
    except AuthError as error:
        return json_auth_error(error)
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(
            {"error": {"code": "INVALID_JSON", "message": "Request body must be valid JSON."}},
            status_code=400,
        )
    if not isinstance(payload, dict):
        return JSONResponse(
            {"error": {"code": "INVALID_PAYLOAD", "message": "Request body must be a JSON object."}},
            status_code=400,
        )
    case_id = str(payload.get("caseId", "")).strip()
    decision = str(payload.get("decision", "")).strip()
    reason = str(payload.get("reason", "")).strip()
    screenshot_name = payload.get("screenshotName")
    screenshot_data_url = payload.get("screenshotDataUrl")
    allowlist_expiry_days = payload.get("allowlistExpiryDays")
    if not case_id:
        return JSONResponse(
            {"error": {"code": "INVALID_CASE_ID", "message": "caseId must be provided."}},
            status_code=400,
        )
    if allowlist_expiry_days is not None and (
        isinstance(allowlist_expiry_days, bool) or not isinstance(allowlist_expiry_days, int)
    ):
        return JSONResponse(
            {
                "error": {
                    "code": "INVALID_ALLOWLIST_EXPIRY",
                    "message": "allowlistExpiryDays must be an integer or null.",
                }
            },
            status_code=400,
        )
    try:
        updated_case = feedback_repository.resolve_case(
            case_id=case_id,
            decision=decision,
            reason=reason,
            decided_by_email=session.email,
            decided_by_name=session.display_name,
            screenshot_name=screenshot_name if isinstance(screenshot_name, str) else None,
            screenshot_data_url=screenshot_data_url if isinstance(screenshot_data_url, str) else None,
            allowlist_expiry_days=allowlist_expiry_days,
        )
    except CaseResolutionError as exc:
        return JSONResponse(
            {"error": {"code": "INVALID_CASE_ACTION", "message": str(exc)}},
            status_code=400,
        )
    except FeedbackStorageError:
        return JSONResponse(
            {"error": {"code": "CASE_ACTION_FAILED", "message": "The review action could not be stored."}},
            status_code=500,
        )
    return JSONResponse({"case": updated_case}, status_code=200)


routes = [
    Route("/api/admin/overview", admin_overview, methods=["GET"]),
    Route("/api/admin/users", admin_users, methods=["GET"]),
    Route("/api/admin/users/{user_id}/status", admin_user_status, methods=["PATCH"]),
    Route("/api/admin/cases", admin_cases, methods=["GET"]),
    Route("/api/admin/models", admin_models, methods=["GET"]),
    Route("/api/admin/scans", admin_scans, methods=["GET"]),
    Route("/api/admin/model/metrics", admin_model_metrics, methods=["GET"]),
    Route("/api/admin/feedback-dataset", admin_feedback_dataset, methods=["GET"]),
    Route("/api/admin/evaluations", admin_evaluations, methods=["GET"]),
    Route("/api/admin/policy-entries", admin_policy_entries, methods=["GET"]),
    Route("/api/admin/policy-entries/{entry_id}", admin_remove_policy_entry, methods=["DELETE"]),
    Route("/api/admin/review-insights", admin_review_insights, methods=["GET"]),
    Route("/api/admin/brand-impersonation", admin_brand_impersonation, methods=["GET"]),
    Route("/api/admin/cases/action", admin_case_action, methods=["POST"]),
]
