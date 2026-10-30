from __future__ import annotations

import json

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.services.auth import AuthError, json_auth_error, require_session
from app.services.pipeline import m5_service


async def create_report(request: Request) -> JSONResponse:
    try:
        require_session(request)
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
    response = m5_service.report_website(payload)
    return JSONResponse(response.body, status_code=response.status_code)


routes = [Route("/api/reports", create_report, methods=["POST"])]
