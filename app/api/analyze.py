from __future__ import annotations

import json

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.module2.preprocessing import PreprocessingError
from app.services.auth import AuthError, json_auth_error, require_session
from app.services.pipeline import PipelineError, analyze_submission


def json_error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code, "message": message}},
        status_code=status_code,
    )


async def analyze(request: Request) -> JSONResponse:
    try:
        require_session(request)
    except AuthError as error:
        return json_auth_error(error)
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        return json_error(400, "INVALID_JSON", "Request body must be valid JSON.")

    if not isinstance(payload, dict):
        return json_error(400, "INVALID_PAYLOAD", "Request body must be a JSON object.")

    try:
        result = analyze_submission(payload)
    except PreprocessingError as error:
        return json_error(422, error.code, str(error))
    except FileNotFoundError:
        return json_error(
            503,
            "MODEL_NOT_FOUND",
            "No trained model artifact is available. Train Module 4 first.",
        )
    except PipelineError as error:
        return json_error(500, error.code, str(error))
    except (TypeError, ValueError) as error:
        return json_error(400, "INVALID_REQUEST", str(error))

    return JSONResponse(result)


routes = [Route("/api/analyze", analyze, methods=["POST"])]
