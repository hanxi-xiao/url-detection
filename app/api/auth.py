from __future__ import annotations

import json

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.services.auth import (
    AuthError,
    auth_repository,
    json_auth_error,
    require_session,
)

async def captcha(_: Request) -> JSONResponse:
    return JSONResponse(auth_repository.create_captcha_challenge())


async def login(request: Request) -> JSONResponse:
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

    email = payload.get("email")
    password = payload.get("password")
    captcha_id = payload.get("captchaId")
    captcha_answer = payload.get("captchaAnswer")
    if not isinstance(email, str) or not isinstance(password, str):
        return JSONResponse(
            {"error": {"code": "INVALID_CREDENTIALS", "message": "Email and password are required."}},
            status_code=400,
        )
    if not isinstance(captcha_id, str) or not isinstance(captcha_answer, str):
        return JSONResponse(
            {
                "error": {
                    "code": "CAPTCHA_REQUIRED",
                    "message": "Enter the code shown in the verification image before signing in.",
                }
            },
            status_code=400,
        )
    try:
        auth_repository.verify_captcha(captcha_id, captcha_answer)
        user = auth_repository.authenticate(email, password)
        session = auth_repository.create_session(user)
    except AuthError as error:
        return json_auth_error(error)
    response = session.to_dict()
    recovery_code = auth_repository.ensure_recovery_code(user.user_id)
    if recovery_code:
        response["recoveryCode"] = recovery_code
    return JSONResponse(response)


async def register(request: Request) -> JSONResponse:
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
    fields = ("email", "password", "displayName", "captchaId", "captchaAnswer")
    if not all(isinstance(payload.get(field), str) for field in fields):
        return JSONResponse(
            {
                "error": {
                    "code": "REGISTRATION_FIELDS_REQUIRED",
                    "message": "Name, email, password, and verification code are required.",
                }
            },
            status_code=400,
        )
    try:
        role = payload.get("role", "employee")
        if not isinstance(role, str):
            role = "employee"
        user = auth_repository.register_user(
            email=payload["email"],
            password=payload["password"],
            display_name=payload["displayName"],
            role=role,
            captcha_id=payload["captchaId"],
            captcha_answer=payload["captchaAnswer"],
        )
    except AuthError as error:
        return json_auth_error(error)
    session = auth_repository.create_session(user)
    response = session.to_dict()
    response["recoveryCode"] = user.recovery_code
    return JSONResponse(response, status_code=201)


async def change_password(request: Request) -> JSONResponse:
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
    fields = (
        "email",
        "currentPassword",
        "newPassword",
        "recoveryCode",
        "captchaId",
        "captchaAnswer",
    )
    if not all(isinstance(payload.get(field), str) for field in fields):
        return JSONResponse(
            {
                "error": {
                    "code": "PASSWORD_FIELDS_REQUIRED",
                    "message": "Email, current password, new password, and verification code are required.",
                }
            },
            status_code=400,
        )
    try:
        auth_repository.change_password(
            email=payload["email"],
            current_password=payload["currentPassword"],
            new_password=payload["newPassword"],
            recovery_code=payload["recoveryCode"],
            captcha_id=payload["captchaId"],
            captcha_answer=payload["captchaAnswer"],
        )
    except AuthError as error:
        return json_auth_error(error)
    return JSONResponse({"ok": True, "message": "Your password has been changed. Please sign in again."})


async def reset_password(request: Request) -> JSONResponse:
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
    fields = ("email", "recoveryCode", "newPassword", "captchaId", "captchaAnswer")
    if not all(isinstance(payload.get(field), str) for field in fields):
        return JSONResponse(
            {
                "error": {
                    "code": "RESET_FIELDS_REQUIRED",
                    "message": "Email, recovery code, new password, and verification code are required.",
                }
            },
            status_code=400,
        )
    try:
        auth_repository.reset_password(
            email=payload["email"],
            recovery_code=payload["recoveryCode"],
            new_password=payload["newPassword"],
            captcha_id=payload["captchaId"],
            captcha_answer=payload["captchaAnswer"],
        )
    except AuthError as error:
        return json_auth_error(error)
    return JSONResponse({"ok": True, "message": "Your password has been reset. You can now sign in."})


async def session_status(request: Request) -> JSONResponse:
    try:
        session = require_session(request)
    except AuthError as error:
        return json_auth_error(error)
    return JSONResponse(session.to_dict())


async def logout(request: Request) -> JSONResponse:
    try:
        session = require_session(request)
    except AuthError as error:
        return json_auth_error(error)
    auth_repository.delete_session(session.token)
    return JSONResponse({"ok": True})


routes = [
    Route("/api/auth/captcha", captcha, methods=["GET"]),
    Route("/api/auth/login", login, methods=["POST"]),
    Route("/api/auth/register", register, methods=["POST"]),
    Route("/api/auth/change-password", change_password, methods=["POST"]),
    Route("/api/auth/reset-password", reset_password, methods=["POST"]),
    Route("/api/auth/session", session_status, methods=["GET"]),
    Route("/api/auth/logout", logout, methods=["POST"]),
]
