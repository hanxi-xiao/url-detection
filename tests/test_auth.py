import asyncio
import json

import pytest
from starlette.requests import Request

from app.api.auth import captcha, login
from app.services.auth import (
    AuthError,
    AuthRepository,
    auth_repository,
    require_role,
    verify_password,
)


def _json_request(payload: dict[str, object]) -> Request:
    body = json.dumps(payload).encode("utf-8")

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/auth/login",
            "headers": [(b"content-type", b"application/json")],
        },
        receive,
    )


def test_default_accounts_can_authenticate() -> None:
    employee = auth_repository.authenticate("employee@clearurl.local", "employee123")
    admin = auth_repository.authenticate("admin@clearurl.local", "admin123")
    assert employee.role == "employee"
    assert admin.role == "admin"
    assert verify_password("employee123", employee.password_hash)


def test_login_requires_human_confirmation() -> None:
    rejected = asyncio.run(
        login(
            _json_request(
                {
                    "email": "employee@clearurl.local",
                    "password": "employee123",
                }
            )
        )
    )
    assert rejected.status_code == 400
    assert json.loads(rejected.body)["error"]["code"] == "CAPTCHA_REQUIRED"

    challenge_response = asyncio.run(captcha(_json_request({})))
    challenge = json.loads(challenge_response.body)
    expected_code, _ = auth_repository._captcha_challenges[challenge["captchaId"]]
    accepted = asyncio.run(
        login(
            _json_request(
                {
                    "email": "employee@clearurl.local",
                    "password": "employee123",
                    "captchaId": challenge["captchaId"],
                    "captchaAnswer": expected_code,
                }
            )
        )
    )
    assert accepted.status_code == 200
    auth_repository.delete_session(json.loads(accepted.body)["token"])


def test_session_roundtrip_and_role_check() -> None:
    admin = auth_repository.authenticate("admin@clearurl.local", "admin123")
    session = auth_repository.create_session(admin)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/admin/overview",
            "headers": [
                (b"authorization", f"Bearer {session.token}".encode("utf-8")),
            ],
        }
    )
    resolved = require_role(request, "admin")
    assert resolved.email == "admin@clearurl.local"
    auth_repository.delete_session(session.token)
    try:
        require_role(request, "admin")
    except AuthError as error:
        assert error.status_code == 401
    else:
        raise AssertionError("Expected deleted session to be rejected.")


def test_employee_registration_creates_an_active_employee_account(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.sqlite3")
    challenge = repository.create_captcha_challenge()
    captcha_code, _ = repository._captcha_challenges[challenge["captchaId"]]

    employee = repository.register_employee(
        email="new.employee@example.com",
        password="secure-password-123",
        display_name="New Employee",
        captcha_id=challenge["captchaId"],
        captcha_answer=captcha_code,
    )

    assert employee.role == "employee"
    assert employee.recovery_code
    assert repository.authenticate("new.employee@example.com", "secure-password-123").is_active


def test_admin_registration_creates_an_active_admin_account(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.sqlite3")
    challenge = repository.create_captcha_challenge()
    captcha_code, _ = repository._captcha_challenges[challenge["captchaId"]]

    admin = repository.register_user(
        email="new.admin@example.com",
        password="secure-password-123",
        display_name="New Admin",
        role="admin",
        captcha_id=challenge["captchaId"],
        captcha_answer=captcha_code,
    )

    assert admin.role == "admin"
    assert repository.authenticate("new.admin@example.com", "secure-password-123").role == "admin"


def test_change_password_replaces_credentials_and_removes_sessions(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.sqlite3")
    employee = repository.authenticate("employee@clearurl.local", "employee123")
    session = repository.create_session(employee)
    challenge = repository.create_captcha_challenge()
    captcha_code, _ = repository._captcha_challenges[challenge["captchaId"]]

    repository.change_password(
        email="employee@clearurl.local",
        current_password="employee123",
        new_password="new-secure-password",
        recovery_code="CLEARURL-EMPLOYEE-RECOVERY",
        captcha_id=challenge["captchaId"],
        captcha_answer=captcha_code,
    )

    assert repository.authenticate("employee@clearurl.local", "new-secure-password").is_active
    with pytest.raises(AuthError) as old_password_error:
        repository.authenticate("employee@clearurl.local", "employee123")
    assert old_password_error.value.code == "INVALID_CREDENTIALS"
    with pytest.raises(AuthError) as session_error:
        repository.resolve_session(session.token)
    assert session_error.value.code == "INVALID_SESSION"


def test_change_password_rejects_incorrect_current_password(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.sqlite3")
    challenge = repository.create_captcha_challenge()
    captcha_code, _ = repository._captcha_challenges[challenge["captchaId"]]

    with pytest.raises(AuthError) as error:
        repository.change_password(
            email="employee@clearurl.local",
            current_password="wrong-password",
            new_password="new-secure-password",
            recovery_code="CLEARURL-EMPLOYEE-RECOVERY",
            captcha_id=challenge["captchaId"],
            captcha_answer=captcha_code,
        )

    assert error.value.code == "INVALID_CREDENTIALS"
    assert repository.authenticate("employee@clearurl.local", "employee123").is_active


def test_change_password_rejects_weak_new_password_before_captcha_use(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.sqlite3")
    challenge = repository.create_captcha_challenge()
    captcha_code, _ = repository._captcha_challenges[challenge["captchaId"]]

    with pytest.raises(AuthError) as error:
        repository.change_password(
            email="employee@clearurl.local",
            current_password="employee123",
            new_password="short",
            recovery_code="CLEARURL-EMPLOYEE-RECOVERY",
            captcha_id=challenge["captchaId"],
            captcha_answer=captcha_code,
        )

    assert error.value.code == "WEAK_PASSWORD"
    assert challenge["captchaId"] in repository._captcha_challenges


def test_forgot_password_reset_uses_saved_recovery_code(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.sqlite3")
    challenge = repository.create_captcha_challenge()
    captcha_code, _ = repository._captcha_challenges[challenge["captchaId"]]

    repository.reset_password(
        email="employee@clearurl.local",
        recovery_code="CLEARURL-EMPLOYEE-RECOVERY",
        new_password="reset-secure-password",
        captcha_id=challenge["captchaId"],
        captcha_answer=captcha_code,
    )

    assert repository.authenticate("employee@clearurl.local", "reset-secure-password").is_active


def test_admin_can_suspend_and_restore_an_employee_account(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.sqlite3")
    employee = repository.authenticate("employee@clearurl.local", "employee123")
    admin = repository.authenticate("admin@clearurl.local", "admin123")

    suspended = repository.set_employee_status(
        user_id=employee.user_id,
        is_active=False,
        acting_user_id=admin.user_id,
    )
    assert not suspended["isActive"]
    with pytest.raises(AuthError) as error:
        repository.authenticate("employee@clearurl.local", "employee123")
    assert error.value.code == "ACCOUNT_SUSPENDED"

    restored = repository.set_employee_status(
        user_id=employee.user_id,
        is_active=True,
        acting_user_id=admin.user_id,
    )
    assert restored["isActive"]
    assert repository.authenticate("employee@clearurl.local", "employee123").is_active
