from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import DEFAULT_AUTH_DB
SESSION_TTL_HOURS = 12
PBKDF2_ITERATIONS = 120_000
CAPTCHA_TTL_MINUTES = 5
CAPTCHA_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
RECOVERY_CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"


@dataclass(frozen=True, slots=True)
class AuthUser:
    user_id: int
    email: str
    password_hash: str
    role: str
    display_name: str
    is_active: bool
    is_verified: bool
    recovery_code: str | None = None


@dataclass(frozen=True, slots=True)
class AuthSession:
    token: str
    user_id: int
    email: str
    role: str
    display_name: str
    expires_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "user": {
                "email": self.email,
                "role": self.role,
                "displayName": self.display_name,
            },
            "expiresAt": self.expires_at,
        }


class AuthError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def json_auth_error(error: AuthError) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": error.code, "message": error.message}},
        status_code=error.status_code,
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _encode_password(password: str, *, salt: bytes | None = None) -> str:
    if not password:
        raise ValueError("Password must not be empty.")
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return (
        f"pbkdf2_sha256${PBKDF2_ITERATIONS}$"
        f"{base64.b64encode(salt).decode('ascii')}$"
        f"{base64.b64encode(derived).decode('ascii')}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iteration_text, salt_text, digest_text = stored_hash.split("$", 3)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        base64.b64decode(salt_text.encode("ascii")),
        int(iteration_text),
    )
    expected = base64.b64decode(digest_text.encode("ascii"))
    return hmac.compare_digest(derived, expected)


DEFAULT_USERS = (
    {
        "email": "employee@clearurl.local",
        "password_hash": _encode_password("employee123"),
        "role": "employee",
        "display_name": "ClearURL Employee",
        "recovery_code": "CLEARURL-EMPLOYEE-RECOVERY",
    },
    {
        "email": "admin@clearurl.local",
        "password_hash": _encode_password("admin123"),
        "role": "admin",
        "display_name": "ClearURL Administrator",
        "recovery_code": "CLEARURL-ADMIN-RECOVERY",
    },
)


class AuthRepository:
    def __init__(self, db_path: str | Path = DEFAULT_AUTH_DB) -> None:
        self.db_path = Path(db_path)
        self._captcha_challenges: dict[str, tuple[str, datetime]] = {}
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()
        self._seed_default_users()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _ensure_schema(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_verified INTEGER NOT NULL DEFAULT 1,
                    recovery_code_hash TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                """
            )
            user_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(users)").fetchall()
            }
            if "is_active" not in user_columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1"
                )
            if "is_verified" not in user_columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 0"
                )
            if "recovery_code_hash" not in user_columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN recovery_code_hash TEXT NOT NULL DEFAULT ''"
                )
            # Existing databases may still contain the old authentication columns.
            # They are intentionally left in place for a non-destructive migration,
            # but no current flow reads or writes them.
            connection.commit()

    def _seed_default_users(self) -> None:
        with self._connect() as connection:
            existing = {
                row["email"]
                for row in connection.execute("SELECT email FROM users").fetchall()
            }
            created_at = _utc_now().isoformat()
            for user in DEFAULT_USERS:
                if user["email"] in existing:
                    continue
                connection.execute(
                    """
                    INSERT INTO users (
                        email, password_hash, role, display_name, created_at,
                        is_active, is_verified, recovery_code_hash
                    )
                    VALUES (?, ?, ?, ?, ?, 1, 1, ?)
                    """,
                    (
                        user["email"],
                        user["password_hash"],
                        user["role"],
                        user["display_name"],
                        created_at,
                        _encode_password(user["recovery_code"]),
                    ),
                )
            for user in DEFAULT_USERS:
                connection.execute(
                    """
                    UPDATE users
                    SET is_verified = 1,
                        recovery_code_hash = CASE
                            WHEN recovery_code_hash = '' THEN ?
                            ELSE recovery_code_hash
                        END
                    WHERE lower(email) = lower(?)
                    """,
                    (_encode_password(user["recovery_code"]), user["email"]),
                )
            connection.commit()

    def authenticate(self, email: str, password: str) -> AuthUser:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id, email, password_hash, role, display_name,
                    is_active, is_verified
                FROM users
                WHERE lower(email) = lower(?)
                """,
                (email.strip(),),
            ).fetchone()
        if row is None or not verify_password(password, row["password_hash"]):
            raise AuthError("INVALID_CREDENTIALS", "Email or password is incorrect.", 401)
        if not bool(row["is_active"]):
            raise AuthError(
                "ACCOUNT_SUSPENDED",
                "This account has been suspended. Contact an administrator for assistance.",
                403,
            )
        return AuthUser(
            user_id=int(row["id"]),
            email=str(row["email"]),
            password_hash=str(row["password_hash"]),
            role=str(row["role"]),
            display_name=str(row["display_name"]),
            is_active=bool(row["is_active"]),
            is_verified=bool(row["is_verified"]),
        )

    def create_captcha_challenge(self) -> dict[str, str]:
        self._purge_expired_captchas()
        code = "".join(secrets.choice(CAPTCHA_ALPHABET) for _ in range(5))
        captcha_id = secrets.token_urlsafe(24)
        expires_at = _utc_now() + timedelta(minutes=CAPTCHA_TTL_MINUTES)
        self._captcha_challenges[captcha_id] = (code, expires_at)

        noise_lines = "".join(
            (
                f'<path d="M {secrets.randbelow(30)} {secrets.randbelow(64)} '
                f'L {150 + secrets.randbelow(80)} {secrets.randbelow(64)}" '
                'stroke="#4f766a" stroke-opacity=".42" stroke-width="1.5"/>'
            )
            for _ in range(5)
        )
        characters = "".join(
            (
                f'<text x="{20 + index * 36}" y="{43 + secrets.randbelow(8)}" '
                f'fill="#173f35" font-size="{27 + secrets.randbelow(7)}" '
                f'font-family="Arial, sans-serif" font-weight="700" '
                f'transform="rotate({secrets.randbelow(19) - 9} '
                f'{20 + index * 36} 38)">{character}</text>'
            )
            for index, character in enumerate(code)
        )
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="210" height="64" '
            'viewBox="0 0 210 64" role="img" aria-label="Security verification code">'
            '<rect width="210" height="64" rx="4" fill="#edf4d7"/>'
            '<path d="M0 14 C45 36 102 4 210 21" fill="none" '
            'stroke="#ddef7d" stroke-width="8" stroke-opacity=".8"/>'
            f"{noise_lines}{characters}</svg>"
        )
        image_data_url = (
            "data:image/svg+xml;base64,"
            + base64.b64encode(svg.encode("utf-8")).decode("ascii")
        )
        return {
            "captchaId": captcha_id,
            "imageDataUrl": image_data_url,
            "expiresAt": expires_at.isoformat(),
        }

    def verify_captcha(self, captcha_id: str, captcha_answer: str) -> None:
        self._purge_expired_captchas()
        challenge = self._captcha_challenges.pop(captcha_id.strip(), None)
        if challenge is None:
            raise AuthError(
                "CAPTCHA_EXPIRED",
                "The verification image expired. Please load a new one.",
                400,
            )
        expected_code, expires_at = challenge
        if (
            expires_at <= _utc_now()
            or captcha_answer.strip().upper() != expected_code
        ):
            raise AuthError(
                "CAPTCHA_FAILED",
                "The verification code was incorrect. Please try a new image.",
                400,
            )

    def register_user(
        self,
        *,
        email: str,
        password: str,
        display_name: str,
        role: str,
        captcha_id: str,
        captcha_answer: str,
    ) -> AuthUser:
        normalized_email = email.strip().lower()
        clean_name = display_name.strip()
        clean_role = role.strip().lower()
        if not clean_name or len(clean_name) > 80:
            raise AuthError(
                "INVALID_DISPLAY_NAME",
                "Enter a name between 1 and 80 characters.",
                400,
            )
        if clean_role not in {"employee", "admin"}:
            raise AuthError(
                "INVALID_ROLE",
                "Choose either Employee or Admin for the account role.",
                400,
            )
        if "@" not in normalized_email or len(normalized_email) > 254:
            raise AuthError("INVALID_EMAIL", "Enter a valid email address.", 400)
        if len(password) < 10:
            raise AuthError(
                "WEAK_PASSWORD",
                "Use a password with at least 10 characters.",
                400,
            )
        self.verify_captcha(captcha_id, captcha_answer)
        recovery_code = self._create_recovery_code()
        try:
            password_hash = _encode_password(password)
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO users (
                        email, password_hash, role, display_name, created_at,
                        is_active, is_verified, recovery_code_hash
                    )
                    VALUES (?, ?, ?, ?, ?, 1, 1, ?)
                    """,
                    (
                        normalized_email,
                        password_hash,
                        clean_role,
                        clean_name,
                        _utc_now().isoformat(),
                        _encode_password(recovery_code),
                    ),
                )
                connection.commit()
        except sqlite3.IntegrityError as error:
            raise AuthError(
                "EMAIL_ALREADY_REGISTERED",
                "An account with this email address already exists.",
                409,
            ) from error

        user = AuthUser(
            user_id=int(cursor.lastrowid),
            email=normalized_email,
            password_hash=password_hash,
            role=clean_role,
            display_name=clean_name,
            is_active=True,
            is_verified=True,
            recovery_code=recovery_code,
        )
        return user

    def register_employee(
        self,
        *,
        email: str,
        password: str,
        display_name: str,
        captcha_id: str,
        captcha_answer: str,
    ) -> AuthUser:
        return self.register_user(
            email=email,
            password=password,
            display_name=display_name,
            role="employee",
            captcha_id=captcha_id,
            captcha_answer=captcha_answer,
        )

    def change_password(
        self,
        *,
        email: str,
        current_password: str,
        new_password: str,
        recovery_code: str,
        captcha_id: str,
        captcha_answer: str,
    ) -> None:
        normalized_email = email.strip().lower()
        if len(new_password) < 10:
            raise AuthError(
                "WEAK_PASSWORD",
                "Use a new password with at least 10 characters.",
                400,
            )
        self.verify_captcha(captcha_id, captcha_answer)
        user = self.authenticate(normalized_email, current_password)
        self._verify_recovery_code(user.user_id, recovery_code)
        self._replace_password(user.user_id, _encode_password(new_password))

    def reset_password(
        self,
        *,
        email: str,
        recovery_code: str,
        new_password: str,
        captcha_id: str,
        captcha_answer: str,
    ) -> None:
        if len(new_password) < 10:
            raise AuthError(
                "WEAK_PASSWORD",
                "Use a new password with at least 10 characters.",
                400,
            )
        self.verify_captcha(captcha_id, captcha_answer)
        user = self._find_user(email)
        self._verify_recovery_code(user.user_id, recovery_code)
        self._replace_password(user.user_id, _encode_password(new_password))

    @staticmethod
    def _create_recovery_code() -> str:
        groups = [
            "".join(secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(4))
            for _ in range(4)
        ]
        return f"CLEARURL-{'-'.join(groups)}"

    def _verify_recovery_code(self, user_id: int, recovery_code: str) -> None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT recovery_code_hash FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        if row is None or not row["recovery_code_hash"] or not verify_password(
            recovery_code.strip().upper(), str(row["recovery_code_hash"])
        ):
            raise AuthError(
                "INVALID_RECOVERY_CODE",
                "The recovery code is incorrect. Use the code saved during registration.",
                401,
            )

    def ensure_recovery_code(self, user_id: int) -> str | None:
        """Provision a recovery code for accounts created before this flow existed."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT recovery_code_hash FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            if row is None or row["recovery_code_hash"]:
                return None
            recovery_code = self._create_recovery_code()
            connection.execute(
                "UPDATE users SET recovery_code_hash = ? WHERE id = ?",
                (_encode_password(recovery_code), user_id),
            )
            connection.commit()
        return recovery_code

    def _find_user(self, email: str) -> AuthUser:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id, email, password_hash, role, display_name,
                    is_active, is_verified
                FROM users
                WHERE lower(email) = lower(?)
                """,
                (email.strip(),),
            ).fetchone()
        if row is None:
            raise AuthError("ACCOUNT_NOT_FOUND", "The account was not found.", 404)
        if not bool(row["is_active"]):
            raise AuthError(
                "ACCOUNT_SUSPENDED",
                "This account has been suspended. Contact an administrator for assistance.",
                403,
            )
        return AuthUser(
            user_id=int(row["id"]),
            email=str(row["email"]),
            password_hash=str(row["password_hash"]),
            role=str(row["role"]),
            display_name=str(row["display_name"]),
            is_active=bool(row["is_active"]),
            is_verified=bool(row["is_verified"]),
        )

    def _replace_password(self, user_id: int, password_hash: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id),
            )
            connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            connection.commit()

    def list_users(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    u.id,
                    u.email,
                    u.role,
                    u.display_name,
                    u.created_at,
                    u.is_active,
                    u.is_verified,
                    MAX(s.created_at) AS last_session_at
                FROM users u
                LEFT JOIN sessions s ON s.user_id = u.id
                GROUP BY u.id
                ORDER BY
                    CASE u.role WHEN 'admin' THEN 0 ELSE 1 END,
                    lower(u.display_name)
                """
            ).fetchall()
        return [
            {
                "userId": int(row["id"]),
                "email": str(row["email"]),
                "role": str(row["role"]),
                "displayName": str(row["display_name"]),
                "createdAt": str(row["created_at"]),
                "isActive": bool(row["is_active"]),
                "isVerified": bool(row["is_verified"]),
                "lastSessionAt": str(row["last_session_at"])
                if row["last_session_at"] is not None
                else None,
            }
            for row in rows
        ]

    def set_employee_status(
        self, *, user_id: int, is_active: bool, acting_user_id: int
    ) -> dict[str, Any]:
        if user_id == acting_user_id:
            raise AuthError(
                "SELF_STATUS_CHANGE_FORBIDDEN",
                "You cannot change the status of your own account.",
                400,
            )
        with self._connect() as connection:
            user = connection.execute(
                "SELECT id, role FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if user is None:
                raise AuthError("ACCOUNT_NOT_FOUND", "The account was not found.", 404)
            if str(user["role"]) != "employee":
                raise AuthError(
                    "ADMIN_STATUS_CHANGE_FORBIDDEN",
                    "Administrator accounts cannot be suspended from this screen.",
                    400,
                )
            connection.execute(
                "UPDATE users SET is_active = ? WHERE id = ?",
                (1 if is_active else 0, user_id),
            )
            if not is_active:
                connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            connection.commit()
        return next(item for item in self.list_users() if item["userId"] == user_id)

    def _purge_expired_captchas(self) -> None:
        now = _utc_now()
        expired = [
            captcha_id
            for captcha_id, (_, expires_at) in self._captcha_challenges.items()
            if expires_at <= now
        ]
        for captcha_id in expired:
            del self._captcha_challenges[captcha_id]

    def create_session(self, user: AuthUser) -> AuthSession:
        token = secrets.token_urlsafe(32)
        created_at = _utc_now()
        expires_at = created_at + timedelta(hours=SESSION_TTL_HOURS)
        with self._connect() as connection:
            connection.execute("DELETE FROM sessions WHERE user_id = ?", (user.user_id,))
            connection.execute(
                """
                INSERT INTO sessions (token, user_id, expires_at, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (token, user.user_id, expires_at.isoformat(), created_at.isoformat()),
            )
            connection.commit()
        return AuthSession(
            token=token,
            user_id=user.user_id,
            email=user.email,
            role=user.role,
            display_name=user.display_name,
            expires_at=expires_at.isoformat(),
        )

    def resolve_session(self, token: str) -> AuthSession:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    s.token, s.user_id, s.expires_at, u.email, u.role, u.display_name,
                    u.is_active
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token = ?
                """,
                (token,),
            ).fetchone()
            if row is None:
                raise AuthError("INVALID_SESSION", "The session is missing or invalid.", 401)
            if not bool(row["is_active"]):
                connection.execute("DELETE FROM sessions WHERE token = ?", (token,))
                connection.commit()
                raise AuthError(
                    "ACCOUNT_SUSPENDED",
                    "This account has been suspended. Contact an administrator for assistance.",
                    403,
                )
            expires_at = datetime.fromisoformat(str(row["expires_at"]))
            if expires_at <= _utc_now():
                connection.execute("DELETE FROM sessions WHERE token = ?", (token,))
                connection.commit()
                raise AuthError("SESSION_EXPIRED", "The session has expired. Please log in again.", 401)
        return AuthSession(
            token=str(row["token"]),
            user_id=int(row["user_id"]),
            email=str(row["email"]),
            role=str(row["role"]),
            display_name=str(row["display_name"]),
            expires_at=str(row["expires_at"]),
        )

    def delete_session(self, token: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM sessions WHERE token = ?", (token,))
            connection.commit()


auth_repository = AuthRepository()


def extract_bearer_token(request: Request) -> str:
    header = request.headers.get("Authorization", "").strip()
    if not header.lower().startswith("bearer "):
        raise AuthError("AUTH_REQUIRED", "You must be logged in to access this resource.", 401)
    token = header[7:].strip()
    if not token:
        raise AuthError("AUTH_REQUIRED", "You must be logged in to access this resource.", 401)
    return token


def require_session(request: Request) -> AuthSession:
    return auth_repository.resolve_session(extract_bearer_token(request))


def require_role(request: Request, role: str) -> AuthSession:
    session = require_session(request)
    if session.role != role:
        raise AuthError("FORBIDDEN", "You do not have permission to access this resource.", 403)
    return session
