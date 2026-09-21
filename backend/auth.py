"""Authentication utilities: user storage, JWT, and FastAPI dependency."""

import fcntl
import json
import os
import shutil
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import bcrypt as _bcrypt
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

from .routers._utils import PROJECTS_DIR

MULTI_USER_MODE: bool = os.environ.get("MULTI_USER_MODE", "false").lower() in ("1", "true", "yes")
JWT_SECRET: str = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_DAYS = 7

DEMO_EMAIL: str = os.environ.get("DEMO_EMAIL", "")
DEMO_PASSWORD: str = os.environ.get("DEMO_PASSWORD", "")
DEMO_USER_ID = "usr_demo"

_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

_USERS_FILE = PROJECTS_DIR / ".users.json"


@dataclass
class AuthUser:
    id: str
    email: str
    is_demo: bool


_LOCAL_USER = AuthUser(id="local", email="local", is_demo=False)


# ── User file helpers ─────────────────────────────────────────────────────────

_users_cache_mtime: int = 0
_users_cache_list: list[dict] = []
_users_cache_by_email: dict[str, dict] = {}
_users_cache_by_id: dict[str, dict] = {}

def _get_cached_users() -> tuple[list[dict], dict[str, dict], dict[str, dict]]:
    global _users_cache_mtime, _users_cache_list, _users_cache_by_email, _users_cache_by_id

    if not _USERS_FILE.exists():
        return [], {}, {}

    try:
        current_mtime = _USERS_FILE.stat().st_mtime_ns
    except Exception:
        current_mtime = 0

    if current_mtime == 0 or current_mtime != _users_cache_mtime:
        try:
            users = json.loads(_USERS_FILE.read_text()).get("users", [])
            _users_cache_list = users
            _users_cache_by_email = {u["email"].lower(): u for u in users if "email" in u}
            _users_cache_by_id = {u["id"]: u for u in users if "id" in u}
            _users_cache_mtime = current_mtime
        except Exception:
            return [], {}, {}

    return _users_cache_list, _users_cache_by_email, _users_cache_by_id

def _load_users() -> list[dict]:
    users_list, _, _ = _get_cached_users()
    return users_list


def _save_users(users: list[dict]) -> None:
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _USERS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"users": users}, indent=2))
    os.replace(tmp, _USERS_FILE)


def _load_users_locked() -> tuple[list[dict], "open"]:
    """Return (users, file_handle) with an exclusive lock held. Caller must close."""
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    fh = open(_USERS_FILE, "a+")
    fcntl.flock(fh, fcntl.LOCK_EX)
    fh.seek(0)
    content = fh.read()
    try:
        users = json.loads(content).get("users", []) if content.strip() else []
    except Exception:
        users = []
    return users, fh


def _save_users_locked(users: list[dict], fh) -> None:
    """Write users back while the file lock from _load_users_locked is still held."""
    tmp = _USERS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"users": users}, indent=2))
    os.replace(tmp, _USERS_FILE)
    fcntl.flock(fh, fcntl.LOCK_UN)
    fh.close()


def _find_user_by_email(email: str) -> dict | None:
    _, by_email, _ = _get_cached_users()
    return by_email.get(email.lower())


def _find_user_by_id(user_id: str) -> dict | None:
    _, _, by_id = _get_cached_users()
    return by_id.get(user_id)


def _update_user_field(user_id: str, field: str, value) -> None:
    users, fh = _load_users_locked()
    for u in users:
        if u["id"] == user_id:
            u[field] = value
            break
    _save_users_locked(users, fh)


# ── Password & JWT helpers ────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def create_access_token(user: dict) -> str:
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="JWT_SECRET is not configured")
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user["id"],
        "email": user["email"],
        "is_demo": user.get("is_demo", False),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=JWT_EXPIRY_DAYS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


# ── User creation ─────────────────────────────────────────────────────────────

def create_user(email: str, password: str, is_demo: bool = False, user_id: str | None = None) -> dict:
    new_user = {
        "id": user_id or f"usr_{uuid.uuid4().hex}",
        "email": email.lower(),
        "password_hash": hash_password(password),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "is_demo": is_demo,
    }
    if is_demo:
        new_user["last_reset_date"] = ""
    users, fh = _load_users_locked()
    if any(u["email"].lower() == email.lower() for u in users):
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()
        raise HTTPException(status_code=409, detail="Email already registered")
    users.append(new_user)
    _save_users_locked(users, fh)
    return new_user


# ── Demo account management ───────────────────────────────────────────────────

def ensure_demo_user() -> None:
    """Create the demo user on startup if credentials are configured."""
    if not MULTI_USER_MODE or not DEMO_EMAIL or not DEMO_PASSWORD:
        return
    existing = _find_user_by_id(DEMO_USER_ID)
    if existing:
        if not verify_password(DEMO_PASSWORD, existing.get("password_hash", "")):
            _update_user_field(DEMO_USER_ID, "password_hash", hash_password(DEMO_PASSWORD))
        return
    try:
        create_user(DEMO_EMAIL, DEMO_PASSWORD, is_demo=True, user_id=DEMO_USER_ID)
    except HTTPException:
        pass


def _get_user_projects_dir_for_id(user_id: str) -> Path:
    """Return the projects root for a user without importing to avoid circular deps."""
    if user_id == "local":
        return PROJECTS_DIR
    p = PROJECTS_DIR / user_id
    p.mkdir(parents=True, exist_ok=True)
    return p


def maybe_reset_demo(user: dict) -> None:
    """If the demo user hasn't been reset today (UTC), wipe and recreate their projects."""
    from .demo_projects import create_demo_projects
    today = date.today().isoformat()
    if user.get("last_reset_date", "") >= today:
        return
    demo_dir = _get_user_projects_dir_for_id(DEMO_USER_ID)
    if demo_dir.exists():
        for child in demo_dir.iterdir():
            if child.is_dir() and not child.name.startswith("."):
                shutil.rmtree(child)
    create_demo_projects(demo_dir)
    _update_user_field(DEMO_USER_ID, "last_reset_date", today)


# ── FastAPI dependency ────────────────────────────────────────────────────────

async def get_current_user(token: str | None = Depends(_oauth2_scheme)) -> AuthUser:
    if not MULTI_USER_MODE:
        return _LOCAL_USER
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="JWT_SECRET is not configured")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = _find_user_by_id(payload["sub"])
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return AuthUser(id=user["id"], email=user["email"], is_demo=user.get("is_demo", False))
