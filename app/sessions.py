"""
Server-side sessions with an inactivity (idle) timeout.

* The browser holds a random 256-bit token in an HttpOnly cookie.
* MySQL holds only its SHA-256 hash plus last_activity_at.
* Every authenticated request checks: now - last_activity_at > SESSION_IDLE_TIMEOUT_MINUTES
  -> session is revoked and the user must sign in again (Microsoft SSO usually makes
  that a single click, MFA is asked again if Entra policy requires it).
"""
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import LoginEvent, User, UserSession

settings = get_settings()


def utcnow() -> datetime:
    # Naive UTC everywhere in the DB (MySQL DATETIME has no timezone).
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()[:64]
    return request.client.host if request.client else None


def log_event(db: Session, request: Request | None, event: str, *, user_id: int | None = None,
              email: str | None = None, detail: str | None = None) -> None:
    db.add(LoginEvent(
        user_id=user_id, email=email, event=event, detail=(detail or "")[:500] or None,
        ip_address=client_ip(request) if request else None,
        user_agent=(request.headers.get("user-agent") or "")[:500] if request else None,
    ))


def create_session(db: Session, request: Request, user: User, remember: bool) -> tuple[str, UserSession]:
    token = secrets.token_urlsafe(32)
    now = utcnow()
    expires = (now + timedelta(days=settings.SESSION_ABSOLUTE_TIMEOUT_DAYS)
               if settings.SESSION_ABSOLUTE_TIMEOUT_DAYS > 0 else None)
    sess = UserSession(
        token_hash=hash_token(token), user_id=user.id, remember=remember,
        created_at=now, last_activity_at=now, expires_at=expires,
        ip_address=client_ip(request), user_agent=(request.headers.get("user-agent") or "")[:500],
    )
    db.add(sess)
    return token, sess


def set_session_cookie(response: Response, token: str, remember: bool) -> None:
    # "Remember me" -> cookie survives browser restarts (still subject to the idle timeout).
    # Otherwise it is a browser-session cookie that disappears when the browser closes.
    max_age = None
    if remember:
        days = settings.SESSION_ABSOLUTE_TIMEOUT_DAYS or 365
        max_age = days * 86400
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME, value=token, max_age=max_age,
        httponly=True, secure=settings.COOKIE_SECURE, samesite="lax", path="/",
        domain=settings.COOKIE_DOMAIN or None,
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(settings.SESSION_COOKIE_NAME, path="/", domain=settings.COOKIE_DOMAIN or None)


@dataclass
class SessionState:
    user: User
    session: UserSession
    idle_expires_at: datetime
    absolute_expires_at: datetime | None


class SessionError(Exception):
    def __init__(self, code: str):
        self.code = code


def resolve_session(db: Session, request: Request, *, touch: bool) -> SessionState:
    """Validate the cookie. touch=True counts the request as user activity."""
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not token:
        raise SessionError("not_signed_in")

    sess = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(token)))
    if sess is None or sess.revoked_at is not None:
        raise SessionError("not_signed_in")

    now = utcnow()
    idle = timedelta(minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES)

    if now - sess.last_activity_at > idle:
        sess.revoked_at, sess.revoke_reason = now, "idle_timeout"
        log_event(db, request, "idle_timeout", user_id=sess.user_id)
        db.commit()
        raise SessionError("idle_timeout")

    if sess.expires_at and now > sess.expires_at:
        sess.revoked_at, sess.revoke_reason = now, "expired"
        log_event(db, request, "session_expired", user_id=sess.user_id)
        db.commit()
        raise SessionError("session_expired")

    user = sess.user
    if not user.is_active:
        sess.revoked_at, sess.revoke_reason = now, "user_disabled"
        db.commit()
        raise SessionError("account_disabled")

    if touch and (now - sess.last_activity_at).total_seconds() >= settings.SESSION_TOUCH_INTERVAL_SECONDS:
        sess.last_activity_at = now
        db.commit()

    return SessionState(user=user, session=sess, idle_expires_at=sess.last_activity_at + idle,
                        absolute_expires_at=sess.expires_at)


def _dependency(touch: bool):
    def dep(request: Request, response: Response, db: Session = Depends(get_db)) -> SessionState:
        try:
            return resolve_session(db, request, touch=touch)
        except SessionError as e:
            # Tell the browser to drop a dead cookie.
            clear = f"{settings.SESSION_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
            if settings.COOKIE_DOMAIN:
                clear += f"; Domain={settings.COOKIE_DOMAIN}"
            raise HTTPException(status_code=401, detail={"code": e.code}, headers={"Set-Cookie": clear})
    return dep


# Use in routes:  state: SessionState = Depends(require_session)
require_session = _dependency(touch=True)
# For background "am I still signed in?" polling that must NOT extend the session.
peek_session = _dependency(touch=False)


def require_role(*roles: str):
    def dep(state: SessionState = Depends(require_session)) -> SessionState:
        if state.user.role not in roles:
            raise HTTPException(status_code=403, detail={"code": "forbidden"})
        return state
    return dep
