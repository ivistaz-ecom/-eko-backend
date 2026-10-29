import json
import logging
from datetime import timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from . import microsoft
from .config import get_settings
from .db import get_db
from .models import OAuthState, User
from .schemas import user_out
from .sessions import (
    SessionError,
    SessionState,
    clear_session_cookie,
    create_session,
    log_event,
    peek_session,
    require_session,
    resolve_session,
    set_session_cookie,
    utcnow,
)

log = logging.getLogger("eko.auth")
settings = get_settings()
router = APIRouter(prefix="/api/auth", tags=["auth"])


def _front(path: str, **query) -> str:
    q = {k: v for k, v in query.items() if v is not None}
    return f"{settings.FRONTEND_URL.rstrip('/')}{path}" + (f"?{urlencode(q)}" if q else "")


def _login_error(code: str) -> RedirectResponse:
    return RedirectResponse(_front("/login", error=code), status_code=302)


def _safe_next(path: str | None) -> str | None:
    # Only same-site relative paths, never "//evil.com" or absolute URLs.
    if path and path.startswith("/") and not path.startswith("//") and "\\" not in path:
        return path[:500]
    return None


@router.get("/config")
def public_config():
    """Non-secret settings the login page needs (single source of truth = backend .env)."""
    return {
        "appName": settings.APP_NAME,
        "allowedDomains": settings.allowed_domains,
        "idleTimeoutMinutes": settings.SESSION_IDLE_TIMEOUT_MINUTES,
        "languages": settings.languages,
    }


@router.get("/login")
def login(request: Request, email: str | None = None, remember: bool = False,
          next: str | None = None, db: Session = Depends(get_db)):
    email = (email or "").strip().lower() or None
    if email and not settings.email_allowed(email):
        log_event(db, request, "login_rejected_domain", email=email)
        db.commit()
        return _login_error("domain")

    now = utcnow()
    db.execute(delete(OAuthState).where(OAuthState.expires_at < now))  # housekeeping

    flow = microsoft.start_login(email)
    db.add(OAuthState(
        state=flow["state"], flow_json=json.dumps(flow), remember=remember,
        next_path=_safe_next(next), created_at=now,
        expires_at=now + timedelta(minutes=settings.LOGIN_STATE_TTL_MINUTES),
    ))
    db.commit()
    return RedirectResponse(flow["auth_uri"], status_code=302)


@router.get("/callback")
async def callback(request: Request, db: Session = Depends(get_db)):
    params = dict(request.query_params)

    if "error" in params:
        # e.g. user pressed "Cancel", MFA denied, or Conditional Access blocked them.
        log_event(db, request, "login_failed", detail=f"{params.get('error')}: {params.get('error_description', '')}")
        db.commit()
        return _login_error("cancelled" if params.get("error") == "access_denied" else "microsoft")

    row = db.get(OAuthState, params.get("state", ""))
    if row is None or row.expires_at < utcnow():
        return _login_error("expired_attempt")
    flow, remember, next_path = json.loads(row.flow_json), row.remember, row.next_path
    db.delete(row)
    db.commit()

    try:
        result = await run_in_threadpool(microsoft.finish_login, flow, params)
    except ValueError as exc:  # state / nonce mismatch
        log.warning("Auth flow validation failed: %s", exc)
        return _login_error("expired_attempt")

    if "error" in result:
        log_event(db, request, "login_failed", detail=f"{result.get('error')}: {result.get('error_description', '')}")
        db.commit()
        return _login_error("microsoft")

    claims = result.get("id_token_claims") or {}
    if str(claims.get("tid", "")).lower() != settings.AZURE_TENANT_ID.lower():
        log_event(db, request, "login_rejected_tenant", email=claims.get("preferred_username"))
        db.commit()
        return _login_error("tenant")

    try:
        profile = await microsoft.fetch_profile(result["access_token"])
    except Exception as exc:  # noqa: BLE001
        log.exception("Graph /me failed: %s", exc)
        return _login_error("microsoft")

    login_key = profile.get("id") or claims.get("oid")
    upn = (profile.get("userPrincipalName") or claims.get("preferred_username") or "").lower()
    mail = (profile.get("mail") or upn).lower()

    if not (settings.email_allowed(mail) or settings.email_allowed(upn)):
        log_event(db, request, "login_rejected_domain", email=mail)
        db.commit()
        return _login_error("domain")

    # ---- Upsert the user (match on immutable object id first, then UPN) ----
    user = db.scalar(select(User).where(or_(User.login_key == login_key, User.username == upn)))
    is_new = user is None
    if is_new:
        user = User(login_key=login_key, tenant_id=claims["tid"], username=upn, name=upn,
                    role="employee", is_active=True)
        db.add(user)

    phones = profile.get("businessPhones") or []
    user.login_key = login_key
    user.tenant_id = claims["tid"]
    user.username = upn
    user.email = mail
    user.name = profile.get("displayName") or claims.get("name") or upn
    user.phone = profile.get("mobilePhone") or (phones[0] if phones else None)
    user.city = profile.get("city") or profile.get("officeLocation")
    user.department = profile.get("department")
    user.job_title = profile.get("jobTitle")
    user.last_login_at = utcnow()
    if mail in settings.super_admins or upn in settings.super_admins:
        user.role = "super_admin"

    if not user.is_active:
        log_event(db, request, "login_rejected_disabled", email=mail)
        db.commit()
        return _login_error("disabled")

    has_photo = await microsoft.fetch_and_store_photo(result["access_token"], login_key)
    user.photo_url = f"/api/users/photo/{login_key}" if has_photo else None

    db.flush()  # assigns user.id for a new user
    token, _ = create_session(db, request, user, remember)
    log_event(db, request, "login_success", user_id=user.id, email=mail, detail="first_login" if is_new else None)
    db.commit()

    # First login (no language chosen yet) -> language picker, otherwise straight in.
    target = _front("/welcome") if not user.language else _front(next_path or "/home", welcome="1")
    resp = RedirectResponse(target, status_code=302)
    set_session_cookie(resp, token, remember)
    return resp


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    try:
        state = resolve_session(db, request, touch=False)
        state.session.revoked_at, state.session.revoke_reason = utcnow(), "logout"
        log_event(db, request, "logout", user_id=state.user.id, email=state.user.email)
        db.commit()
    except SessionError:
        pass  # already gone; still clear the cookie

    login_page = _front("/login", signed_out="1")
    redirect = microsoft.logout_url(login_page) if settings.MS_SIGNOUT_ON_LOGOUT else "/login?signed_out=1"
    resp = JSONResponse({"redirect": redirect})
    clear_session_cookie(resp)
    return resp


@router.get("/me")
def me(state: SessionState = Depends(require_session)):
    return {
        "user": user_out(state.user),
        "session": {
            "idleExpiresAt": state.idle_expires_at.isoformat() + "Z",
            "absoluteExpiresAt": state.absolute_expires_at.isoformat() + "Z" if state.absolute_expires_at else None,
            "idleTimeoutMinutes": settings.SESSION_IDLE_TIMEOUT_MINUTES,
        },
    }


@router.get("/session")
def session_status(state: SessionState = Depends(peek_session)):
    """Lightweight check used by the browser's idle watcher. Does NOT count as activity."""
    return {
        "authenticated": True,
        "idleExpiresAt": state.idle_expires_at.isoformat() + "Z",
        "idleTimeoutMinutes": settings.SESSION_IDLE_TIMEOUT_MINUTES,
    }


@router.post("/activity")
def activity(state: SessionState = Depends(require_session)):
    """Called (throttled) by the browser when the user clicks/types/scrolls, so real use
    of an open tab counts as activity even without page loads."""
    return {
        "authenticated": True,
        "idleExpiresAt": state.idle_expires_at.isoformat() + "Z",
        "idleTimeoutMinutes": settings.SESSION_IDLE_TIMEOUT_MINUTES,
    }
