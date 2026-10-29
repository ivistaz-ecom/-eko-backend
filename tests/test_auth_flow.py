"""
End-to-end test of the sign-in flow with Microsoft mocked out.
Runs on SQLite so it needs no MySQL:   cd backend && python -m pytest -q
"""
import os
import tempfile
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

_tmp = tempfile.mkdtemp()
os.environ.update(
    DATABASE_URL=f"sqlite:///{_tmp}/test.db",
    AZURE_TENANT_ID="tenant-123",
    AZURE_CLIENT_ID="client-abc",
    AZURE_CLIENT_SECRET="secret",
    ALLOWED_EMAIL_DOMAINS="changingtree.in",
    SUPER_ADMIN_EMAILS="boss@changingtree.in",
    FRONTEND_URL="http://localhost:3000",
    SESSION_IDLE_TIMEOUT_MINUTES="1440",
    PHOTO_STORAGE_DIR=f"{_tmp}/photos",
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import microsoft  # noqa: E402
from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import LoginEvent, User, UserSession  # noqa: E402
from app.sessions import utcnow  # noqa: E402

PROFILE = {
    "id": "oid-0001", "displayName": "Asha Rao", "mail": "asha.rao@changingtree.in",
    "userPrincipalName": "asha.rao@changingtree.in", "mobilePhone": "+91 98450 00000",
    "businessPhones": [], "city": "Bengaluru", "department": "Marketing", "jobTitle": "Brand Manager",
    "preferredLanguage": "en-IN",
}


@pytest.fixture(autouse=True)
def fresh_db(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    def fake_start(email):
        return {"state": "st-" + (email or "none"), "auth_uri": f"https://login.microsoftonline.com/x?login_hint={email}"}

    def fake_finish(flow, params):
        if params.get("code") == "bad":
            return {"error": "invalid_grant", "error_description": "bad code"}
        return {"access_token": "AT", "id_token_claims": {"tid": params.get("tid", "tenant-123"), "oid": "oid-0001"}}

    async def fake_profile(_token):
        return dict(PROFILE)

    async def fake_photo(_token, login_key):
        return True

    monkeypatch.setattr(microsoft, "start_login", fake_start)
    monkeypatch.setattr(microsoft, "finish_login", fake_finish)
    monkeypatch.setattr(microsoft, "fetch_profile", fake_profile)
    monkeypatch.setattr(microsoft, "fetch_and_store_photo", fake_photo)
    yield


def client():
    return TestClient(app, base_url="http://localhost:3000", follow_redirects=False)


def sign_in(c, email="asha.rao@changingtree.in", remember=False, **cb):
    r = c.get("/api/auth/login", params={"email": email, "remember": str(remember).lower()})
    assert r.status_code == 302 and r.headers["location"].startswith("https://login.microsoftonline.com")
    return c.get("/api/auth/callback", params={"code": "good", "state": f"st-{email}", **cb})


def test_config_exposes_domain_from_env():
    r = client().get("/api/auth/config")
    assert r.json()["allowedDomains"] == ["changingtree.in"]
    assert r.json()["idleTimeoutMinutes"] == 1440


def test_wrong_domain_is_rejected_before_microsoft():
    r = client().get("/api/auth/login", params={"email": "someone@gmail.com"})
    assert r.status_code == 302 and r.headers["location"].endswith("/login?error=domain")


def test_first_login_saves_profile_and_asks_language():
    c = client()
    r = sign_in(c)
    assert r.status_code == 302 and r.headers["location"] == "http://localhost:3000/welcome"
    assert "eko_session" in r.headers["set-cookie"] and "HttpOnly" in r.headers["set-cookie"]

    with SessionLocal() as db:
        u = db.query(User).one()
        assert (u.login_key, u.username, u.name, u.phone, u.city, u.department) == (
            "oid-0001", "asha.rao@changingtree.in", "Asha Rao", "+91 98450 00000", "Bengaluru", "Marketing")
        assert u.language is None and u.photo_url == "/api/users/photo/oid-0001" and u.role == "employee"

    me = c.get("/api/auth/me").json()["user"]
    assert me["name"] == "Asha Rao"

    r = c.patch("/api/users/me/language", json={"language": "hi"})
    assert r.status_code == 200 and r.json()["user"]["language"] == "hi"
    assert c.patch("/api/users/me/language", json={"language": "xx"}).status_code == 422

    # Second login skips the language page and plays the welcome animation.
    r = sign_in(client())
    assert r.headers["location"] == "http://localhost:3000/home?welcome=1"


def test_wrong_tenant_and_failed_exchange():
    assert sign_in(client(), tid="other-tenant").headers["location"].endswith("error=tenant")
    c = client()
    c.get("/api/auth/login", params={"email": "asha.rao@changingtree.in"})
    r = c.get("/api/auth/callback", params={"code": "bad", "state": "st-asha.rao@changingtree.in"})
    assert r.headers["location"].endswith("error=microsoft")
    r = c.get("/api/auth/callback", params={"error": "access_denied", "state": "x"})
    assert r.headers["location"].endswith("error=cancelled")
    r = c.get("/api/auth/callback", params={"code": "good", "state": "unknown"})
    assert r.headers["location"].endswith("error=expired_attempt")


def test_idle_timeout_signs_user_out():
    c = client()
    sign_in(c)
    assert c.get("/api/auth/me").status_code == 200

    # Pretend the user was inactive for a day and a minute.
    with SessionLocal() as db:
        s = db.query(UserSession).one()
        s.last_activity_at = utcnow() - timedelta(minutes=1441)
        db.commit()

    r = c.get("/api/auth/me")
    assert r.status_code == 401 and r.json()["detail"]["code"] == "idle_timeout"
    with SessionLocal() as db:
        assert db.query(UserSession).one().revoke_reason == "idle_timeout"
        assert db.query(LoginEvent).filter_by(event="idle_timeout").count() == 1


def test_session_poll_does_not_extend_activity():
    c = client()
    sign_in(c)
    old = utcnow() - timedelta(minutes=30)
    with SessionLocal() as db:
        db.query(UserSession).one().last_activity_at = old
        db.commit()
    assert c.get("/api/auth/session").status_code == 200
    with SessionLocal() as db:
        assert db.query(UserSession).one().last_activity_at == old  # untouched
    c.get("/api/auth/me")  # real activity
    with SessionLocal() as db:
        assert db.query(UserSession).one().last_activity_at > old


def test_remember_me_sets_persistent_cookie():
    r = sign_in(client(), remember=True)
    assert "Max-Age=" in r.headers["set-cookie"]
    r = sign_in(client(), remember=False)
    assert "Max-Age=" not in r.headers["set-cookie"]


def test_logout_revokes_session():
    c = client()
    sign_in(c)
    r = c.post("/api/auth/logout")
    assert r.json()["redirect"] == "/login?signed_out=1"
    assert c.get("/api/auth/me").status_code == 401


def test_super_admin_bootstrap(monkeypatch):
    async def boss(_t):
        return {**PROFILE, "mail": "boss@changingtree.in", "userPrincipalName": "boss@changingtree.in"}
    monkeypatch.setattr(microsoft, "fetch_profile", boss)
    sign_in(client(), email="boss@changingtree.in")
    with SessionLocal() as db:
        assert db.query(User).one().role == "super_admin"


def test_real_msal_builds_microsoft_url():
    """Uses the real MSAL library (no network) to check the authorize URL we send users to."""
    import importlib
    importlib.reload(microsoft)
    try:
        flow = microsoft.start_login("asha.rao@changingtree.in")
    except Exception as exc:  # MSAL may need network for authority discovery
        pytest.skip(f"MSAL authority discovery unavailable offline: {exc}")
    q = parse_qs(urlparse(flow["auth_uri"]).query)
    assert q["client_id"] == ["client-abc"] and q["login_hint"] == ["asha.rao@changingtree.in"]
    assert q["code_challenge_method"] == ["S256"]


def test_activity_heartbeat_extends_session():
    c = client()
    sign_in(c)
    old = utcnow() - timedelta(minutes=30)
    with SessionLocal() as db:
        db.query(UserSession).one().last_activity_at = old
        db.commit()
    assert c.post("/api/auth/activity").status_code == 200
    with SessionLocal() as db:
        assert db.query(UserSession).one().last_activity_at > old
