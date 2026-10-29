"""
Database tables. backend/schema.sql is the same schema written as MySQL DDL.

No passwords and no Microsoft tokens are ever stored. Microsoft checks the
password and the Authenticator (MFA) prompt; we only keep the profile and our
own session.
"""
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

# SQLite (used only by the test suite) needs plain INTEGER for autoincrement keys.
BigId = BigInteger().with_variant(Integer, "sqlite")

ROLES = ("super_admin", "admin", "employee")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    # "Login key": the user's immutable Microsoft Entra object ID (oid claim).
    # It never changes even if their email/UPN is renamed, so we match on it.
    login_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)  # M365 UPN
    email: Mapped[str | None] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    phone: Mapped[str | None] = mapped_column(String(50))
    language: Mapped[str | None] = mapped_column(String(10))  # NULL until chosen on first login
    city: Mapped[str | None] = mapped_column(String(120))
    department: Mapped[str | None] = mapped_column(String(160))
    job_title: Mapped[str | None] = mapped_column(String(160))
    photo_url: Mapped[str | None] = mapped_column(String(500))
    role: Mapped[str] = mapped_column(Enum(*ROLES, name="user_role"), default="employee", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    first_login_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    sessions: Mapped[list["UserSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    # SHA-256 of the cookie value; the raw token only ever lives in the browser cookie.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    remember: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_activity_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)  # absolute cap
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    revoke_reason: Mapped[str | None] = mapped_column(String(40))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(500))

    user: Mapped[User] = relationship(back_populates="sessions")


class OAuthState(Base):
    """Short-lived record that links the Microsoft redirect back to the login attempt."""

    __tablename__ = "oauth_states"

    state: Mapped[str] = mapped_column(String(128), primary_key=True)
    flow_json: Mapped[str] = mapped_column(Text, nullable=False)  # MSAL flow (PKCE verifier, nonce)
    remember: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    next_path: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)


class LoginEvent(Base):
    """Audit trail: sign-ins, failures, sign-outs, idle time-outs (feeds analytics later)."""

    __tablename__ = "login_events"

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    email: Mapped[str | None] = mapped_column(String(255))
    event: Mapped[str] = mapped_column(String(40), nullable=False)
    detail: Mapped[str | None] = mapped_column(String(500))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True, nullable=False)
