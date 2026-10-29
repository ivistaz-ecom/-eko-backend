"""
All runtime configuration comes from environment variables (.env).
Change the domain, Azure keys, timeouts etc. in backend/.env, never in code.
"""
from functools import lru_cache
from urllib.parse import quote_plus

from pydantic_settings import BaseSettings, SettingsConfigDict


def _csv(value: str) -> list[str]:
    return [v.strip().lower() for v in value.split(",") if v.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ---- App -------------------------------------------------------------
    APP_NAME: str = "eKO Employee Portal"
    APP_ENV: str = "development"  # development | production
    FRONTEND_URL: str = "http://localhost:3000"  # where users land after login
    CORS_ORIGINS: str = "http://localhost:3000"

    # ---- Organisation / login rules -------------------------------------
    # Only people whose M365 address ends with one of these domains can sign in.
    ALLOWED_EMAIL_DOMAINS: str = "changingtree.in"
    # Comma-separated list of emails that are made Super Admin on first login.
    SUPER_ADMIN_EMAILS: str = ""
    SUPPORTED_LANGUAGES: str = "en,hi,kn,ta,ml,te,mr"

    # ---- Microsoft Entra ID (Azure AD) app registration -----------------
    AZURE_TENANT_ID: str = ""
    AZURE_CLIENT_ID: str = ""
    AZURE_CLIENT_SECRET: str = ""
    AZURE_AUTHORITY_HOST: str = "https://login.microsoftonline.com"
    # Must match a Redirect URI registered on the app registration exactly.
    AZURE_REDIRECT_URI: str = "http://localhost:3000/api/auth/callback"
    AZURE_SCOPES: str = "User.Read"
    GRAPH_BASE_URL: str = "https://graph.microsoft.com/v1.0"
    # Also sign the user out of Microsoft 365 when they sign out of eKO.
    MS_SIGNOUT_ON_LOGOUT: bool = False

    # ---- MySQL -------------------------------------------------------------
    DB_HOST: str = "127.0.0.1"
    DB_PORT: int = 3306
    DB_USER: str = "eko"
    DB_PASSWORD: str = ""
    DB_NAME: str = "eko_portal"
    # Optional full SQLAlchemy URL; overrides the DB_* values when set.
    DATABASE_URL: str = ""

    # ---- Session -----------------------------------------------------------
    SESSION_COOKIE_NAME: str = "eko_session"
    SESSION_IDLE_TIMEOUT_MINUTES: int = 1440  # 1 day of inactivity -> signed out
    SESSION_ABSOLUTE_TIMEOUT_DAYS: int = 30  # hard cap even if active; 0 = no cap
    SESSION_TOUCH_INTERVAL_SECONDS: int = 60  # how often last-activity is written
    COOKIE_SECURE: bool = False  # MUST be true in production (HTTPS)
    COOKIE_DOMAIN: str = ""  # e.g. .changingtree.in ; blank = current host
    LOGIN_STATE_TTL_MINUTES: int = 10  # time allowed to finish the Microsoft sign-in

    # ---- Storage -------------------------------------------------------------
    PHOTO_STORAGE_DIR: str = "./storage/photos"

    # ---- Derived helpers ------------------------------------------------------
    @property
    def allowed_domains(self) -> list[str]:
        return _csv(self.ALLOWED_EMAIL_DOMAINS)

    @property
    def super_admins(self) -> list[str]:
        return _csv(self.SUPER_ADMIN_EMAILS)

    @property
    def languages(self) -> list[str]:
        return _csv(self.SUPPORTED_LANGUAGES)

    @property
    def scopes(self) -> list[str]:
        return [s for s in self.AZURE_SCOPES.replace(",", " ").split() if s]

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def authority(self) -> str:
        return f"{self.AZURE_AUTHORITY_HOST.rstrip('/')}/{self.AZURE_TENANT_ID}"

    @property
    def database_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return (
            f"mysql+pymysql://{quote_plus(self.DB_USER)}:{quote_plus(self.DB_PASSWORD)}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}?charset=utf8mb4"
        )

    def email_allowed(self, email: str | None) -> bool:
        if not email or "@" not in email:
            return False
        return email.rsplit("@", 1)[1].lower() in self.allowed_domains


@lru_cache
def get_settings() -> Settings:
    return Settings()
