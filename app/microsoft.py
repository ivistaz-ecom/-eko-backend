"""
Microsoft Entra ID sign-in (OAuth 2.0 Authorization Code flow + PKCE, via MSAL)
and Microsoft Graph profile/photo lookup.

Why a redirect and not "send the M365 password to our API":
  The password + Microsoft Authenticator (MFA) prompt can only be completed on
  Microsoft's own sign-in page. The legacy "password grant" (ROPC) cannot do MFA
  and Microsoft blocks it for MFA-enabled accounts. So the user types their email
  on eKO, is sent to login.microsoftonline.com for password + Authenticator, and
  comes back to /api/auth/callback with a one-time code we exchange for tokens.
"""
import logging
from pathlib import Path

import httpx
import msal

from .config import get_settings

log = logging.getLogger("eko.microsoft")
settings = get_settings()

PROFILE_FIELDS = ",".join([
    "id", "displayName", "givenName", "surname", "mail", "userPrincipalName",
    "mobilePhone", "businessPhones", "city", "department", "jobTitle",
    "officeLocation", "preferredLanguage", "accountEnabled",
])


def _msal_app() -> msal.ConfidentialClientApplication:
    # A fresh app (and token cache) per request: we never keep Microsoft tokens.
    return msal.ConfidentialClientApplication(
        client_id=settings.AZURE_CLIENT_ID,
        client_credential=settings.AZURE_CLIENT_SECRET,
        authority=settings.authority,
    )


def start_login(email: str | None) -> dict:
    """Returns the MSAL flow dict; flow['auth_uri'] is where the browser goes."""
    kwargs: dict = {"scopes": settings.scopes, "redirect_uri": settings.AZURE_REDIRECT_URI}
    if email:
        kwargs["login_hint"] = email  # pre-fills the email on Microsoft's page
    if settings.allowed_domains:
        kwargs["domain_hint"] = settings.allowed_domains[0]
    return _msal_app().initiate_auth_code_flow(**kwargs)


def finish_login(flow: dict, query_params: dict) -> dict:
    """Exchanges the code. MSAL verifies state, nonce and the PKCE verifier."""
    return _msal_app().acquire_token_by_auth_code_flow(flow, query_params, scopes=settings.scopes)


def logout_url(post_logout_redirect: str) -> str:
    from urllib.parse import quote
    return (f"{settings.authority}/oauth2/v2.0/logout"
            f"?post_logout_redirect_uri={quote(post_logout_redirect, safe='')}")


async def fetch_profile(access_token: str) -> dict:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{settings.GRAPH_BASE_URL}/me",
            params={"$select": PROFILE_FIELDS},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        r.raise_for_status()
        return r.json()


async def fetch_and_store_photo(access_token: str, login_key: str) -> bool:
    """Downloads the M365 profile photo (if the user has one). Returns True if saved."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"{settings.GRAPH_BASE_URL}/me/photos/240x240/$value",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if r.status_code == 404:
                # Some tenants don't have the 240px size; fall back to the default size.
                r = await client.get(
                    f"{settings.GRAPH_BASE_URL}/me/photo/$value",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
            if r.status_code != 200 or not r.content:
                return False
        folder = Path(settings.PHOTO_STORAGE_DIR)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{login_key}.jpg").write_bytes(r.content)
        return True
    except httpx.HTTPError as exc:
        log.warning("Photo download failed for %s: %s", login_key, exc)
        return False


def photo_path(login_key: str) -> Path:
    return Path(settings.PHOTO_STORAGE_DIR) / f"{login_key}.jpg"
