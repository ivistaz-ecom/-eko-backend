from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .schemas import LanguageIn, ProfileIn, user_out
from .sessions import SessionState, require_session

settings = get_settings()
router = APIRouter(prefix="/api/users", tags=["users"])

_PHOTO_TYPES = {"jpg": "image/jpeg", "png": "image/png", "webp": "image/webp"}
_FUNCTIONS = {"Integrated Supply Chain", "Commercial", "Enabling Functions"}
_LOCATIONS = {
    "Bengaluru head office",
    "Gurugram corporate office",
    "Bidadi plant, Karnataka",
    "Wada plant, Maharashtra",
    "Ameenpur plant, Telangana",
    "Siddipet plant, Telangana",
    "Goblej plant, Gujarat",
    "Nemam plant, Tamil Nadu",
    "South zone office",
    "West zone office",
}
_MAX_PHOTO = 5 * 1024 * 1024


def _kind(data: bytes) -> str | None:
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def _find_photo(login_key: str) -> tuple[Path, str] | None:
    folder = Path(settings.PHOTO_STORAGE_DIR)
    found: list[tuple[float, Path, str]] = []
    for ext, media in _PHOTO_TYPES.items():
        path = folder / f"{login_key}.{ext}"
        if path.is_file():
            found.append((path.stat().st_mtime, path, media))
    if not found:
        return None
    found.sort()
    return found[-1][1], found[-1][2]


@router.patch("/me/language")
def set_language(body: LanguageIn, state: SessionState = Depends(require_session), db: Session = Depends(get_db)):
    lang = body.language.strip().lower()
    if lang not in settings.languages:
        raise HTTPException(status_code=422, detail={"code": "unsupported_language"})
    user = db.merge(state.user)
    user.language = lang
    db.commit()
    return {"user": user_out(user)}


@router.patch("/me/profile")
def set_profile(body: ProfileIn, state: SessionState = Depends(require_session), db: Session = Depends(get_db)):
    """Saves the name, designation, function and location from the welcome popup."""
    name = body.name.strip()
    designation = body.designation.strip()
    function = body.function.strip()
    location = body.location.strip()
    if not name or len(name) > 255:
        raise HTTPException(status_code=422, detail={"code": "bad_name"})
    if len(designation) > 160:
        raise HTTPException(status_code=422, detail={"code": "bad_designation"})
    if function and function not in _FUNCTIONS:
        raise HTTPException(status_code=422, detail={"code": "bad_function"})
    if location and location not in _LOCATIONS:
        raise HTTPException(status_code=422, detail={"code": "bad_location"})
    user = db.merge(state.user)
    user.name = name
    user.job_title = designation or None
    if function:
        user.job_function = function
        user.department = function
    if location:
        user.work_location = location
        user.city = location
    db.commit()
    return {"user": user_out(user)}


@router.post("/me/photo")
async def upload_photo(
    file: UploadFile = File(...),
    state: SessionState = Depends(require_session),
    db: Session = Depends(get_db),
):
    data = await file.read(_MAX_PHOTO + 1)
    kind = _kind(data)
    if not kind or len(data) > _MAX_PHOTO:
        raise HTTPException(status_code=422, detail={"code": "bad_photo"})
    login_key = state.user.login_key
    folder = Path(settings.PHOTO_STORAGE_DIR)
    folder.mkdir(parents=True, exist_ok=True)
    for ext in _PHOTO_TYPES:
        stale = folder / f"{login_key}.{ext}"
        if ext != kind and stale.is_file():
            stale.unlink()
    (folder / f"{login_key}.{kind}").write_bytes(data)
    user = db.merge(state.user)
    user.photo_url = f"/api/users/photo/{login_key}"
    db.commit()
    return {"user": user_out(user)}


@router.delete("/me/photo")
def delete_photo(state: SessionState = Depends(require_session), db: Session = Depends(get_db)):
    login_key = state.user.login_key
    folder = Path(settings.PHOTO_STORAGE_DIR)
    for ext in _PHOTO_TYPES:
        path = folder / f"{login_key}.{ext}"
        if path.is_file():
            path.unlink()
    user = db.merge(state.user)
    user.photo_url = None
    db.commit()
    return {"user": user_out(user)}


@router.get("/photo/{login_key}")
def photo(login_key: str, _: SessionState = Depends(require_session)):
    # Photos are only served to signed-in employees (intranet), never publicly.
    if not login_key.replace("-", "").isalnum():
        raise HTTPException(status_code=404)
    found = _find_photo(login_key)
    if not found:
        raise HTTPException(status_code=404)
    path, media = found
    return FileResponse(path, media_type=media, headers={"Cache-Control": "private, max-age=3600"})
