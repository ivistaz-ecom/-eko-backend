from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from . import microsoft
from .config import get_settings
from .db import get_db
from .schemas import LanguageIn, user_out
from .sessions import SessionState, require_session

settings = get_settings()
router = APIRouter(prefix="/api/users", tags=["users"])


@router.patch("/me/language")
def set_language(body: LanguageIn, state: SessionState = Depends(require_session), db: Session = Depends(get_db)):
    lang = body.language.strip().lower()
    if lang not in settings.languages:
        raise HTTPException(status_code=422, detail={"code": "unsupported_language"})
    user = db.merge(state.user)
    user.language = lang
    db.commit()
    return {"user": user_out(user)}


@router.get("/photo/{login_key}")
def photo(login_key: str, _: SessionState = Depends(require_session)):
    # Photos are only served to signed-in employees (intranet), never publicly.
    if not login_key.replace("-", "").isalnum():
        raise HTTPException(status_code=404)
    path = microsoft.photo_path(login_key)
    if not path.is_file():
        raise HTTPException(status_code=404)
    return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=3600"})
