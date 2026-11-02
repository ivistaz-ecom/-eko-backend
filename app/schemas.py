from pydantic import BaseModel

from .models import User


class LanguageIn(BaseModel):
    language: str


class ProfileIn(BaseModel):
    name: str = ""
    designation: str = ""
    function: str = ""
    location: str = ""


def user_out(u: User) -> dict:
    return {
        "id": u.id,
        "loginKey": u.login_key,
        "username": u.username,
        "email": u.email,
        "name": u.name,
        "phone": u.phone,
        "language": u.language,
        "city": u.city,
        "department": u.department,
        "jobTitle": u.job_title,
        "jobFunction": u.job_function,
        "workLocation": u.work_location,
        "photoUrl": u.photo_url,
        "role": u.role,
        "lastLoginAt": u.last_login_at.isoformat() + "Z" if u.last_login_at else None,
    }
