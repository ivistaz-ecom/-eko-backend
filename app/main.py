import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .routes_auth import router as auth_router
from .routes_users import router as users_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
settings = get_settings()

app = FastAPI(
    title="eKO Backend API",
    docs_url="/api/docs" if settings.APP_ENV != "production" else None,
    openapi_url="/api/openapi.json" if settings.APP_ENV != "production" else None,
)

# Only needed if the browser calls the API on a different origin. With the
# Next.js /api proxy (or Nginx routing /api to FastAPI) everything is same-origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type"],
)

app.include_router(auth_router)
app.include_router(users_router)


@app.get("/api/health")
def health():
    return {"ok": True}
