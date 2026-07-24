from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from app.core.paths import STATIC_DIR


router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index():
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")

