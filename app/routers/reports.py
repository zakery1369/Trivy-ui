from fastapi import APIRouter
from fastapi.responses import FileResponse

from app.services.report_service import get_report_path


router = APIRouter(prefix="/api")


@router.get("/report/{scan_id}/{fmt}")
def download_report(scan_id: str, fmt: str):
    report_path, media_type = get_report_path(scan_id, fmt)
    return FileResponse(report_path, media_type=media_type, filename=report_path.name)

