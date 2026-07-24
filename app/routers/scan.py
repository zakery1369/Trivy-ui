from fastapi import APIRouter

from app.schemas.scan import AIRecommendRequest, ScanRequest
from app.services.ai_service import recommend
from app.services.trivy_service import scan_image, update_database


router = APIRouter(prefix="/api")


@router.post("/update-db")
def update_db():
    return update_database()


@router.post("/scan")
def scan(req: ScanRequest):
    return scan_image(req.image, req.pull_if_missing)


@router.post("/ai/recommend")
def ai_recommend(req: AIRecommendRequest):
    return recommend(req.scan_id, req.provider, req.base_url, req.model, req.api_key, req.language)

