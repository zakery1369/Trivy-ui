from fastapi import APIRouter

from app.services.trivy_service import get_trivy_version


router = APIRouter(prefix="/api")


@router.get("/trivy-version")
def trivy_version():
    return get_trivy_version()

