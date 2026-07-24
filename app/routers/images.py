from fastapi import APIRouter

from app.services.docker_service import list_local_images


router = APIRouter(prefix="/api")


@router.get("/images")
def list_images():
    return list_local_images()

