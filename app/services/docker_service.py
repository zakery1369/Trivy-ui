import docker
from docker.errors import DockerException, ImageNotFound
from fastapi import HTTPException


def docker_client():
    try:
        return docker.from_env()
    except DockerException:
        return None


def list_local_images() -> dict[str, object]:
    client = docker_client()
    if not client:
        return {"docker_connected": False, "images": []}

    images: list[str] = []
    try:
        for img in client.images.list():
            for tag in img.tags or []:
                images.append(tag)
    except DockerException:
        return {"docker_connected": False, "images": []}

    return {"docker_connected": True, "images": sorted(images)}


def image_exists_locally(image_ref: str) -> bool:
    client = docker_client()
    if not client:
        return False
    try:
        client.images.get(image_ref)
        return True
    except ImageNotFound:
        return False
    except DockerException:
        return False


def pull_image(image_ref: str) -> None:
    client = docker_client()
    if not client:
        raise HTTPException(
            status_code=400,
            detail="اتصال به Docker برقرار نیست. کانتینر را با mount کردن /var/run/docker.sock اجرا کنید.",
        )
    try:
        client.images.pull(image_ref)
    except DockerException as exc:
        raise HTTPException(status_code=400, detail=f"دانلود ایمیج ناموفق بود: {exc}")

