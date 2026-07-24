from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.core.paths import STATIC_DIR
from app.routers import health, images, pages, reports, scan


def create_app() -> FastAPI:
    app = FastAPI(title="Trivy UI", version="1.0.0")
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(pages.router)
    app.include_router(health.router)
    app.include_router(images.router)
    app.include_router(scan.router)
    app.include_router(reports.router)
    return app


app = create_app()
