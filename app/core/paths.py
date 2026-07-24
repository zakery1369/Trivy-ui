import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
STATIC_DIR = BASE_DIR / "static"
REPORT_DIR = Path(os.getenv("REPORT_DIR", "/app/reports"))
REPORT_DIR.mkdir(parents=True, exist_ok=True)

