import json
import os
import subprocess
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from app.core.config import TRIVY_CACHE_DIR
from app.core.paths import REPORT_DIR
from app.services.docker_service import image_exists_locally, pull_image
from app.services.report_service import make_html_report, make_txt_report, parse_summary, safe_filename


TRIVY_OPERATION_LOCK = threading.Lock()


def run_command(args: list[str], timeout: int = 900) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["TRIVY_CACHE_DIR"] = TRIVY_CACHE_DIR
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)


@contextmanager
def trivy_operation():
    """Prevent DB updates and scans from using Trivy's local cache concurrently."""
    if not TRIVY_OPERATION_LOCK.acquire(blocking=False):
        raise HTTPException(
            status_code=409,
            detail="عملیات دیگری با Trivy در حال اجرا است. پس از پایان آن دوباره تلاش کنید.",
        )
    try:
        yield
    finally:
        TRIVY_OPERATION_LOCK.release()


def get_trivy_version() -> dict[str, str]:
    proc = run_command(["trivy", "--version"], timeout=30)
    if proc.returncode != 0:
        return {"version": "", "raw": proc.stderr or proc.stdout}

    raw = proc.stdout.strip()
    version = ""
    for line in raw.splitlines():
        line = line.strip()
        if line.lower().startswith("version:"):
            version = line.split(":", 1)[1].strip()
            break

    return {"version": version, "raw": raw}


def update_database() -> dict[str, object]:
    with trivy_operation():
        proc = run_command(["trivy", "image", "--download-db-only"], timeout=1200)
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=proc.stderr or proc.stdout)
    return {"ok": True, "message": "دیتابیس Trivy با موفقیت آپدیت شد.", "time": datetime.now().isoformat()}


def common_scan_args() -> list[str]:
    return [
        "trivy",
        "image",
        "--skip-db-update",
        "--cache-backend",
        "memory",
        "--scanners",
        "vuln",
    ]


def scan_image(image_ref: str, pull_if_missing: bool = True) -> dict[str, Any]:
    image_ref = image_ref.strip()
    if not image_ref:
        raise HTTPException(status_code=400, detail="نام یا آدرس ایمیج را وارد کنید.")

    local = image_exists_locally(image_ref)
    pulled = False
    if not local and pull_if_missing:
        pull_image(image_ref)
        pulled = True

    image_file_base = safe_filename(image_ref)
    scan_id = image_file_base

    # Do not use Path.with_suffix() here. Image names can contain dots
    # مثل container.workzy.ir_alocom_backend_qa_4a6afabd
    # and with_suffix() would treat the last dot-part as an extension and
    # incorrectly save the report as container.workzy.json.
    json_path = REPORT_DIR / f"{image_file_base}.json"
    scan_args = common_scan_args()

    with trivy_operation():
        proc = run_command([
            *scan_args,
            "--format",
            "json",
            "--output",
            str(json_path),
            image_ref,
        ])
        if proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=(proc.stderr or proc.stdout or "اسکن ناموفق بود. شاید لازم باشد اول دیتابیس Trivy را آپدیت کنید."),
            )

        report = json.loads(json_path.read_text(encoding="utf-8"))
        html_path = REPORT_DIR / f"{image_file_base}.html"
        txt_path = REPORT_DIR / f"{image_file_base}.txt"
        make_html_report(report, html_path, image_ref)
        make_txt_report(report, txt_path, image_ref)

        sarif_path = REPORT_DIR / f"{image_file_base}.sarif"
        sarif_proc = run_command([
            *scan_args,
            "--format",
            "sarif",
            "--output",
            str(sarif_path),
            image_ref,
        ])
        if sarif_proc.returncode != 0:
            sarif_path.write_text(
                "SARIF generation failed\n" + (sarif_proc.stderr or sarif_proc.stdout),
                encoding="utf-8",
            )

    summary = parse_summary(report)
    return {
        "ok": True,
        "scan_id": scan_id,
        "image": image_ref,
        "pulled": pulled,
        "summary": summary,
        "report": report,
        "report_filename": image_file_base,
        "downloads": {
            "json": f"/api/report/{scan_id}/json",
            "html": f"/api/report/{scan_id}/html",
            "txt": f"/api/report/{scan_id}/txt",
            "sarif": f"/api/report/{scan_id}/sarif",
        },
    }

