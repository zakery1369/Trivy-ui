import html
import json
import os
import re
import subprocess
import hashlib
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import docker
from docker.errors import DockerException, ImageNotFound
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = Path(os.getenv("REPORT_DIR", "/app/reports"))
REPORT_DIR.mkdir(parents=True, exist_ok=True)
TRIVY_CACHE_DIR = os.getenv("TRIVY_CACHE_DIR", "/var/lib/trivy")
TRIVY_OPERATION_LOCK = threading.Lock()

app = FastAPI(title="Trivy UI", version="1.0.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


class ScanRequest(BaseModel):
    image: str = Field(..., min_length=1)
    pull_if_missing: bool = True


def docker_client():
    try:
        return docker.from_env()
    except DockerException:
        return None


def safe_filename(value: str) -> str:
    """Create a stable, filesystem-safe report name from the full image reference.

    The old version truncated the image reference too aggressively, so long image
    names from the same registry could collapse to the same filename and overwrite
    each other. This version keeps the full sanitized image name when possible and
    adds a short hash only when shortening is required. No date/time is added.
    """
    raw = (value or "image").strip()
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "_", raw).strip("._-") or "image"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

    # Leave room for extension and avoid filesystem filename length limits.
    max_len = 180
    if len(cleaned) <= max_len:
        return cleaned

    # Keep both the beginning and the end, because the end often contains the tag.
    head_len = 90
    tail_len = max_len - head_len - len(digest) - 4
    return f"{cleaned[:head_len]}__{cleaned[-tail_len:]}__{digest}"


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


def parse_summary(report: dict[str, Any]) -> dict[str, int]:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for result in report.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = str(vuln.get("Severity", "UNKNOWN")).upper()
            summary[sev] = summary.get(sev, 0) + 1
    return summary


def make_html_report(report: dict[str, Any], destination: Path, image_ref: str = "") -> None:
    rows = []
    for result in report.get("Results", []) or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = str(vuln.get("Severity", "UNKNOWN")).upper()
            fixed_version = vuln.get("FixedVersion") or "Not fixed"
            title = vuln.get("Title") or vuln.get("Description") or ""
            rows.append(
                f"""
                <tr class="{html.escape(severity.lower())}">
                    <td>{html.escape(str(target))}</td>
                    <td>{html.escape(str(vuln.get('PkgName', '')))}</td>
                    <td><span>{html.escape(severity)}</span></td>
                    <td>{html.escape(str(vuln.get('VulnerabilityID', '')))}</td>
                    <td>{html.escape(str(vuln.get('InstalledVersion', '')))}</td>
                    <td>{html.escape(str(fixed_version))}</td>
                    <td>{html.escape(str(title))}</td>
                </tr>
                """
            )
    summary = parse_summary(report)
    image_line = html.escape(image_ref) if image_ref else "-"
    html_report = f"""
<!doctype html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Trivy Scan Report - {image_line}</title>
<style>
* {{ box-sizing: border-box; }}
body {{ margin:0; background:#08111f; color:#eaf2ff; font-family:Arial, Helvetica, sans-serif; direction:ltr; text-align:left; }}
.container {{ max-width:1280px; margin:40px auto; padding:0 24px; }}
.card {{ background:#101c2d; border:1px solid #223855; border-radius:20px; padding:24px; box-shadow:0 20px 60px rgba(0,0,0,.35); }}
h1 {{ margin:0 0 10px; font-size:28px; }}
.meta {{ color:#9fb3d1; margin:0 0 6px; }}
.stats {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin:22px 0; }}
.stat {{ border-radius:14px; padding:16px; background:#13243a; border:1px solid #2a4567; }}
.stat b {{ display:block; font-size:28px; margin-top:8px; color:#fff; }}
.table-wrap {{ width:100%; overflow:auto; border:1px solid #223855; border-radius:16px; }}
table {{ width:100%; min-width:1080px; border-collapse:collapse; direction:ltr; }}
th, td {{ padding:12px; border-bottom:1px solid #223855; text-align:left; direction:ltr; unicode-bidi:plaintext; font-size:14px; vertical-align:top; }}
th {{ background:#0d1828; color:#9fc3ff; position:sticky; top:0; }}
tr.critical td {{ background:rgba(239,68,68,.12); }}
tr.high td {{ background:rgba(249,115,22,.10); }}
tr.medium td {{ background:rgba(234,179,8,.08); }}
tr.low td {{ background:rgba(14,165,233,.08); }}
span {{ display:inline-block; padding:4px 10px; border-radius:999px; background:#1c2f4d; font-weight:700; }}
.empty {{ text-align:center; color:#9fb3d1; padding:28px; }}
@media(max-width:800px) {{ .stats {{ grid-template-columns:1fr 1fr; }} .container {{ margin:20px auto; padding:0 12px; }} }}
</style>
</head>
<body>
<div class="container"><div class="card">
<h1>Trivy Scan Report</h1>
<p class="meta"><b>Image:</b> {image_line}</p>
<p class="meta"><b>Generated at:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="stats">
  <div class="stat">Critical<b>{summary.get('CRITICAL', 0)}</b></div>
  <div class="stat">High<b>{summary.get('HIGH', 0)}</b></div>
  <div class="stat">Medium<b>{summary.get('MEDIUM', 0)}</b></div>
  <div class="stat">Low<b>{summary.get('LOW', 0)}</b></div>
  <div class="stat">Unknown<b>{summary.get('UNKNOWN', 0)}</b></div>
</div>
<div class="table-wrap">
<table>
<thead><tr><th>Target</th><th>Package</th><th>Severity</th><th>CVE</th><th>Installed Version</th><th>Fixed Version</th><th>Title</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan="7" class="empty">No vulnerabilities found.</td></tr>'}</tbody>
</table>
</div>
</div></div>
</body></html>
"""
    destination.write_text(html_report, encoding="utf-8")

def make_txt_report(report: dict[str, Any], destination: Path, image_ref: str = "") -> None:
    lines = ["Trivy Scan Report", "=" * 60, f"Image: {image_ref or '-'}", ""]
    for result in report.get("Results", []) or []:
        lines.append(f"Target: {result.get('Target', '')}")
        for vuln in result.get("Vulnerabilities", []) or []:
            lines.append(
                f"[{vuln.get('Severity', 'UNKNOWN')}] {vuln.get('VulnerabilityID', '')} | "
                f"{vuln.get('PkgName', '')} | installed: {vuln.get('InstalledVersion', '')} | "
                f"fixed: {vuln.get('FixedVersion') or 'Not fixed'}"
            )
        lines.append("")
    destination.write_text("\n".join(lines), encoding="utf-8")


@app.get("/", response_class=HTMLResponse)
def index():
    return (BASE_DIR / "static" / "index.html").read_text(encoding="utf-8")



@app.get("/api/trivy-version")
def trivy_version():
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

@app.get("/api/images")
def list_images():
    client = docker_client()
    if not client:
        return {"docker_connected": False, "images": []}
    images = []
    try:
        for img in client.images.list():
            tags = img.tags or []
            for tag in tags:
                images.append(tag)
    except DockerException:
        return {"docker_connected": False, "images": []}
    return {"docker_connected": True, "images": sorted(images)}


@app.post("/api/update-db")
def update_database():
    with trivy_operation():
        cmd = ["trivy", "image", "--download-db-only"]
        proc = run_command(cmd, timeout=1200)
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=proc.stderr or proc.stdout)
    return {"ok": True, "message": "دیتابیس Trivy با موفقیت آپدیت شد.", "time": datetime.now().isoformat()}


@app.post("/api/scan")
def scan(req: ScanRequest):
    image_ref = req.image.strip()
    if not image_ref:
        raise HTTPException(status_code=400, detail="نام یا آدرس ایمیج را وارد کنید.")

    local = image_exists_locally(image_ref)
    pulled = False
    if not local and req.pull_if_missing:
        pull_image(image_ref)
        pulled = True

    image_file_base = safe_filename(image_ref)
    scan_id = image_file_base

    # Do not use Path.with_suffix() here. Image names can contain dots
    # مثل container.workzy.ir_alocom_backend_qa_4a6afabd
    # and with_suffix() would treat the last dot-part as an extension and
    # incorrectly save the report as container.workzy.json.
    json_path = REPORT_DIR / f"{image_file_base}.json"

    # The filesystem scan cache is backed by BoltDB and permits only one process.
    # Memory cache avoids stale/cross-process fanal locks. The application-level
    # lock also prevents a DB update from overlapping these read operations.
    common_scan_args = [
        "trivy",
        "image",
        "--skip-db-update",
        "--cache-backend",
        "memory",
        "--scanners",
        "vuln",
    ]

    with trivy_operation():
        cmd = [
            *common_scan_args,
            "--format",
            "json",
            "--output",
            str(json_path),
            image_ref,
        ]
        proc = run_command(cmd)
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

        # SARIF is generated separately because Trivy supports it natively.
        sarif_path = REPORT_DIR / f"{image_file_base}.sarif"
        sarif_proc = run_command([
            *common_scan_args, "--format", "sarif", "--output", str(sarif_path), image_ref
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


@app.get("/api/report/{scan_id}/{fmt}")
def download_report(scan_id: str, fmt: str):
    fmt = fmt.lower()
    allowed = {"json": "application/json", "html": "text/html", "txt": "text/plain", "sarif": "application/sarif+json"}
    if fmt not in allowed:
        raise HTTPException(status_code=400, detail="فرمت خروجی معتبر نیست.")
    # First try the exact scan_id returned by /api/scan. The scan_id is already
    # sanitized, so applying Path.with_suffix() or over-aggressive parsing here can
    # break long registry names that contain dots.
    exact_name = safe_filename(scan_id)
    report_path = REPORT_DIR / f"{exact_name}.{fmt}"

    if not report_path.exists():
        # Backward compatibility for reports generated by older versions that
        # accidentally used Path.with_suffix() and truncated dotted filenames.
        matches = sorted(REPORT_DIR.glob(f"{exact_name}*.{fmt}"))
        if not matches:
            raise HTTPException(status_code=404, detail="گزارش پیدا نشد.")
        report_path = matches[0]

    return FileResponse(report_path, media_type=allowed[fmt], filename=report_path.name)
