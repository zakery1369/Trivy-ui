import html
import json
import os
import re
import subprocess
import hashlib
import threading
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import docker
from docker.errors import DockerException, ImageNotFound
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
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


class AIRecommendRequest(BaseModel):
    scan_id: str = Field(..., min_length=1)
    provider: str = Field(..., min_length=1)
    base_url: str = Field(..., min_length=1)
    model: str = Field(..., min_length=1)
    api_key: str = ""
    language: str = "fa"


class AIProviderError(Exception):
    def __init__(self, status_code: int, provider_error: str, error_code: str = "", error_type: str = ""):
        self.status_code = status_code
        self.provider_error = provider_error
        self.error_code = error_code
        self.error_type = error_type


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


def extract_cvss(vuln: dict[str, Any]) -> float | None:
    cvss = vuln.get("CVSS")
    if not isinstance(cvss, dict):
        return None

    scores: list[float] = []
    for vendor_data in cvss.values():
        if not isinstance(vendor_data, dict):
            continue
        for key in ("V3Score", "V2Score"):
            value = vendor_data.get(key)
            if isinstance(value, (int, float)):
                scores.append(float(value))
    return max(scores) if scores else None


def summarize_report_for_ai(report: dict[str, Any], limit: int = 50) -> tuple[dict[str, Any], dict[str, int]]:
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    summary_counts = parse_summary(report)
    rows: list[dict[str, Any]] = []
    package_counts: dict[str, int] = {}
    fixable_count = 0
    not_fixed_count = 0
    image_name = ""

    metadata = report.get("Metadata")
    if isinstance(metadata, dict):
        image_name = str(metadata.get("RepoTags") or metadata.get("ImageID") or "")

    for result in report.get("Results", []) or []:
        target = result.get("Target", "")
        target_type = result.get("Type", "")
        if not image_name and target:
            image_name = str(target)

        for vuln in result.get("Vulnerabilities", []) or []:
            fixed_version = str(vuln.get("FixedVersion") or "").strip()
            package_name = str(vuln.get("PkgName") or "")
            severity = str(vuln.get("Severity") or "UNKNOWN").upper()

            if fixed_version:
                fixable_count += 1
            else:
                not_fixed_count += 1
            if package_name:
                package_counts[package_name] = package_counts.get(package_name, 0) + 1

            rows.append({
                "package": package_name,
                "severity": severity,
                "id": vuln.get("VulnerabilityID") or "",
                "installed_version": vuln.get("InstalledVersion") or "",
                "fixed_version": fixed_version or None,
                "title": vuln.get("Title") or vuln.get("Description") or "",
                "target": target,
                "type": target_type,
                "cvss": extract_cvss(vuln),
            })

    rows.sort(key=lambda item: (
        severity_order.get(str(item["severity"]), 4),
        0 if item.get("fixed_version") else 1,
        -(item.get("cvss") or 0),
    ))

    selected = rows[:limit]
    compact_report = {
        "image": image_name,
        "total_vulnerabilities": len(rows),
        "severity_counts": {
            "CRITICAL": summary_counts.get("CRITICAL", 0),
            "HIGH": summary_counts.get("HIGH", 0),
            "MEDIUM": summary_counts.get("MEDIUM", 0),
            "LOW": summary_counts.get("LOW", 0),
            "UNKNOWN": summary_counts.get("UNKNOWN", 0),
        },
        "fixable_vulnerabilities": fixable_count,
        "not_fixed_vulnerabilities": not_fixed_count,
        "top_vulnerable_packages": [
            {"package": name, "count": count}
            for name, count in sorted(package_counts.items(), key=lambda item: item[1], reverse=True)[:10]
        ],
        "vulnerabilities": selected,
        "omitted_vulnerabilities": max(0, len(rows) - len(selected)),
    }
    return compact_report, {
        "sent_vulnerabilities": len(selected),
        "omitted_vulnerabilities": compact_report["omitted_vulnerabilities"],
    }


def extract_json_text(value: str) -> str:
    text = value.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def provider_status_message(status_code: int, error_code: str = "") -> str:
    if status_code == 403 and error_code == "1010":
        return (
            "درخواست توسط لایه امنیتی سرویس AI رد شد. اگر Groq استفاده می‌کنید، معمولاً این خطا به API key مربوط نیست "
            "و می‌تواند به User-Agent، شبکه، IP یا gateway provider مربوط باشد."
        )

    messages = {
        401: "کلید API نامعتبر است یا ارسال نشده است.",
        403: "کلید API دسترسی لازم برای این درخواست را ندارد یا مدل برای این کلید فعال نیست.",
        404: "مدل یا endpoint سرویس AI اشتباه است.",
        413: "حجم درخواست برای سرویس AI بیش از حد مجاز است.",
        429: "محدودیت نرخ درخواست‌های سرویس AI فعال شده است.",
        498: "ظرفیت سرویس AI در حال حاضر کافی نیست.",
    }
    return messages.get(status_code, "درخواست به سرویس AI ناموفق بود.")


def redact_sensitive_text(value: str, api_key: str = "") -> str:
    text = value or ""
    if api_key:
        text = text.replace(api_key, "[redacted]")
    text = re.sub(r"Bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [redacted]", text, flags=re.IGNORECASE)
    text = re.sub(r"(authorization|api[-_ ]?key|x-api-key)\s*[:=]\s*[^,\s}]+", r"\1: [redacted]", text, flags=re.IGNORECASE)
    return text[:1000]


def extract_provider_error(body: str, api_key: str = "") -> dict[str, str]:
    sanitized_body = redact_sensitive_text(body, api_key).strip()
    if not sanitized_body:
        return {"message": "", "code": "", "type": ""}

    try:
        payload = json.loads(sanitized_body)
    except json.JSONDecodeError:
        return {"message": sanitized_body, "code": "", "type": ""}

    candidate: Any = payload
    error_code = ""
    error_type = ""

    if isinstance(payload, dict):
        if isinstance(payload.get("error"), dict):
            error_payload = payload["error"]
            error_code = str(error_payload.get("code") or "")
            error_type = str(error_payload.get("type") or "")
            candidate = error_payload.get("message") or error_payload.get("detail") or error_payload
        else:
            error_code = str(payload.get("code") or "")
            error_type = str(payload.get("type") or "")
            candidate = payload.get("error") or payload.get("message") or payload.get("detail") or payload

    if isinstance(candidate, (dict, list)):
        message = redact_sensitive_text(json.dumps(candidate, ensure_ascii=False), api_key)
    else:
        message = redact_sensitive_text(str(candidate), api_key)

    return {
        "message": message,
        "code": redact_sensitive_text(error_code, api_key),
        "type": redact_sensitive_text(error_type, api_key),
    }


def call_openai_compatible_chat(base_url: str, model: str, api_key: str, compact_report: dict[str, Any]) -> str:
    endpoint = base_url.rstrip("/") + "/chat/completions"
    system_prompt = (
        "You are a DevSecOps security assistant. Answer in Persian. Be practical and concise. "
        "Prioritize fixable Critical and High vulnerabilities. Never claim a vulnerability can be fixed "
        "when fixed_version is missing. Never invent package versions not present in the report summary. "
        "Recommend base image upgrades when many OS-level vulnerabilities exist. Explain not-fixed "
        "vulnerabilities carefully. Recommend re-scan after remediation. Avoid generic advice unless tied "
        "to the report. Output JSON only."
    )
    user_prompt = (
        "Generate remediation recommendations for this compact Trivy summary. Return exactly this JSON shape:\n"
        "{\n"
        '  "risk_level": "low|medium|high|critical",\n'
        '  "executive_summary": "...",\n'
        '  "priority_actions": [\n'
        "    {\n"
        '      "priority": 1,\n'
        '      "title": "...",\n'
        '      "reason": "...",\n'
        '      "affected_packages": ["..."],\n'
        '      "suggested_action": "...",\n'
        '      "effort": "low|medium|high"\n'
        "    }\n"
        "  ],\n"
        '  "base_image_recommendation": "...",\n'
        '  "not_fixed_guidance": "...",\n'
        '  "next_steps": ["..."]\n'
        "}\n\n"
        f"Report summary:\n{json.dumps(compact_report, ensure_ascii=False)}"
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Trivy-UI-AI-Remediation/1.0",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        provider_error = extract_provider_error(body, api_key)
        raise AIProviderError(
            exc.code,
            provider_error.get("message", ""),
            provider_error.get("code", ""),
            provider_error.get("type", ""),
        ) from exc

    choices = response_payload.get("choices") or []
    if not choices:
        raise ValueError("missing choices")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if not content:
        raise ValueError("missing content")
    return str(content)


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
body {{
  margin:0;
  background:radial-gradient(circle at 82% 0,rgba(34,123,98,.12),transparent 30rem),#08110f;
  color:#ecf4f1;
  font-family:Arial,Helvetica,sans-serif;
  direction:ltr;
  text-align:left;
}}
.container {{ max-width:1180px; margin:42px auto; padding:0 24px; }}
.card {{
  background:#0d1815;
  border:1px solid #20332d;
  border-radius:18px;
  padding:26px;
  box-shadow:0 18px 55px rgba(0,0,0,.2);
}}
h1 {{ margin:0 0 8px; font-size:26px; letter-spacing:-.4px; }}
.brand {{ margin:0 0 4px; color:#2dd4a7; font-size:11px; font-weight:700; letter-spacing:1px; }}
.meta {{ color:#8fa49d; margin:0 0 5px; font-size:13px; }}
.stats {{ display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin:24px 0; }}
.stat {{
  position:relative;
  overflow:hidden;
  border-radius:14px;
  padding:16px;
  color:#b5c5c0;
  background:#111e1a;
  border:1px solid #20332d;
  font-size:12px;
}}
.stat:before {{ content:""; position:absolute; inset:0 auto 0 0; width:3px; background:currentColor; }}
.stat.critical {{ color:#f05252; }}
.stat.high {{ color:#f58a45; }}
.stat.medium {{ color:#eabf45; }}
.stat.low {{ color:#47a9e8; }}
.stat.unknown {{ color:#778a84; }}
.stat b {{ display:block; margin-top:9px; color:#ecf4f1; font-size:27px; }}
.table-wrap {{ width:100%; overflow:auto; border:1px solid #20332d; border-radius:12px; }}
table {{ width:100%; min-width:1080px; border-collapse:collapse; direction:ltr; }}
th,td {{
  padding:12px 13px;
  border-bottom:1px solid #20332d;
  text-align:left;
  direction:ltr;
  unicode-bidi:plaintext;
  font-size:12px;
  vertical-align:top;
}}
th {{ background:#0a1411; color:#91a49e; position:sticky; top:0; font-weight:600; }}
tbody tr:last-child td {{ border-bottom:0; }}
tbody tr:hover td {{ background:rgba(255,255,255,.018); }}
td span {{ display:inline-block; padding:3px 8px; border-radius:999px; font-size:10px; font-weight:700; }}
tr.critical td span {{ color:#ff9a9a; background:rgba(240,82,82,.12); }}
tr.high td span {{ color:#ffb17d; background:rgba(245,138,69,.12); }}
tr.medium td span {{ color:#efd376; background:rgba(234,191,69,.12); }}
tr.low td span {{ color:#8dccf3; background:rgba(71,169,232,.12); }}
tr.unknown td span {{ color:#b1bfba; background:rgba(119,138,132,.14); }}
.empty {{ text-align:center; color:#8fa49d; padding:38px; }}
@media(max-width:800px) {{ .stats {{ grid-template-columns:1fr 1fr; }} .container {{ margin:20px auto; padding:0 12px; }} }}
</style>
</head>
<body>
<div class="container"><div class="card">
<p class="brand">ZAKOPS</p>
<h1>Trivy Scan Report</h1>
<p class="meta"><b>Image:</b> {image_line}</p>
<p class="meta"><b>Generated at:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="stats">
  <div class="stat critical">Critical<b>{summary.get('CRITICAL', 0)}</b></div>
  <div class="stat high">High<b>{summary.get('HIGH', 0)}</b></div>
  <div class="stat medium">Medium<b>{summary.get('MEDIUM', 0)}</b></div>
  <div class="stat low">Low<b>{summary.get('LOW', 0)}</b></div>
  <div class="stat unknown">Unknown<b>{summary.get('UNKNOWN', 0)}</b></div>
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


@app.post("/api/ai/recommend")
def ai_recommend(req: AIRecommendRequest):
    scan_id = safe_filename(req.scan_id.strip())
    provider = req.provider.strip().lower()
    base_url = req.base_url.strip()
    model = req.model.strip()
    api_key = req.api_key.strip()

    if not scan_id:
        raise HTTPException(status_code=400, detail="شناسه اسکن الزامی است.")
    if not provider:
        raise HTTPException(status_code=400, detail="ارائه‌دهنده AI الزامی است.")
    if not base_url:
        raise HTTPException(status_code=400, detail="آدرس سرویس AI الزامی است.")
    if not model:
        raise HTTPException(status_code=400, detail="مدل AI الزامی است.")
    if provider != "custom" and not api_key:
        raise HTTPException(status_code=400, detail="کلید API برای این ارائه‌دهنده الزامی است.")

    parsed_url = urllib.parse.urlparse(base_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise HTTPException(status_code=400, detail="آدرس سرویس AI معتبر نیست.")

    report_path = REPORT_DIR / f"{scan_id}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="گزارش اسکن پیدا نشد.")

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise HTTPException(status_code=500, detail="خواندن گزارش اسکن ناموفق بود.")

    summary_limit = 20 if provider == "groq" else 50
    compact_report, summary_meta = summarize_report_for_ai(report, limit=summary_limit)

    try:
        raw_text = call_openai_compatible_chat(base_url, model, api_key, compact_report)
    except AIProviderError as exc:
        return JSONResponse(
            status_code=200,
            content={
                "ok": False,
                "provider": provider,
                "provider_status": exc.status_code,
                "provider_error_code": exc.error_code,
                "message": provider_status_message(exc.status_code, exc.error_code),
                "provider_error": exc.provider_error,
                "summary": summary_meta,
            },
        )
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError, OSError):
        raise HTTPException(status_code=502, detail="دریافت پیشنهاد AI ناموفق بود. تنظیمات سرویس، مدل یا کلید API را بررسی کنید.")

    try:
        recommendation = json.loads(extract_json_text(raw_text))
    except json.JSONDecodeError:
        return {
            "ok": True,
            "recommendation": None,
            "raw_text": raw_text,
            "summary": summary_meta,
        }

    return {
        "ok": True,
        "recommendation": recommendation,
        "summary": summary_meta,
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
