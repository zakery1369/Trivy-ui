import hashlib
import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from app.core.paths import REPORT_DIR


def safe_filename(value: str) -> str:
    """Create a stable, filesystem-safe report name from the full image reference."""
    raw = (value or "image").strip()
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "_", raw).strip("._-") or "image"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

    max_len = 180
    if len(cleaned) <= max_len:
        return cleaned

    head_len = 90
    tail_len = max_len - head_len - len(digest) - 4
    return f"{cleaned[:head_len]}__{cleaned[-tail_len:]}__{digest}"


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


def read_json_report(scan_id: str) -> dict[str, Any]:
    report_path = REPORT_DIR / f"{safe_filename(scan_id.strip())}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="گزارش اسکن پیدا نشد.")

    try:
        return json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise HTTPException(status_code=500, detail="خواندن گزارش اسکن ناموفق بود.")


def get_report_path(scan_id: str, fmt: str) -> tuple[Path, str]:
    fmt = fmt.lower()
    allowed = {"json": "application/json", "html": "text/html", "txt": "text/plain", "sarif": "application/sarif+json"}
    if fmt not in allowed:
        raise HTTPException(status_code=400, detail="فرمت خروجی معتبر نیست.")

    # The scan_id is already sanitized, so avoid suffix handling that truncates
    # dotted image names.
    exact_name = safe_filename(scan_id)
    report_path = REPORT_DIR / f"{exact_name}.{fmt}"

    if not report_path.exists():
        matches = sorted(REPORT_DIR.glob(f"{exact_name}*.{fmt}"))
        if not matches:
            raise HTTPException(status_code=404, detail="گزارش پیدا نشد.")
        report_path = matches[0]

    return report_path, allowed[fmt]

