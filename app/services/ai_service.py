import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from fastapi import HTTPException
from fastapi.responses import JSONResponse

from app.services.report_service import read_json_report, safe_filename, summarize_report_for_ai


class AIProviderError(Exception):
    def __init__(self, status_code: int, provider_error: str, error_code: str = "", error_type: str = ""):
        self.status_code = status_code
        self.provider_error = provider_error
        self.error_code = error_code
        self.error_type = error_type


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


def call_openai_compatible_chat(
    base_url: str,
    model: str,
    api_key: str,
    compact_report: dict[str, Any],
    language: str = "fa",
) -> str:
    endpoint = base_url.rstrip("/") + "/chat/completions"
    system_prompt = (
        f"You are a DevSecOps security assistant. Answer in {'English' if language == 'en' else 'Persian'}. Be practical and concise. "
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


def recommend(
    scan_id: str,
    provider: str,
    base_url: str,
    model: str,
    api_key: str = "",
    language: str = "fa",
):
    scan_id = safe_filename(scan_id.strip())
    provider = provider.strip().lower()
    base_url = base_url.strip()
    model = model.strip()
    api_key = api_key.strip()

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

    report = read_json_report(scan_id)
    summary_limit = 20 if provider == "groq" else 50
    compact_report, summary_meta = summarize_report_for_ai(report, limit=summary_limit)

    try:
        raw_text = call_openai_compatible_chat(base_url, model, api_key, compact_report, language)
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

