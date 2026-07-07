let currentTab = "local";
let currentDownloads = null;
let currentScanId = null;
let allRows = [];
let selectedSeverity = "ALL";
let imagesLoading = false;

const aiProviderBaseUrls = {
  openai: "https://api.openai.com/v1",
  openrouter: "https://openrouter.ai/api/v1",
  groq: "https://api.groq.com/openai/v1",
  deepseek: "https://api.deepseek.com/v1",
  custom: ""
};

const $ = (id) => document.getElementById(id);
const persianNumber = (value) => Number(value || 0).toLocaleString("fa-IR");

function setStatus(text, type = "") {
  const el = $("scanStatus");
  el.textContent = text;
  el.className = `status ${type}`.trim();
}

function setButtonBusy(button, busy, busyText) {
  if (!button.dataset.label) button.dataset.label = button.textContent.trim();
  button.disabled = busy;
  button.textContent = busy ? busyText : button.dataset.label;
}

function flattenVulns(report) {
  const rows = [];
  for (const result of report.Results || []) {
    for (const vuln of result.Vulnerabilities || []) {
      rows.push({
        package: vuln.PkgName || "",
        severity: (vuln.Severity || "UNKNOWN").toUpperCase(),
        cve: vuln.VulnerabilityID || "",
        installed: vuln.InstalledVersion || "",
        fixed: vuln.FixedVersion || "Not fixed",
        title: vuln.Title || vuln.Description || ""
      });
    }
  }
  return rows;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  })[character]);
}

function formatFixedVersions(value) {
  const text = String(value || "");
  const versions = text.split(/[,،]/).map((version) => version.trim()).filter(Boolean);

  if (versions.length <= 3) {
    return `<span class="fixed-version-value">${escapeHtml(text)}</span>`;
  }

  return `<span class="fixed-version-list">${
    versions.map((version) => `<span>${escapeHtml(version)}</span>`).join("")
  }</span>`;
}

function resetAiPanel(message = "ابتدا یک اسکن موفق انجام دهید.") {
  currentScanId = null;
  $("aiRecommendBtn").disabled = true;
  $("aiStatus").textContent = message;
  $("aiResult").hidden = true;
  $("aiResult").innerHTML = "";
}

function enableAiPanel(scanId) {
  currentScanId = scanId;
  $("aiRecommendBtn").disabled = false;
  $("aiStatus").textContent = "گزارش آماده است؛ در صورت نیاز تنظیمات AI را وارد کنید.";
  $("aiResult").hidden = true;
  $("aiResult").innerHTML = "";
}

function normalizeList(value) {
  return Array.isArray(value) ? value : [];
}

function renderAiRecommendation(data) {
  const result = $("aiResult");
  const recommendation = data.recommendation;
  const summary = data.summary || {};

  if (data.ok === false) {
    const providerMeta = `${data.provider || "provider"} · HTTP ${data.provider_status || "-"}${
      data.provider_error_code ? ` · code ${data.provider_error_code}` : ""
    }`;
    result.innerHTML = `
      <div class="ai-result-head">
        <strong>${escapeHtml(data.message || "درخواست به سرویس AI ناموفق بود.")}</strong>
        <span>${escapeHtml(providerMeta)}</span>
      </div>
      <p>${escapeHtml(data.provider_error || "جزئیات بیشتری از سرویس AI برنگشت.")}</p>
    `;
    result.hidden = false;
    return;
  }

  if (!recommendation) {
    result.innerHTML = `
      <div class="ai-result-head">
        <strong>پاسخ AI</strong>
        <span>${persianNumber(summary.sent_vulnerabilities)} مورد ارسال شد</span>
      </div>
      <pre>${escapeHtml(data.raw_text || "پاسخ قابل نمایش نیست.")}</pre>
    `;
    result.hidden = false;
    return;
  }

  const actions = normalizeList(recommendation.priority_actions).map((action) => `
    <article class="ai-action-item">
      <div>
        <span class="ai-priority">${escapeHtml(action.priority || "-")}</span>
        <strong>${escapeHtml(action.title || "اقدام پیشنهادی")}</strong>
      </div>
      <p>${escapeHtml(action.reason || "")}</p>
      <p>${escapeHtml(action.suggested_action || "")}</p>
      <small>پکیج‌ها: ${escapeHtml(normalizeList(action.affected_packages).join(", ") || "-")} · Effort: ${escapeHtml(action.effort || "-")}</small>
    </article>
  `).join("");

  result.innerHTML = `
    <div class="ai-result-head">
      <strong>سطح ریسک: ${escapeHtml(recommendation.risk_level || "-")}</strong>
      <span>${persianNumber(summary.sent_vulnerabilities)} مورد از مهمترین آسیب پذیری ها برای LLM ارسال شد و ${persianNumber(summary.omitted_vulnerabilities)} مورد به دلیل محدودیت حجم prompt ارسال نشد</span>
    </div>
    <p>${escapeHtml(recommendation.executive_summary || "")}</p>
    <div class="ai-actions-list">${actions || '<p class="ai-muted">اقدام اولویت‌دار مشخصی برنگشت.</p>'}</div>
    <div class="ai-guidance">
      <h3>Base image</h3>
      <p>${escapeHtml(recommendation.base_image_recommendation || "-")}</p>
      <h3>موارد بدون نسخه اصلاحی</h3>
      <p>${escapeHtml(recommendation.not_fixed_guidance || "-")}</p>
      <h3>گام‌های بعدی</h3>
      <ul>${normalizeList(recommendation.next_steps).map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ul>
    </div>
  `;
  result.hidden = false;
}

function renderTable() {
  const query = $("searchBox").value.trim().toLowerCase();
  let rows = allRows;

  if (selectedSeverity !== "ALL") {
    rows = rows.filter((row) => row.severity === selectedSeverity);
  }
  if (query) {
    rows = rows.filter((row) => Object.values(row).join(" ").toLowerCase().includes(query));
  }

  $("resultCount").textContent = persianNumber(rows.length);
  const body = $("resultsBody");
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">${
      allRows.length ? "موردی مطابق فیلتر فعلی پیدا نشد." : "هنوز اسکنی انجام نشده است."
    }</td></tr>`;
    return;
  }

  body.innerHTML = rows.slice(0, 250).map((row) => `
    <tr>
      <td>${escapeHtml(row.package)}</td>
      <td><span class="sev ${escapeHtml(row.severity)}">${escapeHtml(row.severity)}</span></td>
      <td>${escapeHtml(row.cve)}</td>
      <td>${escapeHtml(row.installed)}</td>
      <td class="fixed-version-cell">${formatFixedVersions(row.fixed)}</td>
      <td>${escapeHtml(row.title)}</td>
    </tr>
  `).join("");
}

function updateSummary(summary = {}) {
  const values = {
    critical: summary.CRITICAL || 0,
    high: summary.HIGH || 0,
    medium: summary.MEDIUM || 0,
    low: summary.LOW || 0
  };
  const total = Object.values(values).reduce((sum, count) => sum + count, 0) + (summary.UNKNOWN || 0);

  for (const [severity, count] of Object.entries(values)) {
    $(`${severity}Count`).textContent = persianNumber(count);
    $(`legend${severity[0].toUpperCase()}${severity.slice(1)}`).textContent = persianNumber(count);
  }
  $("donut").querySelector(".donut-content span").textContent = persianNumber(total);
  $("donut").setAttribute("aria-label", `توزیع شدت آسیب‌پذیری‌ها، مجموع ${total} مورد`);

  if (!total) {
    $("donut").style.background = "conic-gradient(var(--border-strong) 0 360deg)";
    return;
  }

  const criticalEnd = values.critical / total * 360;
  const highEnd = criticalEnd + values.high / total * 360;
  const mediumEnd = highEnd + values.medium / total * 360;
  const lowEnd = mediumEnd + values.low / total * 360;
  $("donut").style.background = `conic-gradient(
    var(--critical) 0deg ${criticalEnd}deg,
    var(--high) ${criticalEnd}deg ${highEnd}deg,
    var(--medium) ${highEnd}deg ${mediumEnd}deg,
    var(--low) ${mediumEnd}deg ${lowEnd}deg,
    var(--unknown) ${lowEnd}deg 360deg
  )`;
}

async function loadTrivyVersion() {
  try {
    const response = await fetch("/api/trivy-version", { cache: "no-store" });
    if (!response.ok) throw new Error();
    const data = await response.json();
    $("trivyTitle").textContent = data.version ? `Trivy ${data.version}` : "Trivy";
  } catch {
    $("trivyTitle").textContent = "Trivy";
  }
}

function setDockerStatus(connected, text) {
  $("dockerStatus").textContent = text;
  document.querySelector(".status-dot").style.background = connected ? "var(--accent)" : "var(--critical)";
}

async function loadImages() {
  if (imagesLoading) return;

  const select = $("localImages");
  const previousValue = select.value;
  imagesLoading = true;
  $("refreshImages").disabled = true;
  $("imagesStatus").textContent = "در حال به‌روزرسانی لیست ایمیج‌ها...";

  try {
    const response = await fetch(`/api/images?t=${Date.now()}`, { cache: "no-store" });
    if (!response.ok) throw new Error();
    const data = await response.json();
    const images = Array.isArray(data.images) ? data.images : [];
    setDockerStatus(data.docker_connected, data.docker_connected ? "Docker متصل" : "Docker در دسترس نیست");

    if (!data.docker_connected) {
      select.innerHTML = '<option value="">Docker در دسترس نیست</option>';
      $("imagesStatus").textContent = "اتصال Docker برقرار نیست؛ socket را بررسی کنید.";
    } else if (!images.length) {
      select.innerHTML = '<option value="">ایمیج محلی پیدا نشد</option>';
      $("imagesStatus").textContent = "برای اسکن، آدرس ایمیج را در تب Registry وارد کنید.";
    } else {
      select.innerHTML = images.map((image) =>
        `<option value="${escapeHtml(image)}">${escapeHtml(image)}</option>`
      ).join("");
      if (previousValue && images.includes(previousValue)) select.value = previousValue;
      $("imagesStatus").textContent = `${persianNumber(images.length)} ایمیج محلی در دسترس است.`;
    }
  } catch {
    select.innerHTML = '<option value="">خطا در دریافت ایمیج‌ها</option>';
    setDockerStatus(false, "خطا در اتصال Docker");
    $("imagesStatus").textContent = "دریافت لیست ایمیج‌ها ناموفق بود.";
  } finally {
    imagesLoading = false;
    $("refreshImages").disabled = false;
  }
}

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    currentTab = button.dataset.tab;
    document.querySelectorAll(".tab").forEach((tab) => {
      const selected = tab === button;
      tab.classList.toggle("active", selected);
      tab.setAttribute("aria-selected", String(selected));
    });
    const localActive = currentTab === "local";
    $("localPanel").classList.toggle("active-panel", localActive);
    $("localPanel").hidden = !localActive;
    $("remotePanel").classList.toggle("active-panel", !localActive);
    $("remotePanel").hidden = localActive;
    if (!localActive) $("remoteImage").focus();
  });
});

document.querySelectorAll(".filter").forEach((button) => {
  button.addEventListener("click", () => {
    selectedSeverity = button.dataset.sev;
    document.querySelectorAll(".filter").forEach((filter) => {
      filter.classList.toggle("active", filter === button);
    });
    renderTable();
  });
});

$("searchBox").addEventListener("input", renderTable);
$("refreshImages").addEventListener("click", loadImages);

$("aiProvider").addEventListener("change", () => {
  const provider = $("aiProvider").value;
  $("aiBaseUrl").value = aiProviderBaseUrls[provider] || "";
});

$("updateDb").addEventListener("click", async () => {
  const button = $("updateDb");
  setButtonBusy(button, true, "در حال به‌روزرسانی...");
  $("dbStatus").textContent = "دیتابیس در حال به‌روزرسانی است...";
  try {
    const response = await fetch("/api/update-db", { method: "POST", cache: "no-store" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "به‌روزرسانی ناموفق بود.");
    $("dbStatus").textContent = "دیتابیس همین حالا به‌روزرسانی شد.";
  } catch (error) {
    $("dbStatus").textContent = error.message || "به‌روزرسانی دیتابیس ناموفق بود.";
  } finally {
    setButtonBusy(button, false);
  }
});

$("scanBtn").addEventListener("click", async () => {
  const image = currentTab === "local" ? $("localImages").value : $("remoteImage").value.trim();
  if (!image) {
    setStatus("یک ایمیج انتخاب یا وارد کنید.", "error");
    return;
  }

  const button = $("scanBtn");
  resetAiPanel("اسکن جدید در حال اجرا است...");
  setButtonBusy(button, true, "در حال اسکن...");
  setStatus("آماده‌سازی ایمیج و اجرای اسکن...", "loading");
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ image, pull_if_missing: true })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "اسکن ناموفق بود.");

    currentDownloads = data.downloads;
    enableAiPanel(data.scan_id);
    allRows = flattenVulns(data.report || {});
    updateSummary(data.summary);
    renderTable();
    $("downloadBtn").disabled = false;
    setStatus(data.pulled ? "ایمیج دریافت و با موفقیت اسکن شد." : "اسکن با موفقیت انجام شد.", "success");
    $("summaryTitle").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    resetAiPanel("بعد از یک اسکن موفق، پیشنهاد AI فعال می‌شود.");
    setStatus(error.message || "اسکن ناموفق بود.", "error");
  } finally {
    setButtonBusy(button, false);
  }
});

$("aiRecommendBtn").addEventListener("click", async () => {
  if (!currentScanId) {
    $("aiStatus").textContent = "ابتدا یک اسکن موفق انجام دهید.";
    return;
  }

  const provider = $("aiProvider").value.trim();
  const baseUrl = $("aiBaseUrl").value.trim();
  const model = $("aiModel").value.trim();
  const apiKey = $("aiApiKey").value.trim();

  if (!baseUrl || !model) {
    $("aiStatus").textContent = "Base URL و مدل AI را وارد کنید.";
    return;
  }
  if (provider !== "custom" && !apiKey) {
    $("aiStatus").textContent = "برای این ارائه‌دهنده، API Key الزامی است.";
    return;
  }

  const button = $("aiRecommendBtn");
  setButtonBusy(button, true, "در حال دریافت...");
  $("aiStatus").textContent = "ارسال خلاصه امن گزارش به سرویس AI...";
  $("aiResult").hidden = true;
  $("aiResult").innerHTML = "";

  try {
    const response = await fetch("/api/ai/recommend", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_id: currentScanId,
        provider,
        base_url: baseUrl,
        model,
        api_key: apiKey,
        language: "fa"
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "دریافت پیشنهاد AI ناموفق بود.");
    if (data.ok === false) {
      renderAiRecommendation(data);
      $("aiStatus").textContent = data.message || "درخواست به سرویس AI ناموفق بود.";
      return;
    }
    renderAiRecommendation(data);
    $("aiStatus").textContent = "پیشنهاد AI آماده شد.";
  } catch (error) {
    $("aiStatus").textContent = error.message || "دریافت پیشنهاد AI ناموفق بود.";
  } finally {
    setButtonBusy(button, false);
  }
});

$("remoteImage").addEventListener("keydown", (event) => {
  if (event.key === "Enter") $("scanBtn").click();
});

$("downloadBtn").addEventListener("click", () => {
  if (!currentDownloads) return;
  const format = $("exportFormat").value;
  if (currentDownloads[format]) window.location.href = currentDownloads[format];
});

loadTrivyVersion();
// لیست در ورود اولیه فقط یک‌بار دریافت می‌شود؛ تازه‌سازی‌های بعدی کاملاً دستی هستند.
loadImages();
$("aiBaseUrl").value = aiProviderBaseUrls[$("aiProvider").value] || "";
