let currentTab = "local";
let currentDownloads = null;
let currentScanId = null;
let allRows = [];
let selectedSeverity = "ALL";
let imagesLoading = false;
let lastSummary = {};

const aiProviderBaseUrls = {
  openai: "https://api.openai.com/v1",
  openrouter: "https://openrouter.ai/api/v1",
  groq: "https://api.groq.com/openai/v1",
  deepseek: "https://api.deepseek.com/v1",
  custom: ""
};

const $ = (id) => document.getElementById(id);
const t = (key, params) => i18n.t(key, params);
const formatNumber = (value) => i18n.number(value);

function setStatus(key, type = "") {
  const element = $("scanStatus");
  element.textContent = t(key);
  element.dataset.messageKey = key;
  element.className = `status ${type}`.trim();
}

function setMessage(element, key, params = {}) {
  element.textContent = t(key, params);
  element.dataset.messageKey = key;
  element.dataset.messageParams = JSON.stringify(params);
}

function setButtonBusy(button, busy, busyKey) {
  const labelKey = button.dataset.i18n;
  button.disabled = busy;
  button.textContent = t(busy ? busyKey : labelKey);
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
        fixed: vuln.FixedVersion || null,
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
  const text = value || t("results.notFixed");
  const versions = text.split(/[,،]/).map((version) => version.trim()).filter(Boolean);
  if (versions.length <= 3) return `<span class="fixed-version-value">${escapeHtml(text)}</span>`;
  return `<span class="fixed-version-list">${versions.map((version) => `<span>${escapeHtml(version)}</span>`).join("")}</span>`;
}

function resetAiPanel(key = "ai.scanFirst") {
  currentScanId = null;
  $("aiRecommendBtn").disabled = true;
  setMessage($("aiStatus"), key);
  $("aiResult").hidden = true;
  $("aiResult").innerHTML = "";
}

function enableAiPanel(scanId) {
  currentScanId = scanId;
  $("aiRecommendBtn").disabled = false;
  setMessage($("aiStatus"), "ai.ready");
  $("aiResult").hidden = true;
  $("aiResult").innerHTML = "";
}

const normalizeList = (value) => Array.isArray(value) ? value : [];

function renderAiRecommendation(data) {
  const result = $("aiResult");
  const recommendation = data.recommendation;
  const summary = data.summary || {};

  if (data.ok === false) {
    const providerMeta = `${data.provider || "provider"} · HTTP ${data.provider_status || "-"}${
      data.provider_error_code ? ` · code ${data.provider_error_code}` : ""
    }`;
    result.innerHTML = `<div class="ai-result-head"><strong>${escapeHtml(t("ai.providerFailed"))}</strong><span>${escapeHtml(providerMeta)}</span></div><p>${escapeHtml(data.provider_error || t("ai.providerNoDetails"))}</p>`;
    result.hidden = false;
    return;
  }

  if (!recommendation) {
    result.innerHTML = `<div class="ai-result-head"><strong>${t("ai.response")}</strong><span>${t("ai.itemsSent", { count: summary.sent_vulnerabilities || 0 })}</span></div><pre>${escapeHtml(data.raw_text || t("ai.unavailableResponse"))}</pre>`;
    result.hidden = false;
    return;
  }

  const actions = normalizeList(recommendation.priority_actions).map((action) => `
    <article class="ai-action-item"><div><span class="ai-priority">${escapeHtml(action.priority || "-")}</span><strong>${escapeHtml(action.title || t("ai.recommendedAction"))}</strong></div>
    <p>${escapeHtml(action.reason || "")}</p><p>${escapeHtml(action.suggested_action || "")}</p>
    <small>${t("ai.packages")} ${escapeHtml(normalizeList(action.affected_packages).join(", ") || "-")} · Effort: ${escapeHtml(action.effort || "-")}</small></article>
  `).join("");

  result.innerHTML = `
    <div class="ai-result-head"><strong>${t("ai.riskLevel")} ${escapeHtml(recommendation.risk_level || "-")}</strong>
    <span>${t("ai.promptSummary", { sent: summary.sent_vulnerabilities || 0, omitted: summary.omitted_vulnerabilities || 0 })}</span></div>
    <p>${escapeHtml(recommendation.executive_summary || "")}</p>
    <div class="ai-actions-list">${actions || `<p class="ai-muted">${t("ai.noPriorityActions")}</p>`}</div>
    <div class="ai-guidance"><h3>Base image</h3><p>${escapeHtml(recommendation.base_image_recommendation || "-")}</p>
    <h3>${t("ai.noFix")}</h3><p>${escapeHtml(recommendation.not_fixed_guidance || "-")}</p>
    <h3>${t("ai.nextSteps")}</h3><ul>${normalizeList(recommendation.next_steps).map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ul></div>`;
  result.hidden = false;
}

function renderTable() {
  const query = $("searchBox").value.trim().toLowerCase();
  let rows = selectedSeverity === "ALL" ? allRows : allRows.filter((row) => row.severity === selectedSeverity);
  if (query) rows = rows.filter((row) => Object.values(row).join(" ").toLowerCase().includes(query));
  $("resultCount").textContent = formatNumber(rows.length);
  const body = $("resultsBody");
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">${t(allRows.length ? "results.noMatches" : "results.notScanned")}</td></tr>`;
    return;
  }
  body.innerHTML = rows.slice(0, 250).map((row) => `<tr><td>${escapeHtml(row.package)}</td><td><span class="sev ${escapeHtml(row.severity)}">${escapeHtml(row.severity)}</span></td><td>${escapeHtml(row.cve)}</td><td>${escapeHtml(row.installed)}</td><td class="fixed-version-cell">${formatFixedVersions(row.fixed)}</td><td>${escapeHtml(row.title)}</td></tr>`).join("");
}

function updateSummary(summary = {}) {
  lastSummary = summary;
  const values = { critical: summary.CRITICAL || 0, high: summary.HIGH || 0, medium: summary.MEDIUM || 0, low: summary.LOW || 0 };
  const total = Object.values(values).reduce((sum, count) => sum + count, 0) + (summary.UNKNOWN || 0);
  for (const [severity, count] of Object.entries(values)) {
    $(`${severity}Count`).textContent = formatNumber(count);
    $(`legend${severity[0].toUpperCase()}${severity.slice(1)}`).textContent = formatNumber(count);
  }
  $("donut").querySelector(".donut-content span").textContent = formatNumber(total);
  $("donut").setAttribute("aria-label", t("distribution.totalLabel", { count: total }));
  if (!total) {
    $("donut").style.background = "conic-gradient(var(--border-strong) 0 360deg)";
    return;
  }
  const criticalEnd = values.critical / total * 360;
  const highEnd = criticalEnd + values.high / total * 360;
  const mediumEnd = highEnd + values.medium / total * 360;
  const lowEnd = mediumEnd + values.low / total * 360;
  $("donut").style.background = `conic-gradient(var(--critical) 0deg ${criticalEnd}deg,var(--high) ${criticalEnd}deg ${highEnd}deg,var(--medium) ${highEnd}deg ${mediumEnd}deg,var(--low) ${mediumEnd}deg ${lowEnd}deg,var(--unknown) ${lowEnd}deg 360deg)`;
}

async function loadTrivyVersion() {
  try {
    const response = await fetch("/api/trivy-version", { cache: "no-store" });
    if (!response.ok) throw new Error();
    const data = await response.json();
    $("trivyTitle").textContent = data.version ? `Trivy ${data.version}` : "Trivy";
  } catch { $("trivyTitle").textContent = "Trivy"; }
}

function setDockerStatus(connected, key) {
  setMessage($("dockerStatus"), key);
  document.querySelector(".status-dot").style.background = connected ? "var(--accent)" : "var(--critical)";
}

async function loadImages() {
  if (imagesLoading) return;
  const select = $("localImages");
  const previousValue = select.value;
  imagesLoading = true;
  $("refreshImages").disabled = true;
  setMessage($("imagesStatus"), "scan.refreshingImages");
  try {
    const response = await fetch(`/api/images?t=${Date.now()}`, { cache: "no-store" });
    if (!response.ok) throw new Error();
    const data = await response.json();
    const images = Array.isArray(data.images) ? data.images : [];
    setDockerStatus(data.docker_connected, data.docker_connected ? "docker.connected" : "docker.unavailable");
    if (!data.docker_connected) {
      select.innerHTML = `<option value="">${t("docker.unavailable")}</option>`;
      setMessage($("imagesStatus"), "scan.socketHelp");
    } else if (!images.length) {
      select.innerHTML = `<option value="">${t("scan.noLocalImages")}</option>`;
      setMessage($("imagesStatus"), "scan.useRegistry");
    } else {
      select.innerHTML = images.map((image) => `<option value="${escapeHtml(image)}">${escapeHtml(image)}</option>`).join("");
      if (previousValue && images.includes(previousValue)) select.value = previousValue;
      setMessage($("imagesStatus"), "scan.imagesAvailable", { count: images.length });
    }
  } catch {
    select.innerHTML = `<option value="">${t("scan.imagesLoadError")}</option>`;
    setDockerStatus(false, "docker.connectionError");
    setMessage($("imagesStatus"), "scan.imagesRequestFailed");
  } finally {
    imagesLoading = false;
    $("refreshImages").disabled = false;
  }
}

document.querySelectorAll(".tab").forEach((button) => button.addEventListener("click", () => {
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
}));

document.querySelectorAll(".filter").forEach((button) => button.addEventListener("click", () => {
  selectedSeverity = button.dataset.sev;
  document.querySelectorAll(".filter").forEach((filter) => filter.classList.toggle("active", filter === button));
  renderTable();
}));

$("searchBox").addEventListener("input", renderTable);
$("refreshImages").addEventListener("click", loadImages);
$("aiProvider").addEventListener("change", () => { $("aiBaseUrl").value = aiProviderBaseUrls[$("aiProvider").value] || ""; });

$("updateDb").addEventListener("click", async () => {
  const button = $("updateDb");
  setButtonBusy(button, true, "database.updating");
  setMessage($("dbStatus"), "database.updatingStatus");
  try {
    const response = await fetch("/api/update-db", { method: "POST", cache: "no-store" });
    if (!response.ok) throw new Error();
    setMessage($("dbStatus"), "database.updated");
  } catch { setMessage($("dbStatus"), "database.failed"); }
  finally { setButtonBusy(button, false); }
});

$("scanBtn").addEventListener("click", async () => {
  const image = currentTab === "local" ? $("localImages").value : $("remoteImage").value.trim();
  if (!image) return setStatus("scan.selectRequired", "error");
  const button = $("scanBtn");
  resetAiPanel("scan.newRunning");
  setButtonBusy(button, true, "scan.scanning");
  setStatus("scan.preparing", "loading");
  try {
    const response = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ image, pull_if_missing: true }) });
    const data = await response.json();
    if (!response.ok) throw new Error();
    currentDownloads = data.downloads;
    enableAiPanel(data.scan_id);
    allRows = flattenVulns(data.report || {});
    updateSummary(data.summary);
    renderTable();
    $("downloadBtn").disabled = false;
    setStatus(data.pulled ? "scan.pulledSuccess" : "scan.success", "success");
    $("summaryTitle").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch {
    resetAiPanel("ai.afterScan");
    setStatus("scan.failed", "error");
  } finally { setButtonBusy(button, false); }
});

$("aiRecommendBtn").addEventListener("click", async () => {
  if (!currentScanId) return setMessage($("aiStatus"), "ai.scanFirst");
  const provider = $("aiProvider").value.trim();
  const baseUrl = $("aiBaseUrl").value.trim();
  const model = $("aiModel").value.trim();
  const apiKey = $("aiApiKey").value.trim();
  if (!baseUrl || !model) return setMessage($("aiStatus"), "ai.settingsRequired");
  if (provider !== "custom" && !apiKey) return setMessage($("aiStatus"), "ai.keyRequired");
  const button = $("aiRecommendBtn");
  setButtonBusy(button, true, "ai.loading");
  setMessage($("aiStatus"), "ai.sending");
  $("aiResult").hidden = true;
  try {
    const response = await fetch("/api/ai/recommend", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scan_id: currentScanId, provider, base_url: baseUrl, model, api_key: apiKey, language: i18n.locale }) });
    const data = await response.json();
    if (!response.ok) throw new Error();
    renderAiRecommendation(data);
    setMessage($("aiStatus"), data.ok === false ? "ai.providerFailed" : "ai.complete");
  } catch { setMessage($("aiStatus"), "ai.failed"); }
  finally { setButtonBusy(button, false); }
});

$("remoteImage").addEventListener("keydown", (event) => { if (event.key === "Enter") $("scanBtn").click(); });
$("downloadBtn").addEventListener("click", () => {
  if (!currentDownloads) return;
  const format = $("exportFormat").value;
  if (currentDownloads[format]) window.location.href = currentDownloads[format];
});

$("languageToggle").addEventListener("click", () => i18n.setLocale(i18n.locale === "fa" ? "en" : "fa"));
document.addEventListener("localechange", () => {
  document.querySelectorAll("[data-message-key]").forEach((element) => setMessage(element, element.dataset.messageKey, JSON.parse(element.dataset.messageParams || "{}")));
  updateSummary(lastSummary);
  renderTable();
  if (!$("aiResult").hidden) $("aiResult").hidden = true;
});

i18n.apply();
updateSummary(lastSummary);
renderTable();
loadTrivyVersion();
loadImages();
$("aiBaseUrl").value = aiProviderBaseUrls[$("aiProvider").value] || "";
