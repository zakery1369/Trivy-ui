let currentTab = "local";
let currentDownloads = null;
let allRows = [];
let selectedSeverity = "ALL";
let imagesLoading = false;

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
        fixed: vuln.FixedVersion || "اصلاح نشده",
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
      <td>${escapeHtml(row.fixed)}</td>
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
    allRows = flattenVulns(data.report || {});
    updateSummary(data.summary);
    renderTable();
    $("downloadBtn").disabled = false;
    setStatus(data.pulled ? "ایمیج دریافت و با موفقیت اسکن شد." : "اسکن با موفقیت انجام شد.", "success");
    $("summaryTitle").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setStatus(error.message || "اسکن ناموفق بود.", "error");
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
