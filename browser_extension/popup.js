const API_BASE = "http://127.0.0.1:5001/api/discovery";

const consentStatus = document.getElementById("consent-status");
const backendStatus = document.getElementById("backend-status");
const lastResult = document.getElementById("last-result");
const openTabsResult = document.getElementById("open-tabs-result");
const pageMetricsStatus = document.getElementById("page-metrics-status");
const lastPageMetricsResult = document.getElementById("last-page-metrics-result");
const enablePageMetricsButton = document.getElementById("enable-page-metrics");
const disablePageMetricsButton = document.getElementById("disable-page-metrics");
const scanOpenTabsButton = document.getElementById("scan-open-tabs");
const pairingCode = document.getElementById("pairing-code");
const message = document.getElementById("message");
let availablePageMetricOrigins = [];

async function getBackendStatus(token) {
  const response = await fetch(`${API_BASE}/status`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    let result;
    try {
      result = await response.json();
    } catch {
      if (response.status === 404) {
        throw new Error(
          "This Flask service has no browser-discovery API. Run the sdpmain Flask service on port 5001.",
        );
      }
      throw new Error(`Backend returned HTTP ${response.status}.`);
    }
    throw new Error(result.error || `Backend returned HTTP ${response.status}.`);
  }
  return response.json();
}

async function refreshStatus() {
  const {
    consent,
    token,
    lastDiscoveryStatus,
    lastOpenTabsScan,
    pageMetricsEnabled,
    pageMetricsOrigins = [],
    lastPageMetricsStatus,
  } = await chrome.storage.local.get([
    "consent",
    "token",
    "lastDiscoveryStatus",
    "lastOpenTabsScan",
    "pageMetricsEnabled",
    "pageMetricsOrigins",
    "lastPageMetricsStatus",
  ]);
  consentStatus.textContent = consent || "disabled";
  lastResult.textContent = lastDiscoveryStatus || "—";
  openTabsResult.textContent = lastOpenTabsScan || "Not scanned";
  lastPageMetricsResult.textContent = lastPageMetricsStatus || "—";
  pageMetricsStatus.textContent = pageMetricsEnabled
    ? `Enabled for ${pageMetricsOrigins.length} website(s)`
    : "Disabled";
  disablePageMetricsButton.disabled = !pageMetricsEnabled;
  if (!token) {
    backendStatus.textContent = "Not paired";
    enablePageMetricsButton.disabled = true;
    scanOpenTabsButton.disabled = true;
    return;
  }
  try {
    const status = await getBackendStatus(token);
    backendStatus.textContent =
      status.mode === "enabled" ? "Connected · discovery enabled" :
      status.mode === "paused" ? "Connected · discovery paused" :
      "Connected · discovery disabled";
    scanOpenTabsButton.disabled =
      consent !== "enabled" || status.mode !== "enabled";
    const response = await fetch(`${API_BASE}/applications`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || `Backend returned HTTP ${response.status}.`);
    }
    availablePageMetricOrigins = (result.applications || [])
      .filter((application) =>
        ["registered", "existing"].includes(application.registration_status) &&
        application.monitoring_status === "enabled" &&
        !application.user_excluded &&
        typeof application.origin === "string")
      .map((application) => application.origin);
    enablePageMetricsButton.disabled =
      consent !== "enabled" || availablePageMetricOrigins.length === 0;
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Backend status check failed.";
    backendStatus.textContent =
      errorMessage === "Browser extension is not paired."
        ? "Not paired"
        : errorMessage.includes("no browser-discovery API")
          ? "Wrong Flask service"
          : "Not connected";
    availablePageMetricOrigins = [];
    enablePageMetricsButton.disabled = true;
    scanOpenTabsButton.disabled = true;
    message.textContent = errorMessage;
  }
}

async function setConsent(value) {
  await chrome.storage.local.set({ consent: value });
  if (value !== "enabled") {
    const result = await chrome.runtime.sendMessage({
      type: "SDP_DISABLE_PAGE_METRICS",
    });
    if (!result?.ok) {
      message.textContent = result?.error || "Could not disable page metrics.";
      return;
    }
  }
  message.textContent =
    value === "enabled" ? "Browser discovery enabled for this extension." :
    value === "paused" ? "Browser discovery paused." :
    "Browser discovery disabled.";
  await refreshStatus();
}

document.getElementById("enable").addEventListener("click", () => setConsent("enabled"));
document.getElementById("pause").addEventListener("click", () => setConsent("paused"));
document.getElementById("disable").addEventListener("click", () => setConsent("disabled"));

scanOpenTabsButton.addEventListener("click", async () => {
  message.textContent = "";
  try {
    const granted = await chrome.permissions.request({
      permissions: ["tabs"],
    });
    if (!granted) {
      message.textContent = "Tab access was not granted; no open tabs were scanned.";
      return;
    }
    const result = await chrome.runtime.sendMessage({
      type: "SDP_SCAN_OPEN_TABS",
    });
    if (!result?.ok) {
      throw new Error(result?.error || "Could not scan open tabs.");
    }
    message.textContent =
      `Scanned ${result.tabCount} open HTTP(S) tab(s) across ` +
      `${result.websiteCount} website(s).` +
      (result.skippedPrivate
        ? ` Skipped ${result.skippedPrivate} local/private site(s).`
        : "");
    await refreshStatus();
  } catch (error) {
    message.textContent =
      error instanceof Error ? error.message : "Could not scan open tabs.";
  }
});

enablePageMetricsButton.addEventListener("click", async () => {
  message.textContent = "";
  if (!availablePageMetricOrigins.length) {
    message.textContent = "No registered, monitored websites are available.";
    return;
  }
  try {
    const origins = [...new Set(availablePageMetricOrigins)];
    const granted = await chrome.permissions.request({
      origins: origins.map((origin) => `${origin}/*`),
    });
    if (!granted) {
      message.textContent = "Website access was not granted; no page metrics were enabled.";
      return;
    }
    const result = await chrome.runtime.sendMessage({
      type: "SDP_ENABLE_PAGE_METRICS",
      origins,
    });
    if (!result?.ok) {
      throw new Error(result?.error || "Could not enable page metrics.");
    }
    const reloadHint = result.failures.length
      ? ` ${result.failures.length} open tab(s) could not be attached; reload them to start measurements.`
      : "";
    message.textContent =
      `Page measurements enabled for ${result.enabledOrigins} website(s).` +
      reloadHint;
    await refreshStatus();
  } catch (error) {
    message.textContent =
      error instanceof Error ? error.message : "Could not enable page metrics.";
  }
});

disablePageMetricsButton.addEventListener("click", async () => {
  message.textContent = "";
  try {
    const result = await chrome.runtime.sendMessage({
      type: "SDP_DISABLE_PAGE_METRICS",
    });
    if (!result?.ok) {
      throw new Error(result?.error || "Could not disable page metrics.");
    }
    message.textContent =
      "Page measurements disabled and website permissions removed.";
    await refreshStatus();
  } catch (error) {
    message.textContent =
      error instanceof Error ? error.message : "Could not disable page metrics.";
  }
});

document.getElementById("pair").addEventListener("click", async () => {
  message.textContent = "";
  const code = pairingCode.value.trim();
  if (!code) {
    message.textContent = "Enter the one-time pairing code.";
    return;
  }
  try {
    const response = await fetch(`${API_BASE}/pair`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });
    const result = await response.json();
    if (!response.ok || !result.token) {
      throw new Error(result.error || "Pairing failed.");
    }
    await chrome.storage.local.set({ token: result.token });
    pairingCode.value = "";
    message.textContent = "Extension paired with the local SDP backend.";
    await refreshStatus();
  } catch (error) {
    message.textContent = error.message || "Could not reach the local backend.";
  }
});

void refreshStatus();
