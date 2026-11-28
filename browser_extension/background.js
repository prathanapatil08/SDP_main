const API_BASE = "http://127.0.0.1:5001/api/discovery";
const DISCOVERY_COOLDOWN_MS = 60_000;
const MAX_RECENT_ORIGINS = 200;
const MAX_OPEN_TABS = 1000;
const PAGE_METRICS_SCRIPT_ID = "sdp-page-metrics";

async function submitOrigin(urlString) {
  const { consent, token } = await chrome.storage.local.get(["consent", "token"]);
  if (consent !== "enabled" || !token) {
    return;
  }

  let pageUrl;
  try {
    pageUrl = new URL(urlString);
  } catch {
    return;
  }
  if (
    !["http:", "https:"].includes(pageUrl.protocol) ||
    pageUrl.username ||
    pageUrl.password ||
    !pageUrl.hostname
  ) {
    return;
  }

  const origin = pageUrl.origin;
  const now = Date.now();
  const recent = await chrome.storage.session.get("recentOrigins");
  const recentOrigins = recent.recentOrigins || {};
  if (now - (recentOrigins[origin] || 0) < DISCOVERY_COOLDOWN_MS) {
    return;
  }
  recentOrigins[origin] = now;
  for (const [knownOrigin, seenAt] of Object.entries(recentOrigins)) {
    if (now - seenAt > DISCOVERY_COOLDOWN_MS) {
      delete recentOrigins[knownOrigin];
    }
  }
  const entries = Object.entries(recentOrigins)
    .sort((left, right) => right[1] - left[1])
    .slice(0, MAX_RECENT_ORIGINS);
  await chrome.storage.session.set({
    recentOrigins: Object.fromEntries(entries),
  });

  try {
    const response = await fetch(`${API_BASE}/register`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        origin,
        hostname: pageUrl.hostname,
        source: "browser_extension",
      }),
    });
    const result = await response.json();
    await chrome.storage.local.set({
      lastDiscoveryStatus: response.ok
        ? result.registration_status || "discovered"
        : result.error || `Backend returned ${response.status}`,
    });
  } catch {
    await chrome.storage.local.set({
      lastDiscoveryStatus: "Local backend unavailable",
    });
  }
}

chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0 || !details.url) {
    return;
  }
  void submitOrigin(details.url);
});

function normalizeWebsiteOrigin(value) {
  if (typeof value !== "string") {
    return null;
  }
  try {
    const parsed = new URL(value);
    if (
      !["http:", "https:"].includes(parsed.protocol) ||
      parsed.username ||
      parsed.password ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash ||
      !parsed.hostname
    ) {
      return null;
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

async function updatePageMetricsScript(origins) {
  const patterns = [...new Set(origins.map((origin) => `${origin}/*`))];
  const existing = await chrome.scripting.getRegisteredContentScripts({
    ids: [PAGE_METRICS_SCRIPT_ID],
  });
  if (existing.length) {
    await chrome.scripting.unregisterContentScripts({
      ids: [PAGE_METRICS_SCRIPT_ID],
    });
  }
  if (patterns.length) {
    await chrome.scripting.registerContentScripts([{
      id: PAGE_METRICS_SCRIPT_ID,
      matches: patterns,
      js: ["page_metrics.js"],
      runAt: "document_idle",
      allFrames: false,
      persistAcrossSessions: true,
    }]);
  }
}

async function enablePageMetrics(origins) {
  const { consent, token } = await chrome.storage.local.get(["consent", "token"]);
  if (consent !== "enabled" || !token) {
    throw new Error("Enable browser discovery and pair the extension first.");
  }
  const normalized = [...new Set(
    (Array.isArray(origins) ? origins : [])
      .map(normalizeWebsiteOrigin)
      .filter(Boolean),
  )];
  const permitted = [];
  for (const origin of normalized) {
    if (await chrome.permissions.contains({ origins: [`${origin}/*`] })) {
      permitted.push(origin);
    }
  }
  if (!permitted.length) {
    throw new Error("No authorized website permissions were granted.");
  }

  await chrome.storage.local.set({
    pageMetricsEnabled: true,
    pageMetricsOrigins: permitted,
  });
  await updatePageMetricsScript(permitted);

  const tabs = await chrome.tabs.query({
    url: permitted.map((origin) => `${origin}/*`),
  });
  const failures = [];
  for (const tab of tabs) {
    if (typeof tab.id !== "number") {
      continue;
    }
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["page_metrics.js"],
        world: "ISOLATED",
      });
    } catch (error) {
      failures.push(error instanceof Error ? error.message : String(error));
    }
  }
  return { enabledOrigins: permitted.length, activeTabs: tabs.length, failures };
}

async function disablePageMetrics() {
  const { pageMetricsOrigins = [] } = await chrome.storage.local.get([
    "pageMetricsOrigins",
  ]);
  await stopPageMetricsForOrigins(pageMetricsOrigins);
  await chrome.storage.local.set({
    pageMetricsEnabled: false,
    pageMetricsOrigins: [],
  });
  await updatePageMetricsScript([]);
  if (pageMetricsOrigins.length) {
    await chrome.permissions.remove({
      origins: pageMetricsOrigins.map((origin) => `${origin}/*`),
    });
  }
}

function originFromSender(sender) {
  try {
    const senderUrl = new URL(sender.url);
    if (
      ["http:", "https:"].includes(senderUrl.protocol) &&
      !senderUrl.username &&
      !senderUrl.password
    ) {
      return senderUrl.origin;
    }
  } catch {
    return null;
  }
  return null;
}

async function trackPageMetricsTab(sender) {
  const origin = originFromSender(sender);
  if (!sender.tab || typeof sender.tab.id !== "number" || !origin) {
    return;
  }
  const { consent, pageMetricsEnabled, pageMetricsOrigins = [] } =
    await chrome.storage.local.get([
      "consent",
      "pageMetricsEnabled",
      "pageMetricsOrigins",
    ]);
  if (
    consent !== "enabled" ||
    !pageMetricsEnabled ||
    !pageMetricsOrigins.includes(origin) ||
    !(await chrome.permissions.contains({ origins: [`${origin}/*`] }))
  ) {
    return;
  }
  const { pageMetricsTabs = {} } =
    await chrome.storage.session.get("pageMetricsTabs");
  const tabIds = new Set(pageMetricsTabs[origin] || []);
  tabIds.add(sender.tab.id);
  pageMetricsTabs[origin] = [...tabIds];
  await chrome.storage.session.set({ pageMetricsTabs });
}

async function stopPageMetricsForOrigins(origins) {
  const { pageMetricsTabs = {} } =
    await chrome.storage.session.get("pageMetricsTabs");
  for (const origin of origins) {
    const tabIds = pageMetricsTabs[origin] || [];
    for (const tabId of tabIds) {
      try {
        await chrome.tabs.sendMessage(tabId, {
          type: "SDP_STOP_PAGE_METRICS",
        });
      } catch {
        // A tab may have closed or navigated before it could be stopped.
      }
    }
    delete pageMetricsTabs[origin];
  }
  await chrome.storage.session.set({ pageMetricsTabs });
}

async function submitPageMetrics(payload, sender) {
  const senderOrigin = originFromSender(sender);
  const payloadOrigin = normalizeWebsiteOrigin(payload?.origin);
  if (!sender.tab || !senderOrigin || payloadOrigin !== senderOrigin) {
    return { ok: false, error: "Page metric origin did not match its tab." };
  }
  const {
    consent,
    token,
    pageMetricsEnabled,
    pageMetricsOrigins = [],
  } = await chrome.storage.local.get([
    "consent",
    "token",
    "pageMetricsEnabled",
    "pageMetricsOrigins",
  ]);
  if (
    consent !== "enabled" ||
    !pageMetricsEnabled ||
    !token ||
    !pageMetricsOrigins.includes(senderOrigin) ||
    !(await chrome.permissions.contains({
      origins: [`${senderOrigin}/*`],
    }))
  ) {
    return { ok: false, error: "Page metrics are not authorized for this site." };
  }

  try {
    const response = await fetch(`${API_BASE}/page-metrics`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    const status = response.ok
      ? "Page metrics sent"
      : result.error || `Backend returned ${response.status}`;
    await chrome.storage.local.set({ lastPageMetricsStatus: status });
    return response.ok
      ? { ok: true }
      : { ok: false, error: status };
  } catch (error) {
    const status =
      error instanceof Error ? error.message : "Local backend unavailable";
    await chrome.storage.local.set({ lastPageMetricsStatus: status });
    return { ok: false, error: status };
  }
}

async function scanOpenTabs() {
  const { consent, token } = await chrome.storage.local.get(["consent", "token"]);
  if (consent !== "enabled" || !token) {
    throw new Error("Enable browser discovery and pair the extension first.");
  }

  const statusResponse = await fetch(`${API_BASE}/status`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const status = await statusResponse.json();
  if (!statusResponse.ok) {
    throw new Error(status.error || `Backend returned HTTP ${statusResponse.status}.`);
  }
  if (status.mode !== "enabled") {
    throw new Error("Enable discovery in the SDP dashboard before scanning tabs.");
  }

  const tabs = await chrome.tabs.query({});
  if (tabs.length > MAX_OPEN_TABS) {
    throw new Error(
      `This browser has ${tabs.length} tabs; the safe scan limit is ${MAX_OPEN_TABS}.`,
    );
  }
  const origins = [];
  for (const tab of tabs) {
    if (typeof tab.url !== "string") {
      continue;
    }
    try {
      const pageUrl = new URL(tab.url);
      if (
        ["http:", "https:"].includes(pageUrl.protocol) &&
        !pageUrl.username &&
        !pageUrl.password &&
        pageUrl.hostname
      ) {
        origins.push(pageUrl.origin);
      }
    } catch {
      continue;
    }
  }

  const response = await fetch(`${API_BASE}/open-tabs`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ origins }),
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.error || `Backend returned HTTP ${response.status}.`);
  }
  const scanLabel =
    `${result.website_count} website(s) · ` +
    new Date(result.scanned_at).toLocaleString();
  await chrome.storage.local.set({ lastOpenTabsScan: scanLabel });
  return {
    ok: true,
    tabCount: result.tab_count,
    websiteCount: result.website_count,
    skippedPrivate: result.skipped_private,
  };
}

chrome.permissions.onRemoved.addListener(({ origins = [] }) => {
  if (!origins.length) {
    return;
  }
  void (async () => {
    const { pageMetricsOrigins = [] } = await chrome.storage.local.get(
      "pageMetricsOrigins",
    );
    const stillPermitted = [];
    for (const origin of pageMetricsOrigins) {
      if (await chrome.permissions.contains({ origins: [`${origin}/*`] })) {
        stillPermitted.push(origin);
      }
    }
    await stopPageMetricsForOrigins(
      pageMetricsOrigins.filter((origin) => !stillPermitted.includes(origin)),
    );
    await chrome.storage.local.set({
      pageMetricsOrigins: stillPermitted,
      pageMetricsEnabled: stillPermitted.length > 0,
    });
    await updatePageMetricsScript(stillPermitted);
  })();
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "SDP_PAGE_METRICS_STARTED") {
    void trackPageMetricsTab(sender).catch((error) =>
      chrome.storage.local.set({
        lastPageMetricsStatus:
          error instanceof Error ? error.message : String(error),
      }),
    );
    return false;
  }
  if (message?.type === "SDP_SCAN_OPEN_TABS") {
    void scanOpenTabs().then(
      sendResponse,
      (error) => sendResponse({
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }),
    );
    return true;
  }
  if (message?.type === "SDP_PAGE_METRICS") {
    void submitPageMetrics(message.payload, sender).then(
      sendResponse,
      (error) => sendResponse({
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }),
    );
    return true;
  }
  if (message?.type === "SDP_ENABLE_PAGE_METRICS") {
    void enablePageMetrics(message.origins).then(
      (result) => sendResponse({ ok: true, ...result }),
      (error) => sendResponse({
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }),
    );
    return true;
  }
  if (message?.type === "SDP_DISABLE_PAGE_METRICS") {
    void disablePageMetrics().then(
      () => sendResponse({ ok: true }),
      (error) => sendResponse({
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }),
    );
    return true;
  }
  return false;
});
