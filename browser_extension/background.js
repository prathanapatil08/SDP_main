const API_BASE = "http://127.0.0.1:5000/api/discovery";
const DISCOVERY_COOLDOWN_MS = 60_000;
const MAX_RECENT_ORIGINS = 200;

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
