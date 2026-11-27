const API_BASE = "http://127.0.0.1:5000/api/discovery";

const consentStatus = document.getElementById("consent-status");
const backendStatus = document.getElementById("backend-status");
const lastResult = document.getElementById("last-result");
const pairingCode = document.getElementById("pairing-code");
const message = document.getElementById("message");

async function getBackendStatus(token) {
  const response = await fetch(`${API_BASE}/status`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    throw new Error("Backend authentication failed.");
  }
  return response.json();
}

async function refreshStatus() {
  const { consent, token, lastDiscoveryStatus } =
    await chrome.storage.local.get(["consent", "token", "lastDiscoveryStatus"]);
  consentStatus.textContent = consent || "disabled";
  lastResult.textContent = lastDiscoveryStatus || "—";
  if (!token) {
    backendStatus.textContent = "Not paired";
    return;
  }
  try {
    const status = await getBackendStatus(token);
    backendStatus.textContent =
      status.mode === "enabled" ? "Connected · discovery enabled" :
      status.mode === "paused" ? "Connected · discovery paused" :
      "Connected · discovery disabled";
  } catch {
    backendStatus.textContent = "Not connected";
  }
}

async function setConsent(value) {
  await chrome.storage.local.set({ consent: value });
  message.textContent =
    value === "enabled" ? "Browser discovery enabled for this extension." :
    value === "paused" ? "Browser discovery paused." :
    "Browser discovery disabled.";
  await refreshStatus();
}

document.getElementById("enable").addEventListener("click", () => setConsent("enabled"));
document.getElementById("pause").addEventListener("click", () => setConsent("paused"));
document.getElementById("disable").addEventListener("click", () => setConsent("disabled"));

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
