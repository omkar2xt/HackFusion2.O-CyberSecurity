/**
 * SignalSafe Campus - Popup Controller
 * Developer 2 - Chrome Browser Extension
 * 
 * Complies with Manifest V3 and zero-surveillance design:
 * - Scans URLs only on explicit user interaction.
 * - Supports simulated demo scenarios and authoritative live backend integration.
 * - Communicates with POST /api/v1/scan/url, GET /api/v1/health, and POST /api/v1/incidents.
 * - Provides resilient timeout handling, actionable error diagnostics, and dynamic evidence rendering.
 */

// Application State
const state = {
  currentUrl: "",
  currentHost: "",
  currentProtocol: "https://",
  isScanning: false,
  lastScanResult: null,
  config: {
    mockMode: true,
    backendUrl: "http://127.0.0.1:8000",
    demoScenario: "auto" // 'auto', 'low_risk', 'suspicious', 'unknown', 'malicious'
  }
};

// DOM Elements
const elements = {
  badgeMode: document.getElementById("badgeMode"),
  urlDisplay: document.getElementById("urlDisplay"),
  urlProtocol: document.getElementById("urlProtocol"),
  urlHost: document.getElementById("urlHost"),
  btnRefreshUrl: document.getElementById("btnRefreshUrl"),
  btnScan: document.getElementById("btnScan"),
  btnScanText: document.getElementById("btnScanText"),

  scanningState: document.getElementById("scanningState"),
  scanProgressText: document.getElementById("scanProgressText"),
  scanProgressBar: document.getElementById("scanProgressBar"),

  errorState: document.getElementById("errorState"),
  errorTitle: document.getElementById("errorTitle"),
  errorMessage: document.getElementById("errorMessage"),
  btnRetryScan: document.getElementById("btnRetryScan"),

  resultSection: document.getElementById("resultSection"),
  demoDisclaimerBanner: document.getElementById("demoDisclaimerBanner"),
  verdictBox: document.getElementById("verdictBox"),
  verdictIconWrap: document.getElementById("verdictIconWrap"),
  verdictText: document.getElementById("verdictText"),
  verdictLevelTag: document.getElementById("verdictLevelTag"),
  scoreBox: document.getElementById("scoreBox"),
  riskScoreValue: document.getElementById("riskScoreValue"),
  scoreRingFill: document.getElementById("scoreRingFill"),
  metaScannedDomain: document.getElementById("metaScannedDomain"),
  metaScannedTime: document.getElementById("metaScannedTime"),
  indicatorCount: document.getElementById("indicatorCount"),
  indicatorsList: document.getElementById("indicatorsList"),
  recommendationsList: document.getElementById("recommendationsList"),

  btnOpenReport: document.getElementById("btnOpenReport"),
  reportModal: document.getElementById("reportModal"),
  btnCloseReport: document.getElementById("btnCloseReport"),
  btnCancelReport: document.getElementById("btnCancelReport"),
  incidentForm: document.getElementById("incidentForm"),
  reportTargetUrl: document.getElementById("reportTargetUrl"),
  reportCategory: document.getElementById("reportCategory"),
  reportSummary: document.getElementById("reportSummary"),
  reportNotes: document.getElementById("reportNotes"),
  btnSubmitReport: document.getElementById("btnSubmitReport"),
  btnSubmitReportText: document.getElementById("btnSubmitReportText"),
  incidentSuccessState: document.getElementById("incidentSuccessState"),
  incidentRefId: document.getElementById("incidentRefId"),
  btnCloseSuccessReport: document.getElementById("btnCloseSuccessReport"),

  btnSettings: document.getElementById("btnSettings"),
  settingsModal: document.getElementById("settingsModal"),
  btnCloseSettings: document.getElementById("btnCloseSettings"),
  chkMockMode: document.getElementById("chkMockMode"),
  selectDemoScenario: document.getElementById("selectDemoScenario"),
  inputBackendUrl: document.getElementById("inputBackendUrl"),
  btnSaveSettings: document.getElementById("btnSaveSettings")
};

// SVG Icon Helpers
const ICONS = {
  safe: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>`,
  suspicious: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  malicious: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
  unknown: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  check: `<svg class="recommendation-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`
};

// ==========================================================================
// Initialization & Configuration
// ==========================================================================
document.addEventListener("DOMContentLoaded", async () => {
  await loadConfiguration();
  await detectActiveTabUrl();
  bindEvents();
});

async function loadConfiguration() {
  try {
    const data = await chrome.storage.local.get(["mockMode", "backendUrl", "demoScenario"]);
    if (data.mockMode !== undefined) state.config.mockMode = data.mockMode;
    if (data.backendUrl) state.config.backendUrl = data.backendUrl;
    if (data.demoScenario) state.config.demoScenario = data.demoScenario;
  } catch (err) {
    console.warn("[SignalSafe] Could not read chrome.storage, using defaults:", err);
  }

  await checkBackendConnectivity();
}

/**
 * Validates connection with FastAPI health endpoint when Mock Mode is disabled.
 */
async function checkBackendConnectivity() {
  if (state.config.mockMode) {
    updateModeBadge("SIMULATED_DEMO");
    return;
  }

  const endpoint = `${state.config.backendUrl.replace(/\/$/, "")}/api/v1/health`;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2500);
    const resp = await fetch(endpoint, { method: "GET", signal: controller.signal });
    clearTimeout(timeoutId);

    if (resp.ok) {
      updateModeBadge("LIVE_BACKEND");
    } else {
      updateModeBadge("BACKEND_OFFLINE");
    }
  } catch {
    updateModeBadge("BACKEND_OFFLINE");
  }
}

/**
 * Updates UI badge according to required connection states:
 * - LIVE BACKEND (Connected)
 * - BACKEND OFFLINE (Cannot connect)
 * - SIMULATED DEMO (Mock Mode enabled)
 * - PARTIAL ANALYSIS (Some providers unavailable)
 */
function updateModeBadge(modeOverride) {
  const mode = modeOverride || (state.config.mockMode ? "SIMULATED_DEMO" : "LIVE_BACKEND");

  switch (mode) {
    case "SIMULATED_DEMO":
      elements.badgeMode.textContent = "SIMULATED DEMO";
      elements.badgeMode.className = "badge-pill badge-mock";
      elements.badgeMode.title = "Mock Mode enabled. Presenting simulated threat scenarios.";
      break;

    case "BACKEND_OFFLINE":
      elements.badgeMode.textContent = "BACKEND OFFLINE";
      elements.badgeMode.className = "badge-pill badge-offline";
      elements.badgeMode.title = `Cannot reach backend at ${state.config.backendUrl}. Verify FastAPI server is running.`;
      break;

    case "PARTIAL_ANALYSIS":
      elements.badgeMode.textContent = "PARTIAL ANALYSIS";
      elements.badgeMode.className = "badge-pill badge-partial";
      elements.badgeMode.title = "Analysis completed with partial threat intelligence provider reachability.";
      break;

    case "LIVE_BACKEND":
    default:
      elements.badgeMode.textContent = "LIVE BACKEND";
      elements.badgeMode.className = "badge-pill badge-live";
      elements.badgeMode.title = `Connected to ${state.config.backendUrl}`;
      break;
  }
}

// ==========================================================================
// Tab & URL Resolution
// ==========================================================================
async function detectActiveTabUrl() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs || tabs.length === 0 || !tabs[0].url) {
      setFallbackUrl("No active tab detected");
      return;
    }

    const tabUrl = tabs[0].url;
    parseAndDisplayUrl(tabUrl);
  } catch (err) {
    console.warn("[SignalSafe] Error accessing active tab:", err);
    setFallbackUrl("example.com");
  }
}

function parseAndDisplayUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);

    // Invalidate stale previous scan results if navigating to a different URL
    if (state.currentUrl && state.currentUrl !== rawUrl) {
      state.lastScanResult = null;
      elements.resultSection.classList.add("hidden");
      hideError();
    }

    if (parsed.protocol.startsWith("chrome") || parsed.protocol.startsWith("about")) {
      state.currentUrl = rawUrl;
      state.currentHost = parsed.hostname || "Browser Internal Page";
      state.currentProtocol = parsed.protocol + "//";
      elements.urlProtocol.textContent = state.currentProtocol;
      elements.urlHost.textContent = state.currentHost;
      return;
    }

    state.currentUrl = rawUrl;
    state.currentHost = parsed.hostname;
    state.currentProtocol = parsed.protocol + "//";

    elements.urlProtocol.textContent = state.currentProtocol;
    elements.urlHost.textContent = parsed.hostname + (parsed.pathname !== "/" ? parsed.pathname : "");
    elements.urlDisplay.title = rawUrl;
  } catch {
    state.currentUrl = rawUrl;
    state.currentHost = rawUrl;
    state.currentProtocol = "";
    elements.urlProtocol.textContent = "";
    elements.urlHost.textContent = rawUrl;
  }
}

function setFallbackUrl(displayMsg) {
  state.currentUrl = "https://example.com";
  state.currentHost = "example.com";
  state.currentProtocol = "https://";
  elements.urlProtocol.textContent = "https://";
  elements.urlHost.textContent = displayMsg;
}

// ==========================================================================
// Event Bindings
// ==========================================================================
function bindEvents() {
  // Scan button & Retry button
  elements.btnScan.addEventListener("click", () => handleInitiateScan());
  elements.btnRetryScan.addEventListener("click", () => handleInitiateScan());

  // URL refresh & click to copy
  elements.btnRefreshUrl.addEventListener("click", async () => {
    await detectActiveTabUrl();
    flashUrlRefresh();
  });

  elements.urlDisplay.addEventListener("click", () => {
    if (state.currentUrl) {
      navigator.clipboard.writeText(state.currentUrl);
      flashCopiedNotice();
    }
  });

  // Report modal flow
  elements.btnOpenReport.addEventListener("click", () => openReportModal());
  elements.btnCloseReport.addEventListener("click", () => closeReportModal());
  elements.btnCancelReport.addEventListener("click", () => closeReportModal());
  elements.incidentForm.addEventListener("submit", (e) => handleSubmitIncident(e));
  elements.btnCloseSuccessReport.addEventListener("click", () => closeReportModal());

  // Settings modal flow
  elements.btnSettings.addEventListener("click", () => openSettingsModal());
  elements.btnCloseSettings.addEventListener("click", () => closeSettingsModal());
  elements.btnSaveSettings.addEventListener("click", () => handleSaveSettings());
}

function flashUrlRefresh() {
  elements.btnRefreshUrl.style.transform = "rotate(180deg)";
  setTimeout(() => {
    elements.btnRefreshUrl.style.transform = "none";
  }, 300);
}

function flashCopiedNotice() {
  const originalHost = elements.urlHost.textContent;
  elements.urlHost.textContent = "Copied to clipboard!";
  setTimeout(() => {
    elements.urlHost.textContent = originalHost;
  }, 1200);
}

// ==========================================================================
// Scanning Flow
// ==========================================================================
async function handleInitiateScan() {
  if (state.isScanning) return;

  // Validate URL scheme
  if (!state.currentUrl || state.currentUrl.startsWith("chrome") || state.currentUrl.startsWith("about")) {
    showError("Unsupported Target", "SignalSafe can only scan public web addresses (HTTP/HTTPS), not internal browser pages.");
    return;
  }

  setScanningUIState(true);
  hideError();
  elements.resultSection.classList.add("hidden");
  state.lastScanResult = null;

  try {
    let result;
    if (state.config.mockMode) {
      result = await executeSimulatedScan(state.currentUrl);
    } else {
      result = await executeBackendScan(state.currentUrl);
    }

    state.lastScanResult = result;
    renderScanResult(result);
  } catch (err) {
    console.error("[SignalSafe] Scan execution failed:", err);
    showError("Scan Connection Error", err.message || "Failed to complete threat analysis. Verify network connectivity.");
  } finally {
    setScanningUIState(false);
  }
}

function setScanningUIState(isScanning) {
  state.isScanning = isScanning;
  if (isScanning) {
    elements.btnScan.disabled = true;
    elements.btnScanText.textContent = "Scanning in Progress...";
    elements.scanningState.classList.remove("hidden");
    
    // Simulate step progress text
    const steps = [
      "Analyzing domain heuristics...",
      "Cross-referencing threat telemetry...",
      "Evaluating certificate & redirect chain...",
      "Synthesizing authoritative verdict..."
    ];
    let stepIndex = 0;
    const interval = setInterval(() => {
      stepIndex++;
      if (stepIndex < steps.length && state.isScanning) {
        elements.scanProgressText.textContent = steps[stepIndex];
      } else {
        clearInterval(interval);
      }
    }, 450);
  } else {
    elements.btnScan.disabled = false;
    elements.btnScanText.textContent = "Scan Current Website";
    elements.scanningState.classList.add("hidden");
  }
}

// ==========================================================================
// Mock Scanner Logic & Scenarios (Active ONLY when Mock Mode is ON)
// ==========================================================================
function calculateStringEntropy(str) {
  if (!str) return 0;
  const counts = {};
  for (const ch of str.toLowerCase()) {
    counts[ch] = (counts[ch] || 0) + 1;
  }
  const len = str.length;
  let ent = 0;
  for (const k in counts) {
    const p = counts[k] / len;
    ent -= p * Math.log2(p);
  }
  return ent;
}

function calculateDynamicDomainScore(domain, minScore = 20, maxScore = 55) {
  if (!domain) return 30;
  const ent = calculateStringEntropy(domain);
  const len = domain.length;
  const dots = (domain.match(/\./g) || []).length;
  const hyphens = (domain.match(/-/g) || []).length;
  const digits = (domain.match(/\d/g) || []).length;
  
  const raw = Math.round(ent * 7 + len * 0.4 + dots * 3 + hyphens * 4 + digits * 2);
  return Math.max(minScore, Math.min(maxScore, raw));
}

async function executeSimulatedScan(url) {
  await new Promise((resolve) => setTimeout(resolve, 900));

  let scenario = state.config.demoScenario;
  if (scenario === "auto") {
    scenario = detectScenarioFromUrl(url);
  }

  const hostname = extractHostname(url);
  const nowIso = new Date().toISOString();

  switch (scenario) {
    case "low_risk": {
      const dynamicLow = Math.max(5, Math.min(15, 6 + Math.round(calculateStringEntropy(hostname) * 1.5)));
      return {
        scan_id: generateUuid(),
        target_url: url,
        hostname: hostname,
        verdict: "LOW_RISK",
        risk_level: "LOW",
        risk_score: dynamicLow,
        is_mock: true,
        checked_at: nowIso,
        indicators: [
          {
            code: "ind-tls-01",
            label: "High-Assurance TLS Certificate",
            severity: "LOW",
            detail: "Cryptographic identity verified by recognized public root certificate authority."
          },
          {
            code: "ind-reput-02",
            label: "Clean Threat Intel Baseline",
            severity: "LOW",
            detail: "Target destination has no historical records in campus or commercial blocklists."
          },
          {
            code: "ind-intel-03",
            label: "Benign Structural Heuristics",
            severity: "LOW",
            detail: "Clean lexical profile with zero userinfo credential obfuscation."
          }
        ],
        recommendations: [
          "Safe for standard campus browsing and reference access.",
          "Apply standard credential safety: never reuse campus passwords on third-party sites."
        ]
      };
    }

    case "suspicious":
      return {
        scan_id: generateUuid(),
        target_url: url,
        hostname: hostname,
        verdict: "SUSPICIOUS",
        risk_level: "HIGH",
        risk_score: 68,
        is_mock: true,
        checked_at: nowIso,
        indicators: [
          {
            code: "ind-entropy-01",
            label: "High Character Entropy & Lookalike Domain",
            severity: "HIGH",
            detail: "Hostname structure closely mimics institutional portal terminology with elevated character entropy."
          },
          {
            code: "ind-keyword-02",
            label: "Urgent Credential Lure Detected",
            severity: "MEDIUM",
            detail: "Destination URL contains sensitive account-verification tokens typical of phishing campaigns."
          }
        ],
        recommendations: [
          "Do NOT enter your student or staff login credentials on this website.",
          "Verify the legitimate destination independently through official university portals."
        ]
      };

    case "malicious":
      return {
        scan_id: generateUuid(),
        target_url: url,
        hostname: hostname,
        verdict: "MALICIOUS",
        risk_level: "CRITICAL",
        risk_score: 95,
        is_mock: true,
        checked_at: nowIso,
        indicators: [
          {
            code: "ind-phish-kit-01",
            label: "Active Credential Harvester",
            severity: "CRITICAL",
            detail: "Signature matches verified campus phishing kit targeting institutional SSO credentials."
          },
          {
            code: "ind-blacklist-02",
            label: "Universal Threat Intelligence Consensus",
            severity: "CRITICAL",
            detail: "Identified as malicious across multiple commercial threat feeds and campus blocklists."
          }
        ],
        recommendations: [
          "LEAVE this website immediately. Do not interact with any page elements.",
          "If credentials were submitted, change your campus password immediately via official IT channels."
        ]
      };

    case "unknown":
    default: {
      const dynamicUnknownScore = calculateDynamicDomainScore(hostname, 22, 58);
      return {
        scan_id: generateUuid(),
        target_url: url,
        hostname: hostname,
        verdict: "UNKNOWN",
        risk_level: "UNKNOWN",
        risk_score: dynamicUnknownScore,
        is_mock: true,
        checked_at: nowIso,
        indicators: [
          {
            code: "ind-telemetry-01",
            label: "Unindexed Telemetry Baseline",
            severity: "UNKNOWN",
            detail: `Domain '${hostname}' lacks historical campus telemetry. Entropy baseline: ${calculateStringEntropy(hostname).toFixed(2)}.`
          },
          {
            code: "ind-categorization-02",
            label: "Uncategorized Third-Party Web Host",
            severity: "UNKNOWN",
            detail: "Domain is neither explicitly whitelisted nor listed in active abuse catalogs."
          }
        ],
        recommendations: [
          "Exercise vigilance and inspect page links carefully before proceeding.",
          "Verify destination legitimacy independently prior to entering sensitive personal data."
        ]
      };
    }
  }
}

function detectScenarioFromUrl(url) {
  const lower = url.toLowerCase();

  if (
    lower.includes("example.com") ||
    lower.includes(".edu") ||
    lower.includes("google.com") ||
    lower.includes("github.com") ||
    lower.includes("wikipedia.org")
  ) {
    return "low_risk";
  }

  if (
    lower.includes("anikoto.cz") ||
    lower.includes("phish") ||
    lower.includes("secure-login") ||
    lower.includes("verify-account") ||
    lower.includes("account-update") ||
    lower.includes("suspicious")
  ) {
    return "suspicious";
  }

  if (lower.includes("malicious") || lower.includes("malware") || lower.includes("evil.com")) {
    return "malicious";
  }

  return "unknown";
}

function extractHostname(rawUrl) {
  try {
    return new URL(rawUrl).hostname;
  } catch {
    return rawUrl;
  }
}

function generateUuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

// ==========================================================================
// Live Backend API Scanner
// ==========================================================================
async function executeBackendScan(url) {
  const endpoint = `${state.config.backendUrl.replace(/\/$/, "")}/api/v1/scan/url`;
  const timeoutMs = 10000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: url }),
      signal: controller.signal
    });
  } catch (netErr) {
    clearTimeout(timeoutId);
    updateModeBadge("BACKEND_OFFLINE");
    if (netErr.name === "AbortError") {
      throw new Error(`Connection timed out after ${timeoutMs / 1000}s while contacting ${state.config.backendUrl}. The threat intelligence lookup may have stalled.`);
    }
    throw new Error(`Cannot connect to FastAPI backend at ${state.config.backendUrl}. Ensure the server is running (e.g., uvicorn backend.app.main:app --host 127.0.0.1 --port 8000).`);
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    let errorDetail = `Backend HTTP error ${response.status}`;
    try {
      const errJson = await response.json();
      if (errJson.error && errJson.error.message) {
        errorDetail = errJson.error.message;
      } else if (errJson.detail) {
        errorDetail = typeof errJson.detail === "string" ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {}
    throw new Error(errorDetail);
  }

  const data = await response.json();
  const indicators = data.indicators || [];

  // Detect whether analysis is partial due to unconfigured / offline providers
  const hasOfflineProvider = indicators.some(
    (ind) =>
      (ind.code && (ind.code.startsWith("TI_OFFLINE") || ind.code.startsWith("TI_DEGRADED"))) ||
      (ind.label && ind.label.toLowerCase().includes("offline"))
  );

  if (hasOfflineProvider) {
    updateModeBadge("PARTIAL_ANALYSIS");
  } else {
    updateModeBadge("LIVE_BACKEND");
  }

  return {
    scan_id: data.scan_id || generateUuid(),
    target_url: url,
    hostname: extractHostname(url),
    verdict: data.verdict || "UNKNOWN",
    risk_level: data.risk_level || "UNKNOWN",
    risk_score: typeof data.risk_score === "number" ? data.risk_score : 0,
    is_mock: false, // Authoritative live backend response
    checked_at: data.checked_at || new Date().toISOString(),
    indicators: indicators,
    recommendations: data.recommendations || []
  };
}

// ==========================================================================
// Render Scan Result View
// ==========================================================================
function renderScanResult(result) {
  // Demo disclaimer banner - visible ONLY for simulated demo scans
  if (result.is_mock || state.config.mockMode) {
    elements.demoDisclaimerBanner.classList.remove("hidden");
  } else {
    elements.demoDisclaimerBanner.classList.add("hidden");
  }

  // Normalise verdict string
  const verdictRaw = (result.verdict || "UNKNOWN").toUpperCase();
  let verdictStyle = "verdict-unknown";
  let verdictLabel = "UNKNOWN";
  let iconHtml = ICONS.unknown;

  if (verdictRaw === "LOW_RISK" || verdictRaw === "SAFE") {
    verdictStyle = "verdict-safe";
    verdictLabel = "SAFE";
    iconHtml = ICONS.safe;
  } else if (verdictRaw === "SUSPICIOUS") {
    verdictStyle = "verdict-suspicious";
    verdictLabel = "SUSPICIOUS";
    iconHtml = ICONS.suspicious;
  } else if (verdictRaw === "MALICIOUS") {
    verdictStyle = "verdict-malicious";
    verdictLabel = "MALICIOUS";
    iconHtml = ICONS.malicious;
  }

  // Update Verdict Box
  elements.verdictBox.className = `verdict-box ${verdictStyle}`;
  elements.verdictIconWrap.innerHTML = iconHtml;
  elements.verdictText.textContent = verdictLabel;
  elements.verdictLevelTag.textContent = `${(result.risk_level || "EVALUATED").toUpperCase()} RISK LEVEL`;

  // Update Risk Score Ring
  const score = Math.max(0, Math.min(100, Math.round(result.risk_score || 0)));
  elements.riskScoreValue.textContent = score;
  elements.scoreBox.className = `score-box ${verdictStyle}`;
  
  // SVG ring stroke-dasharray (circumference = 100)
  elements.scoreRingFill.setAttribute("stroke-dasharray", `${score}, 100`);

  // Meta info
  elements.metaScannedDomain.textContent = result.hostname || extractHostname(result.target_url);
  elements.metaScannedDomain.title = result.target_url;
  elements.metaScannedTime.textContent = formatTimestamp(result.checked_at);

  // Render Threat Indicators
  elements.indicatorsList.innerHTML = "";
  const indicators = result.indicators || [];
  elements.indicatorCount.textContent = indicators.length;

  if (indicators.length === 0) {
    elements.indicatorsList.innerHTML = `
      <div class="indicator-card">
        <div class="indicator-desc">No abnormal threat indicators detected for this domain.</div>
      </div>
    `;
  } else {
    indicators.forEach((ind) => {
      const card = document.createElement("div");
      card.className = "indicator-card";

      const name = ind.label || ind.name || ind.code || ind.indicator_id || "Threat Telemetry Flag";
      let sev = "low";
      if (ind.severity) {
        sev = ind.severity.toLowerCase();
      } else if (ind.evidence_type === "threat_intelligence") {
        sev = ind.code && ind.code.startsWith("TI_OFFLINE") ? "unknown" : "low";
      }
      const desc = ind.detail || ind.description || ind.rule_id || "";

      card.innerHTML = `
        <div class="indicator-top">
          <span class="indicator-name">${escapeHtml(name)}</span>
          <span class="severity-pill sev-${sev}">${sev}</span>
        </div>
        ${desc ? `<div class="indicator-desc">${escapeHtml(desc)}</div>` : ""}
      `;
      elements.indicatorsList.appendChild(card);
    });
  }

  // Render Recommendations
  elements.recommendationsList.innerHTML = "";
  const recs = result.recommendations || [];
  if (recs.length === 0) {
    elements.recommendationsList.innerHTML = `
      <li class="recommendation-item">
        ${ICONS.check}
        <span>Follow standard campus digital security protocols.</span>
      </li>
    `;
  } else {
    recs.forEach((rec) => {
      const li = document.createElement("li");
      li.className = "recommendation-item";
      li.innerHTML = `
        ${ICONS.check}
        <span>${escapeHtml(rec)}</span>
      `;
      elements.recommendationsList.appendChild(li);
    });
  }

  // Unhide Result Card
  elements.resultSection.classList.remove("hidden");
  elements.resultSection.scrollIntoView({ behavior: "smooth" });
}

function formatTimestamp(isoStr) {
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return "Just now";
  }
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// ==========================================================================
// Incident Reporting Flow
// ==========================================================================
function openReportModal() {
  elements.reportTargetUrl.value = state.currentUrl || "https://example.com";
  elements.reportSummary.value = "";
  elements.reportNotes.value = "";
  elements.incidentSuccessState.classList.add("hidden");
  elements.incidentForm.classList.remove("hidden");
  elements.reportModal.classList.remove("hidden");
}

function closeReportModal() {
  elements.reportModal.classList.add("hidden");
}

async function handleSubmitIncident(event) {
  event.preventDefault();
  
  const payload = {
    scan_id: state.lastScanResult ? state.lastScanResult.scan_id : null,
    category: elements.reportCategory.value,
    summary: elements.reportSummary.value.trim(),
    description: elements.reportNotes.value.trim() || undefined,
    evidence_refs: [state.currentUrl]
  };

  elements.btnSubmitReport.disabled = true;
  elements.btnSubmitReportText.textContent = "Transmitting...";

  try {
    let incidentId;
    if (state.config.mockMode) {
      await new Promise((resolve) => setTimeout(resolve, 800));
      incidentId = "INC-" + generateUuid().substring(0, 8).toUpperCase();
    } else {
      const endpoint = `${state.config.backendUrl.replace(/\/$/, "")}/api/v1/incidents`;
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      if (!response.ok) {
        let errMessage = `HTTP ${response.status}`;
        try {
          const errJson = await response.json();
          if (errJson.error && errJson.error.message) errMessage = errJson.error.message;
        } catch {}
        throw new Error(errMessage);
      }
      const data = await response.json();
      incidentId = data.incident_id || data.id || "INC-VERIFIED";
    }

    elements.incidentRefId.textContent = incidentId;
    elements.incidentForm.classList.add("hidden");
    elements.incidentSuccessState.classList.remove("hidden");
  } catch (err) {
    alert("Could not transmit incident report: " + err.message);
  } finally {
    elements.btnSubmitReport.disabled = false;
    elements.btnSubmitReportText.textContent = "Submit Security Report";
  }
}

// ==========================================================================
// Settings Drawer Flow
// ==========================================================================
function openSettingsModal() {
  elements.chkMockMode.checked = state.config.mockMode;
  elements.selectDemoScenario.value = state.config.demoScenario;
  elements.inputBackendUrl.value = state.config.backendUrl;
  elements.settingsModal.classList.remove("hidden");
}

function closeSettingsModal() {
  elements.settingsModal.classList.add("hidden");
}

async function handleSaveSettings() {
  const newMockMode = elements.chkMockMode.checked;
  const newScenario = elements.selectDemoScenario.value;
  const newBackendUrl = elements.inputBackendUrl.value.trim() || "http://127.0.0.1:8000";

  state.config.mockMode = newMockMode;
  state.config.demoScenario = newScenario;
  state.config.backendUrl = newBackendUrl;

  try {
    await chrome.storage.local.set({
      mockMode: newMockMode,
      demoScenario: newScenario,
      backendUrl: newBackendUrl
    });
  } catch (err) {
    console.warn("[SignalSafe] Could not save settings to storage:", err);
  }

  await checkBackendConnectivity();
  closeSettingsModal();
}

// ==========================================================================
// Error Banner Handling
// ==========================================================================
function showError(title, message) {
  elements.errorTitle.textContent = title;
  elements.errorMessage.textContent = message;
  elements.errorState.classList.remove("hidden");
}

function hideError() {
  elements.errorState.classList.add("hidden");
}
