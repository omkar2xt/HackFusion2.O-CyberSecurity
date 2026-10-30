# SignalSafe Campus — Chrome Browser Extension (Developer 2)

**SignalSafe Campus** is an AI-assisted threat radar and incident reporting browser extension for students, faculty, and campus staff. It enables real-time verification of URLs, phishing prevention, and direct incident escalation to Campus Security Operations (SecOps).

---

## 🛡️ Architecture & Key Features

* **Manifest V3 Compliant**: Built strictly adhering to Chrome Extension Manifest V3 specifications.
* **Zero-Surveillance Design**:
  * Does **NOT** record or track browsing history.
  * Does **NOT** continuously scan web requests or tabs in the background.
  * Captures the active tab URL **only** when the user explicitly clicks the Scan button.
* **Dynamic Simulated Demo Scenarios**:
  * **LOW RISK / SAFE**: `https://example.com` (also `.edu`, `google.com`, etc.)
  * **SUSPICIOUS**: `https://anikoto.cz` (also URLs containing `phish`, `secure-login`, etc.)
  * **UNKNOWN**: Unconfigured domains (fallback for arbitrary external websites)
  * **MALICIOUS**: Explicit flag / `malicious-test.com` for critical demonstrations
* **Ready for Live Backend Integration**:
  * `POST /api/v1/scan/url`
  * `POST /api/v1/incidents`
  * Clean toggle between **Mock Mode (Simulated Demos)** and **Live Backend Mode**.
* **Modern Cybersecurity Visual Design**:
  * Dark navy (`#070813`) and deep purple (`#120e29`, `#7c3aed`) theme.
  * Frosted glass containers, subtle purple hairline borders, and neon accent glows.
  * Circular score meter and interactive incident reporting modal.

---

## 📂 File Structure

```text
browser-extension/
├── manifest.json       # Manifest V3 extension configuration
├── popup.html          # Extension popup user interface
├── popup.css           # Premium dark cyber design styling
├── popup.js            # Active tab URL capture, mock scenarios, backend API client
├── background.js       # Lightweight service worker for config initialization
├── README.md           # Documentation and testing guide
└── assets/
    ├── icon16.png      # 16x16 icon
    ├── icon48.png      # 48x48 icon
    └── icon128.png     # 128x128 icon
```

---

## 🚀 How to Load and Test the Extension in Google Chrome

1. **Open Chrome Extensions Manager**:
   * In Google Chrome, open a new tab and navigate to: `chrome://extensions/`
   * Or click the three dots menu (⋮) -> **Extensions** -> **Manage Extensions**.

2. **Enable Developer Mode**:
   * In the top-right corner of the Extensions page, toggle the **Developer mode** switch **ON**.

3. **Load the Unpacked Extension**:
   * Click the **Load unpacked** button in the top-left corner.
   * Select the folder:
     `d:\work\hack2.0\HackFusion2.O-CyberSecurity\browser-extension`
   * The extension will appear with the shield icon and the title **SignalSafe Campus - Phishing & Threat Scanner**.

4. **Pin the Extension**:
   * Click the puzzle icon (Extensions) on Chrome's toolbar and pin **SignalSafe Campus** for instant one-click access.

---

## 🧪 Testing the 3 Demo Scenarios

Make sure **Mock Mode** is active (default).

### Scenario 1: LOW RISK (Safe)
1. In Chrome, open a tab to `https://example.com` (or any university `.edu` site).
2. Click the SignalSafe Campus extension icon.
3. Observe the active target URL: `https://example.com`.
4. Click **Scan Current Website**.
5. **Expected Output**:
   * Verdict: **SAFE** (Green badge & glow)
   * Risk Score: **8 / 100** (Low Risk Level)
   * Banner: **SIMULATED DEMO RESULT**
   * Threat Indicators: Trusted TLS/SSL Certificate, Benign Domain Baseline, Zero Threat Intel Matches.
   * Recommendations: Safe for standard browsing; maintain standard password hygiene.

### Scenario 2: SUSPICIOUS (Warning)
1. In Chrome, open a tab to `https://anikoto.cz` (or navigate to any test page with `phish` in the URL).
2. Click the SignalSafe Campus extension icon.
3. Click **Scan Current Website**.
4. **Expected Output**:
   * Verdict: **SUSPICIOUS** (Amber/Yellow badge & warning glow)
   * Risk Score: **74 / 100** (High Risk Level)
   * Banner: **SIMULATED DEMO RESULT**
   * Threat Indicators: Lookalike Domain Heuristic, Anomalous Registrar Telemetry, Unverified Destination Route.
   * Recommendations: Do not enter SSO or campus credentials; report to SecOps.

### Scenario 3: UNKNOWN (Default Fallback)
1. In Chrome, open any general arbitrary site (e.g., `https://randomsite.xyz` or an intranet development link).
2. Click the SignalSafe Campus extension icon.
3. Click **Scan Current Website**.
4. **Expected Output**:
   * Verdict: **UNKNOWN** (Violet/Slate badge)
   * Risk Score: **45 / 100** (Unknown Risk Level)
   * Threat Indicators: Unindexed Telemetry Baseline, Uncategorized Third-Party Web Host.
   * Recommendations: Exercise vigilance and verify destination before submitting sensitive data.

> 💡 **Judge/Demo Tip**: You can also click the **Settings** (gear icon) in the top-right header to manually force any scenario (`Force LOW RISK`, `Force SUSPICIOUS`, `Force UNKNOWN`, or `Force MALICIOUS`) on any tab!

---

## 🚨 Testing Incident Reporting

1. After scanning a suspicious website, click **Report Suspicious Website**.
2. An in-popup modal appears pre-filled with the target URL and scan reference.
3. Select threat category (e.g. `Phishing / Credential Theft`), add a summary (e.g. `Suspicious login box mimicking university SSO`), and click **Submit Incident**.
4. You will see a success confirmation along with an Incident Reference ID (e.g., `INC-8F42D1A0`).

---

## 🔌 Connecting to Live FastAPI Backend

1. Start the SignalSafe Campus backend:
   ```bash
   uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
   ```
2. Click the **Settings** gear icon in the extension popup.
3. Toggle **Mock Mode (Simulated Demos)** to **OFF**.
4. Ensure the backend URL is set to `http://127.0.0.1:8000`.
5. Click **Save Configuration**. The header pill will now display **LIVE BACKEND**.
6. When you scan a URL, requests are sent directly to `POST /api/v1/scan/url` and incidents submit to `POST /api/v1/incidents`.
