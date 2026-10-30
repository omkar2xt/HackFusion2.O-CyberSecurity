/**
 * SignalSafe Campus - Background Service Worker (Manifest V3)
 * Developer 2 - Chrome Browser Extension
 * 
 * Note: Under Manifest V3 and zero-surveillance design:
 * - We do NOT track browsing history.
 * - We do NOT listen to all web requests.
 * - We do NOT automatically scan pages in the background.
 * - We only handle installation lifecycle and default configuration storage.
 */

// Initialize default extension configuration on install or update
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log("[SignalSafe Campus] Extension installed / updated:", details.reason);

  const existingConfig = await chrome.storage.local.get(["mockMode", "backendUrl", "demoScenario"]);
  
  const defaults = {
    mockMode: existingConfig.mockMode !== undefined ? existingConfig.mockMode : true,
    backendUrl: existingConfig.backendUrl || "http://127.0.0.1:8000",
    demoScenario: existingConfig.demoScenario || "auto" // 'auto', 'low_risk', 'suspicious', 'unknown'
  };

  await chrome.storage.local.set(defaults);
  console.log("[SignalSafe Campus] Config initialized:", defaults);
});
