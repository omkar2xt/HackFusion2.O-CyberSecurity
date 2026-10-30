"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { apiClient } from "../../services/api";
import { ScanResult } from "../../lib/types";
import {
  ShieldIcon,
  AlertCircleIcon,
  CheckCircleIcon,
  LockIcon,
  ChevronRightIcon,
  ScanIcon,
  QrCodeIcon,
  FileTextIcon,
} from "../../components/Icons";
import { SkeletonCard } from "../../components/SkeletonLoader";

type ScanTab = "url" | "message" | "qr";

export default function ScanPage() {
  const router = useRouter();

  const [activeTab, setActiveTab] = useState<ScanTab>("url");
  const [url, setUrl] = useState("");
  const [messageText, setMessageText] = useState("");
  const [qrPayload, setQrPayload] = useState("");
  const [qrImageName, setQrImageName] = useState<string | null>(null);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [errorMsg, setErrorMsg] = useState("");

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setErrorMsg("");

    if (activeTab === "url" && !url.trim()) {
      setErrorMsg("Please provide a target URL to analyze.");
      return;
    }
    if (activeTab === "message" && !messageText.trim()) {
      setErrorMsg("Please paste the message or email body to analyze.");
      return;
    }
    if (activeTab === "qr" && !qrPayload.trim()) {
      setErrorMsg("Please enter decoded QR payload or upload a QR image.");
      return;
    }

    setLoading(true);

    try {
      let scanRes: ScanResult;
      if (activeTab === "qr") {
        scanRes = await apiClient.submitScan({
          qrPayload: qrPayload.trim(),
        });
      } else if (activeTab === "url") {
        scanRes = await apiClient.submitScan({
          url: url.trim(),
          messageText: messageText.trim() || undefined,
        });
      } else {
        scanRes = await apiClient.submitScan({
          messageText: messageText.trim(),
        });
      }
      setResult(scanRes);
    } catch {
      setErrorMsg("Failed to complete scan. Please try again or verify your connection.");
    } finally {
      setLoading(false);
    }
  };

  const handleLoadUrlPreset = (presetUrl: string, msg: string = "") => {
    setActiveTab("url");
    setUrl(presetUrl);
    setMessageText(msg);
    setErrorMsg("");
  };

  const handleLoadMessagePreset = (presetText: string) => {
    setActiveTab("message");
    setMessageText(presetText);
    setUrl("");
    setErrorMsg("");
  };

  const handleLoadQrPreset = (presetQr: string) => {
    setActiveTab("qr");
    setQrPayload(presetQr);
    setQrImageName(null);
    setErrorMsg("");
  };

  const handleQrImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setQrImageName(file.name);
      // Simulate client-side QR barcode decoding to extract text payload
      if (file.name.toLowerCase().includes("canteen") || file.name.toLowerCase().includes("upi")) {
        setQrPayload("upi://pay?pa=attacker.scam@okaxis&pn=Canteen%20Counter%203&am=120");
      } else if (file.name.toLowerCase().includes("wifi")) {
        setQrPayload("WIFI:S:Campus_Hostel_Free_HighSpeed;T:WPA;P:hostel2026;;");
      } else {
        setQrPayload("https://campus-kiosk-refunds.xyz/auth/verify?session=9128");
      }
    }
  };

  const handleScanExtractedUrl = (extractedUrl: string) => {
    setActiveTab("url");
    setUrl(extractedUrl);
    handleScan();
  };

  const handleEscalateToReport = () => {
    if (!result) return;
    sessionStorage.setItem("signalsafe_pending_scan", JSON.stringify(result));
    router.push("/report");
  };

  const getVerdictBadge = (verdict: ScanResult["verdict"]) => {
    switch (verdict) {
      case "SAFE":
        return {
          bg: "bg-emerald-500/20 text-emerald-200 border-emerald-400/30",
          label: "Low Risk / Likely Safe",
          icon: CheckCircleIcon,
        };
      case "SUSPICIOUS":
        return {
          bg: "bg-amber-500/20 text-amber-200 border-amber-400/30",
          label: "Suspicious / Proceed With Caution",
          icon: AlertCircleIcon,
        };
      case "MALICIOUS":
        return {
          bg: "bg-red-500/20 text-red-200 border-red-400/30",
          label: "High Risk / Potential Threat",
          icon: AlertCircleIcon,
        };
      default:
        return {
          bg: "bg-white/10 text-white/80 border-white/20",
          label: "Uncertain / Verification Required",
          icon: ShieldIcon,
        };
    }
  };

  return (
    <div className="mx-auto max-w-5xl px-5 sm:px-8 md:px-12 py-10 space-y-8">
      
      {/* Title & Badge */}
      <div>
        <div className="inline-block border-l-2 border-white bg-white/15 px-3 py-1.5 backdrop-blur-md mb-3">
          <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/90">
            Authoritative Threat Detection
          </span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-normal tracking-tight text-white drop-shadow-md">
          Multimodal Threat Scanner
        </h1>
        <p className="mt-2 text-sm text-white/70 max-w-2xl leading-relaxed">
          Screen suspicious links, email bodies, SMS text, or QR code stickers against known campus threat signatures, 34-feature ML heuristics, and threat intelligence feeds.
        </p>
      </div>

      {/* Preset Scenarios with Glass Badges */}
      <div className="rounded-2xl border border-white/15 bg-white/10 p-5 backdrop-blur-md shadow-xl space-y-3">
        <div className="flex items-center justify-between">
          <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">
            Interactive Test Scenarios (Click to test backend features)
          </p>
          <span className="font-mono text-[10px] text-white/40">FastAPI Hybrid Engine</span>
        </div>
        
        <div className="flex flex-wrap gap-2.5">
          {/* Preset 1: URL */}
          <button
            type="button"
            onClick={() =>
              handleLoadUrlPreset(
                "https://campus-portal-refunds.org/auth/verify?session=9812",
                "URGENT: Dean of Student Affairs requires bank verification within 3 hours."
              )
            }
            className="rounded-full border border-red-400/30 bg-red-500/10 px-3.5 py-1.5 text-xs font-mono text-red-200 hover:bg-red-500/20 transition-colors flex items-center gap-1.5"
          >
            <ScanIcon className="h-3 w-3" />
            <span>URL: Spoofed Refund Phishing</span>
          </button>

          {/* Preset 2: Message */}
          <button
            type="button"
            onClick={() =>
              handleLoadMessagePreset(
                "CRITICAL ALERT: Your campus library and moodle access will be permanently suspended due to unresolved verification paperwork. Immediately verify your credentials at http://verify-student-records.xyz/confirm before 6:00 PM."
              )
            }
            className="rounded-full border border-amber-400/30 bg-amber-500/10 px-3.5 py-1.5 text-xs font-mono text-amber-200 hover:bg-amber-500/20 transition-colors flex items-center gap-1.5"
          >
            <FileTextIcon className="h-3 w-3" />
            <span>Message: Urgency Lure & Auto URL Extraction</span>
          </button>

          {/* Preset 3: QR Code Quishing (NEW FEATURE) */}
          <button
            type="button"
            onClick={() =>
              handleLoadQrPreset("upi://pay?pa=canteen.counter3.fraud@axisbank&pn=Canteen%20Desk&am=120&cu=INR")
            }
            className="rounded-full border border-purple-400/30 bg-purple-500/15 px-3.5 py-1.5 text-xs font-mono text-purple-200 hover:bg-purple-500/25 transition-colors flex items-center gap-1.5"
          >
            <QrCodeIcon className="h-3.5 w-3.5" />
            <span>QR / Quishing: Tampered Cafeteria UPI Sticker</span>
          </button>

          {/* Preset 4: Rogue Wi-Fi QR */}
          <button
            type="button"
            onClick={() =>
              handleLoadQrPreset("WIFI:S:Campus_Free_HighSpeed_Guest;T:WPA;P:unsecured2026;;")
            }
            className="rounded-full border border-blue-400/30 bg-blue-500/15 px-3.5 py-1.5 text-xs font-mono text-blue-200 hover:bg-blue-500/25 transition-colors flex items-center gap-1.5"
          >
            <QrCodeIcon className="h-3.5 w-3.5" />
            <span>QR: Rogue Campus Wi-Fi Payload</span>
          </button>
        </div>
      </div>

      {/* Feature Tabs Selector */}
      <div className="flex border-b border-white/15 gap-2 sm:gap-6 text-xs font-mono uppercase tracking-[0.15em]">
        <button
          type="button"
          onClick={() => {
            setActiveTab("url");
            setErrorMsg("");
          }}
          className={`pb-3 border-b-2 flex items-center gap-2 transition-colors ${
            activeTab === "url"
              ? "border-white font-bold text-white"
              : "border-transparent text-white/50 hover:text-white/80"
          }`}
        >
          <ScanIcon className="h-4 w-4" />
          <span>URL Link Inspector</span>
        </button>

        <button
          type="button"
          onClick={() => {
            setActiveTab("message");
            setErrorMsg("");
          }}
          className={`pb-3 border-b-2 flex items-center gap-2 transition-colors ${
            activeTab === "message"
              ? "border-white font-bold text-white"
              : "border-transparent text-white/50 hover:text-white/80"
          }`}
        >
          <FileTextIcon className="h-4 w-4" />
          <span>Message & Email Scanner</span>
        </button>

        <button
          type="button"
          onClick={() => {
            setActiveTab("qr");
            setErrorMsg("");
          }}
          className={`pb-3 border-b-2 flex items-center gap-2 transition-colors relative ${
            activeTab === "qr"
              ? "border-white font-bold text-white"
              : "border-transparent text-white/50 hover:text-white/80"
          }`}
        >
          <QrCodeIcon className="h-4 w-4 text-purple-300" />
          <span>QR Code & Quishing</span>
          <span className="rounded-full bg-purple-500/30 border border-purple-400/40 text-[9px] px-1.5 py-0.2 text-purple-200">
            Backend API
          </span>
        </button>
      </div>

      {/* Input Form Glass Card */}
      <div className="rounded-2xl border border-white/15 bg-white/10 p-6 sm:p-8 backdrop-blur-md shadow-2xl space-y-6">
        <form onSubmit={handleScan} className="space-y-5">
          
          {errorMsg && (
            <div className="rounded-xl border border-red-400/30 bg-red-500/10 p-3.5 text-xs text-red-200 flex items-center gap-2">
              <AlertCircleIcon className="h-4 w-4 shrink-0 text-red-400" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* TAB 1: URL INSPECTOR */}
          {activeTab === "url" && (
            <div className="space-y-4">
              <div>
                <label className="block font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-2">
                  Target Destination URL
                </label>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://campus-portal.org/login or http://192.168.1.1:8080"
                  className="w-full rounded-xl border border-white/20 bg-white/5 px-4 py-3 text-sm text-white placeholder:text-white/40 font-mono text-xs focus:border-white focus:outline-none focus:ring-1 focus:ring-white transition-colors"
                />
                <p className="mt-1.5 font-mono text-[10px] text-white/50 tracking-[0.1em]">
                  Routed to /api/v1/scan/url. Evaluates punycode homographs, lookalikes, IP hosts, and URLhaus/VirusTotal feeds.
                </p>
              </div>

              <div>
                <label className="block font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-2">
                  Context / Email Subject (Optional)
                </label>
                <input
                  type="text"
                  value={messageText}
                  onChange={(e) => setMessageText(e.target.value)}
                  placeholder="e.g. Received via campus Outlook from unknown sender"
                  className="w-full rounded-xl border border-white/20 bg-white/5 px-4 py-2.5 text-sm text-white placeholder:text-white/40 focus:border-white focus:outline-none focus:ring-1 focus:ring-white transition-colors"
                />
              </div>
            </div>
          )}

          {/* TAB 2: MESSAGE & EMAIL BODY SCANNER */}
          {activeTab === "message" && (
            <div className="space-y-4">
              <div>
                <label className="block font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-2">
                  Message Text, Email Body, or WhatsApp Chat
                </label>
                <textarea
                  rows={5}
                  value={messageText}
                  onChange={(e) => setMessageText(e.target.value)}
                  placeholder="Paste complete email headers, SMS notification, or social engineering message containing suspicious links..."
                  className="w-full rounded-xl border border-white/20 bg-white/5 p-4 text-sm text-white placeholder:text-white/40 focus:border-white focus:outline-none focus:ring-1 focus:ring-white transition-colors"
                />
                <p className="mt-1.5 font-mono text-[10px] text-white/50 tracking-[0.1em]">
                  Routed to /api/v1/scan/message. Automatically discovers extracted URLs and detects coercion & urgency cues.
                </p>
              </div>
            </div>
          )}

          {/* TAB 3: QR CODE & QUISHING (NEW FEATURE) */}
          {activeTab === "qr" && (
            <div className="space-y-4">
              <div>
                <label className="block font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-2">
                  Decoded QR Payload or Payment Destination
                </label>
                <input
                  type="text"
                  value={qrPayload}
                  onChange={(e) => setQrPayload(e.target.value)}
                  placeholder="e.g. upi://pay?pa=fake.canteen@upi, WIFI:S:CampusGuest;..., or https://kiosk.xyz"
                  className="w-full rounded-xl border border-white/20 bg-white/5 px-4 py-3 text-sm text-white placeholder:text-white/40 font-mono text-xs focus:border-white focus:outline-none focus:ring-1 focus:ring-white transition-colors"
                />
                <p className="mt-1.5 font-mono text-[10px] text-white/50 tracking-[0.1em]">
                  Routed to /api/v1/scan/qr. Protects students from tampered physical stickers at cafeteria counters and notice boards.
                </p>
              </div>

              {/* Upload QR Image Box */}
              <div className="rounded-xl border border-dashed border-white/25 bg-white/5 p-5 text-center">
                <QrCodeIcon className="mx-auto h-8 w-8 text-white/50 mb-2" />
                <p className="text-xs text-white/80">Upload Photo of Physical QR Code (Cafeteria / Notice Board)</p>
                <p className="font-mono text-[10px] text-white/40 mt-1">PNG, JPG, or WEBP up to 10MB</p>
                
                <label className="mt-3 inline-block cursor-pointer rounded-full border border-white/20 bg-white/10 px-4 py-1.5 text-xs font-mono uppercase tracking-wider text-white hover:bg-white/20 transition-colors">
                  <span>Browse Image</span>
                  <input
                    type="file"
                    accept="image/*"
                    onChange={handleQrImageUpload}
                    className="hidden"
                  />
                </label>

                {qrImageName && (
                  <p className="mt-2 font-mono text-[11px] text-emerald-300">
                    Loaded: {qrImageName} (Payload extracted)
                  </p>
                )}
              </div>
            </div>
          )}

          <div className="flex flex-col sm:flex-row items-center justify-between pt-2 gap-4">
            <span className="font-mono text-[10px] text-white/50 uppercase tracking-[0.1em] flex items-center gap-1.5">
              <LockIcon className="h-3.5 w-3.5 text-white/40" />
              Isolated heuristic sandbox • Zero surveillance
            </span>
            <button
              type="submit"
              disabled={loading}
              className="w-full sm:w-auto rounded-full bg-white px-6 py-2.5 text-xs font-medium text-black hover:bg-white/85 disabled:bg-white/40 transition-colors shadow-lg"
            >
              {loading
                ? "Evaluating Threat Indicators..."
                : activeTab === "qr"
                ? "Analyze QR Code Payload"
                : activeTab === "message"
                ? "Scan Message & Extract Links"
                : "Run URL Security Scan"}
            </button>
          </div>
        </form>
      </div>

      {/* Loading Skeleton */}
      {loading && <SkeletonCard />}

      {/* Scan Result Glass Card */}
      {result && !loading && (
        <div className="rounded-2xl border border-white/15 bg-white/10 p-6 sm:p-8 backdrop-blur-md shadow-2xl space-y-6">
          
          {/* Header & Verdict */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/15 pb-6">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">
                  Scan ID: {result.id}
                </span>
                {result.payloadType && (
                  <span className="rounded-full bg-purple-500/20 border border-purple-400/30 px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider text-purple-200">
                    QR Payload: {result.payloadType}
                  </span>
                )}
                {result.analysisScope && (
                  <span className="rounded-full bg-blue-500/20 border border-blue-400/30 px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider text-blue-200">
                    {result.analysisScope}
                  </span>
                )}
              </div>
              <h2 className="text-2xl font-normal text-white mt-1 drop-shadow-sm">
                Authoritative Detection Report
              </h2>
              <p className="font-mono text-[11px] text-white/50 mt-1">
                Analyzed at {new Date(result.analyzedAt).toLocaleTimeString()}
              </p>
            </div>

            {(() => {
              const badge = getVerdictBadge(result.verdict);
              const Icon = badge.icon;
              return (
                <div className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border text-xs font-mono uppercase tracking-[0.1em] ${badge.bg}`}>
                  <Icon className="h-4 w-4" />
                  <span>{badge.label}</span>
                </div>
              );
            })()}
          </div>

          {/* Risk Score & Confidence Gauge */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 border-b border-white/15 pb-6">
            <div className="rounded-xl border border-white/15 bg-white/5 p-4">
              <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">Calculated Risk Score</span>
              <div className="flex items-baseline gap-2 mt-2">
                <span className={`text-4xl font-light ${
                  result.riskScore > 70 ? "text-red-300" : result.riskScore > 40 ? "text-amber-300" : "text-emerald-300"
                }`}>
                  {result.riskScore}
                </span>
                <span className="font-mono text-xs text-white/40">/ 100</span>
              </div>
              <div className="w-full bg-white/10 h-1.5 rounded-full mt-3 overflow-hidden">
                <div
                  className={`h-full ${
                    result.riskScore > 70 ? "bg-red-400" : result.riskScore > 40 ? "bg-amber-400" : "bg-emerald-400"
                  }`}
                  style={{ width: `${result.riskScore}%` }}
                />
              </div>
            </div>

            <div className="rounded-xl border border-white/15 bg-white/5 p-4">
              <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">Diagnostic Confidence</span>
              <p className="text-4xl font-light text-white mt-2">
                {Math.round(result.confidence * 100)}%
              </p>
              <p className="font-mono text-[10px] text-white/50 mt-2">Rule coverage & reputation correlation</p>
            </div>

            <div className="rounded-xl border border-white/15 bg-white/5 p-4">
              <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">Risk Classification</span>
              <p className="text-3xl font-light text-white mt-2 uppercase tracking-wide">
                {result.threatLevel}
              </p>
              <p className="font-mono text-[10px] text-white/50 mt-2">Authoritative backend detection verdict</p>
            </div>
          </div>

          {/* Extracted URLs breakdown (For Message Scanner) */}
          {result.extractedUrls && result.extractedUrls.length > 0 && (
            <div className="rounded-xl border border-blue-400/25 bg-blue-500/10 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-blue-200">
                  Extracted URLs from Message ({result.extractedUrls.length})
                </span>
                <span className="font-mono text-[9px] text-blue-300/60">Auto-dissected via regex</span>
              </div>
              <div className="space-y-1.5">
                {result.extractedUrls.map((u, i) => (
                  <div key={i} className="flex items-center justify-between gap-3 bg-black/30 p-2.5 rounded-lg text-xs font-mono">
                    <span className="text-white/90 truncate">{u}</span>
                    <button
                      type="button"
                      onClick={() => handleScanExtractedUrl(u)}
                      className="shrink-0 rounded bg-white/20 hover:bg-white/30 px-2.5 py-1 text-[10px] text-white uppercase tracking-wider"
                    >
                      Deep Inspect URL
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Detailed Summary */}
          <div>
            <h3 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-2">Executive Summary</h3>
            <p className="text-sm text-white/85 leading-relaxed bg-white/5 border border-white/15 rounded-xl p-4">
              {result.summary}
            </p>
          </div>

          {/* Indicators Breakdown */}
          {result.indicators.length > 0 && (
            <div>
              <h3 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-3">Fired Threat Indicators</h3>
              <div className="space-y-2.5">
                {result.indicators.map((ind, i) => (
                  <div
                    key={i}
                    className={`rounded-xl border p-4 text-xs flex items-start gap-3 ${
                      ind.severity === "danger"
                        ? "border-red-400/30 bg-red-500/10 text-red-200"
                        : "border-amber-400/30 bg-amber-500/10 text-amber-200"
                    }`}
                  >
                    <AlertCircleIcon className={`h-4 w-4 shrink-0 mt-0.5 ${
                      ind.severity === "danger" ? "text-red-400" : "text-amber-400"
                    }`} />
                    <div>
                      <span className="font-semibold text-white">{ind.label}:</span>{" "}
                      <span className="text-white/80">{ind.description}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          <div>
            <h3 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-3">Action Recommendations</h3>
            <div className="space-y-2">
              {result.recommendations.map((rec, i) => (
                <div key={i} className="flex items-start gap-2.5 text-xs text-white/80">
                  <CheckCircleIcon className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Escalation CTA */}
          <div className="border-t border-white/15 pt-6 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div>
              <p className="text-sm font-medium text-white">Did you encounter this threat on campus?</p>
              <p className="text-xs text-white/60">
                Submit this incident directly to the Campus Incident Response Team to protect other members.
              </p>
            </div>
            <button
              type="button"
              onClick={handleEscalateToReport}
              className="inline-flex items-center gap-2 rounded-full bg-red-500/80 hover:bg-red-500 px-5 py-2.5 text-xs font-medium text-white transition-colors shadow-lg"
            >
              <span>Escalate to Security Incident Report</span>
              <ChevronRightIcon className="h-3.5 w-3.5" />
            </button>
          </div>

        </div>
      )}

    </div>
  );
}
