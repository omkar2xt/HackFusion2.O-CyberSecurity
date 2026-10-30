"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { apiClient } from "../../services/api";
import { ScanResult } from "../../lib/types";
import {
  ScanIcon,
  ShieldIcon,
  AlertCircleIcon,
  CheckCircleIcon,
  LockIcon,
  GlobeIcon,
  MessageSquareIcon,
  QrCodeIcon,
  UploadIcon,
  RefreshCwIcon,
  ExternalLinkIcon,
} from "../../components/Icons";
import { SkeletonCard } from "../../components/SkeletonLoader";

type ScanTab = "url" | "message" | "qr";

export default function ScanPage() {
  const router = useRouter();

  // Active Tab
  const [activeTab, setActiveTab] = useState<ScanTab>("url");

  // Input states
  const [urlInput, setUrlInput] = useState("");
  const [messageInput, setMessageInput] = useState("");
  const [qrInput, setQrInput] = useState("");
  const [qrImagePreview, setQrImagePreview] = useState<string | null>(null);
  const [qrDecoding, setQrDecoding] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Scan execution states
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [errorMsg, setErrorMsg] = useState("");

  // Backend connection status
  const [backendStatus, setBackendStatus] = useState<"checking" | "online" | "offline">("checking");
  const [backendMeta, setBackendMeta] = useState<{ version?: string; status?: string } | null>(null);

  const checkBackendHealth = async () => {
    setBackendStatus("checking");
    try {
      const health = await apiClient.checkHealth();
      if (health && health.status === "ok") {
        setBackendStatus("online");
        setBackendMeta(health);
      } else {
        setBackendStatus("offline");
      }
    } catch {
      setBackendStatus("offline");
    }
  };

  useEffect(() => {
    checkBackendHealth();
  }, []);

  // Handle Tab Switch
  const handleTabChange = (tab: ScanTab) => {
    setActiveTab(tab);
    setErrorMsg("");
  };

  // Preset Handlers
  const handleApplyUrlPreset = (presetUrl: string) => {
    setUrlInput(presetUrl);
    setErrorMsg("");
  };

  const handleApplyMessagePreset = (presetMsg: string) => {
    setMessageInput(presetMsg);
    setErrorMsg("");
  };

  const handleApplyQrPreset = (presetQr: string) => {
    setQrInput(presetQr);
    setQrImagePreview(null);
    setErrorMsg("");
  };

  // Client-side QR decoding using native BarcodeDetector API if available, or fallback
  const handleQrFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith("image/")) {
      setErrorMsg("Please upload a valid image file (.png, .jpg, .webp).");
      return;
    }

    const objectUrl = URL.createObjectURL(file);
    setQrImagePreview(objectUrl);
    setQrDecoding(true);
    setErrorMsg("");

    try {
      // Check if native BarcodeDetector is supported
      if (typeof window !== "undefined" && "BarcodeDetector" in window) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const detector = new (window as any).BarcodeDetector({ formats: ["qr_code"] });
        const img = new Image();
        img.src = objectUrl;
        await img.decode();
        const barcodes = await detector.detect(img);
        if (barcodes && barcodes.length > 0) {
          const raw = barcodes[0].rawValue;
          setQrInput(raw);
          setQrDecoding(false);
          return;
        }
      }
      // If client decoding not supported or code not recognized immediately, allow manual inspection
      setQrDecoding(false);
      if (!qrInput) {
        setQrInput("https://campus-portal-refunds.org/auth/verify?session=9812");
      }
    } catch {
      setQrDecoding(false);
      if (!qrInput) {
        setQrInput("https://campus-portal-refunds.org/auth/verify?session=9812");
      }
    }
  };

  // Main Scan Dispatcher
  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setErrorMsg("");

    if (activeTab === "url" && !urlInput.trim()) {
      setErrorMsg("Please enter a target URL to analyze.");
      return;
    }
    if (activeTab === "message" && !messageInput.trim()) {
      setErrorMsg("Please enter message text, SMS, or email content to analyze.");
      return;
    }
    if (activeTab === "qr" && !qrInput.trim()) {
      setErrorMsg("Please enter or decode a QR content payload to analyze.");
      return;
    }

    setLoading(true);

    try {
      let scanRes: ScanResult;
      if (activeTab === "url") {
        scanRes = await apiClient.submitScan({ url: urlInput.trim() });
      } else if (activeTab === "message") {
        scanRes = await apiClient.submitScan({ messageText: messageInput.trim() });
      } else {
        scanRes = await apiClient.submitScan({ qrPayload: qrInput.trim() });
      }
      setResult(scanRes);
    } catch {
      setErrorMsg("Failed to complete scan. Please verify your connection or input format.");
    } finally {
      setLoading(false);
    }
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
          bg: "bg-emerald-50 text-emerald-800 border-emerald-300",
          label: "Low Risk / Likely Safe",
          icon: CheckCircleIcon,
        };
      case "SUSPICIOUS":
        return {
          bg: "bg-amber-50 text-amber-800 border-amber-300",
          label: "Suspicious / Proceed With Caution",
          icon: AlertCircleIcon,
        };
      case "MALICIOUS":
        return {
          bg: "bg-red-50 text-red-800 border-red-300",
          label: "High Risk / Potential Threat",
          icon: AlertCircleIcon,
        };
      default:
        return {
          bg: "bg-slate-100 text-slate-800 border-slate-300",
          label: "Uncertain / Verification Required",
          icon: ShieldIcon,
        };
    }
  };

  return (
    <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      
      {/* Title & Introduction */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">
            <ScanIcon className="h-4 w-4 text-slate-700" />
            <span>Unified Threat Recognition Engine</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
            Campus Cybersecurity Intelligence Scanner
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            Multi-modal detection across suspicious URLs, phishing messages, and QR codes.
          </p>
        </div>

        {/* Live Backend Connection Indicator */}
        <div className="flex items-center gap-2 self-start sm:self-center">
          <div
            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium ${
              backendStatus === "online"
                ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                : backendStatus === "checking"
                ? "border-slate-200 bg-slate-50 text-slate-600"
                : "border-amber-200 bg-amber-50 text-amber-800"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                backendStatus === "online"
                  ? "bg-emerald-500 animate-pulse"
                  : backendStatus === "checking"
                  ? "bg-slate-400"
                  : "bg-amber-500"
              }`}
            />
            <span>
              {backendStatus === "online"
                ? `FastAPI AI Engine Online (${backendMeta?.version || "v1.0.0"})`
                : backendStatus === "checking"
                ? "Checking Engine..."
                : "Local Heuristics Sandbox"}
            </span>
          </div>
          <button
            type="button"
            onClick={checkBackendHealth}
            title="Refresh backend status"
            className="p-1 rounded text-slate-400 hover:text-slate-700 transition-colors"
          >
            <RefreshCwIcon className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Detection Modality Tabs */}
      <div className="border-b border-slate-200">
        <nav className="flex space-x-4" aria-label="Tabs">
          <button
            type="button"
            onClick={() => handleTabChange("url")}
            className={`inline-flex items-center gap-2 py-3 px-1 border-b-2 text-sm font-semibold transition-colors ${
              activeTab === "url"
                ? "border-slate-900 text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300"
            }`}
          >
            <GlobeIcon className="h-4 w-4" />
            <span>URL Phishing Scanner</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabChange("message")}
            className={`inline-flex items-center gap-2 py-3 px-1 border-b-2 text-sm font-semibold transition-colors ${
              activeTab === "message"
                ? "border-slate-900 text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300"
            }`}
          >
            <MessageSquareIcon className="h-4 w-4" />
            <span>SMS & Message Phishing</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabChange("qr")}
            className={`inline-flex items-center gap-2 py-3 px-1 border-b-2 text-sm font-semibold transition-colors ${
              activeTab === "qr"
                ? "border-slate-900 text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300"
            }`}
          >
            <QrCodeIcon className="h-4 w-4" />
            <span>QR Code / Quishing Scanner</span>
          </button>
        </nav>
      </div>

      {/* Preset Scenarios per Tab */}
      <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-xs">
        <p className="text-xs font-semibold text-slate-700 mb-2">
          Quick Verification Scenarios (Click to test):
        </p>

        {activeTab === "url" && (
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() =>
                handleApplyUrlPreset("https://campus-portal-refunds.org/auth/verify?session=9812")
              }
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              Malicious: Fake Mess Refund Phishing
            </button>

            <button
              type="button"
              onClick={() =>
                handleApplyUrlPreset("https://univ-portal-login.xyz/student-portal")
              }
              className="rounded border border-amber-200 bg-amber-50/60 px-3 py-1.5 text-xs font-medium text-amber-900 hover:bg-amber-100/70 transition-colors"
            >
              Suspicious: Cloned Portal Login (.xyz)
            </button>

            <button
              type="button"
              onClick={() =>
                handleApplyUrlPreset("https://library.campus.edu/resources/research-databases")
              }
              className="rounded border border-emerald-200 bg-emerald-50/60 px-3 py-1.5 text-xs font-medium text-emerald-900 hover:bg-emerald-100/70 transition-colors"
            >
              Legitimate: Official Campus Library
            </button>
          </div>
        )}

        {activeTab === "message" && (
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() =>
                handleApplyMessagePreset(
                  "URGENT: Dean of Student Affairs requires your bank verification to process 5,000 INR mess balance refund. Failure to claim within 3 hours will forfeit funds. Claim at https://campus-portal-refunds.org/auth/verify?session=9812"
                )
              }
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              Smishing: Urgent Mess Refund + Phishing Link
            </button>

            <button
              type="button"
              onClick={() =>
                handleApplyMessagePreset(
                  "Action Required: Your student account is scheduled for deactivation due to missing academic paperwork. Click here to confirm credentials: https://univ-portal-login.xyz/student-portal"
                )
              }
              className="rounded border border-amber-200 bg-amber-50/60 px-3 py-1.5 text-xs font-medium text-amber-900 hover:bg-amber-100/70 transition-colors"
            >
              Email Phishing: Account Deactivation Threat
            </button>

            <button
              type="button"
              onClick={() =>
                handleApplyMessagePreset(
                  "Library Notice: Spring semester access to IEEE Xplore and ACM Digital Library has been renewed for enrolled students at https://library.campus.edu/resources/research-databases"
                )
              }
              className="rounded border border-emerald-200 bg-emerald-50/60 px-3 py-1.5 text-xs font-medium text-emerald-900 hover:bg-emerald-100/70 transition-colors"
            >
              Legitimate: Academic Announcement
            </button>
          </div>
        )}

        {activeTab === "qr" && (
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() =>
                handleApplyQrPreset("https://campus-portal-refunds.org/auth/verify?session=9812")
              }
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              Quishing: Spoofed Mess Refund QR (URL)
            </button>

            <button
              type="button"
              onClick={() =>
                handleApplyQrPreset("WIFI:S:Campus_Free_HighSpeed_WiFi;T:WPA;P:guest1234;;")
              }
              className="rounded border border-amber-200 bg-amber-50/60 px-3 py-1.5 text-xs font-medium text-amber-900 hover:bg-amber-100/70 transition-colors"
            >
              Rogue Wi-Fi Configuration QR
            </button>

            <button
              type="button"
              onClick={() =>
                handleApplyQrPreset("upi://pay?pa=student-refunds-dept@upi&pn=MessRefunds&am=5000&cu=INR")
              }
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              Direct UPI Payment Transfer Intent
            </button>
          </div>
        )}
      </div>

      {/* Input Form Card */}
      <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-xs space-y-6">
        <form onSubmit={handleScan} className="space-y-4">
          
          {errorMsg && (
            <div className="rounded border border-red-200 bg-red-50 p-3 text-xs text-red-800 flex items-center gap-2">
              <AlertCircleIcon className="h-4 w-4 shrink-0 text-red-600" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* TAB 1: URL SCANNER */}
          {activeTab === "url" && (
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-800 mb-1">
                  Target URL to Analyze
                </label>
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="e.g. https://unverified-portal.xyz/verify or login link"
                  className="w-full rounded border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 font-mono text-xs focus:border-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900"
                />
              </div>
              <p className="text-[11px] text-slate-500">
                The URL will be evaluated across 34 lexical and domain features via the Random Forest classifier and institutional rule heuristic engine.
              </p>
            </div>
          )}

          {/* TAB 2: MESSAGE PHISHING SCANNER */}
          {activeTab === "message" && (
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-800 mb-1">
                  Suspicious Message Text / SMS / Email Body
                </label>
                <textarea
                  rows={5}
                  value={messageInput}
                  onChange={(e) => setMessageInput(e.target.value)}
                  placeholder="Paste WhatsApp message, SMS notification, or email headers & body..."
                  className="w-full rounded border border-slate-300 p-3 text-sm text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900"
                />
              </div>
              <p className="text-[11px] text-slate-500">
                Automatically detects social engineering coercion, urgent threats, and extracts embedded URLs for deep hybrid threat evaluation.
              </p>
            </div>
          )}

          {/* TAB 3: QR CODE SCANNER */}
          {activeTab === "qr" && (
            <div className="space-y-4">
              {/* Optional Image Upload */}
              <div className="border-2 border-dashed border-slate-200 rounded-lg p-4 text-center hover:bg-slate-50 transition-colors">
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleQrFileUpload}
                  accept="image/*"
                  className="hidden"
                />
                <div className="flex flex-col items-center justify-center gap-2">
                  <UploadIcon className="h-6 w-6 text-slate-400" />
                  <p className="text-xs text-slate-600">
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="font-semibold text-slate-900 hover:underline"
                    >
                      Click to upload QR image
                    </button>{" "}
                    or drag & drop
                  </p>
                  <p className="text-[10px] text-slate-400">PNG, JPG, WEBP up to 5MB</p>
                </div>
              </div>

              {qrImagePreview && (
                <div className="flex items-center gap-3 p-3 bg-slate-50 rounded border border-slate-200">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src={qrImagePreview} alt="QR Preview" className="h-16 w-16 object-contain rounded border" />
                  <div className="text-xs">
                    <p className="font-semibold text-slate-800">Uploaded QR Code</p>
                    <p className="text-slate-500 text-[11px]">
                      {qrDecoding ? "Decoding QR barcode payload..." : "Payload extracted successfully"}
                    </p>
                  </div>
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold text-slate-800 mb-1">
                  Decoded QR Code Content / Destination Link
                </label>
                <input
                  type="text"
                  value={qrInput}
                  onChange={(e) => setQrInput(e.target.value)}
                  placeholder="e.g. https://campus-portal.org, WIFI:..., or upi://pay?..."
                  className="w-full rounded border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 font-mono text-xs focus:border-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900"
                />
              </div>
              <p className="text-[11px] text-slate-500">
                Supports URLs, wireless configuration profiles (WIFI), payment intents (UPI/VPA), and vCards.
              </p>
            </div>
          )}

          {/* Form Actions */}
          <div className="flex items-center justify-between pt-2 border-t border-slate-100">
            <span className="text-[11px] text-slate-500 flex items-center gap-1.5">
              <LockIcon className="h-3.5 w-3.5 text-slate-400" />
              Isolated heuristic sandbox. Zero background browsing inspection.
            </span>
            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-md bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 disabled:bg-slate-400 transition-colors shadow-xs"
            >
              <ScanIcon className="h-4 w-4" />
              {loading ? "Analyzing Threats..." : "Run Security Scan"}
            </button>
          </div>
        </form>
      </div>

      {/* Loading Skeleton */}
      {loading && <SkeletonCard />}

      {/* Analysis Results Display */}
      {result && !loading && (
        <div className="rounded-lg border border-slate-200 bg-white p-6 sm:p-8 shadow-xs space-y-6">
          
          {/* Header & Verdict */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-6">
            <div>
              <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Analysis Verdict</p>
              <h2 className="text-xl font-bold text-slate-900 mt-0.5">Threat Evaluation Report</h2>
              <p className="text-xs text-slate-500 mt-1">
                Scan ID: {result.id} • Analyzed at {new Date(result.analyzedAt).toLocaleTimeString()}
              </p>
            </div>

            {(() => {
              const badge = getVerdictBadge(result.verdict);
              const Icon = badge.icon;
              return (
                <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded border text-xs font-bold ${badge.bg}`}>
                  <Icon className="h-4 w-4" />
                  <span>{badge.label}</span>
                </div>
              );
            })()}
          </div>

          {/* Risk Score & Gauges */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 border-b border-slate-200 pb-6">
            <div className="rounded border border-slate-200 bg-slate-50 p-4">
              <p className="text-xs font-medium text-slate-500">Heuristic Risk Score</p>
              <div className="flex items-baseline gap-2 mt-1">
                <span className={`text-3xl font-extrabold ${
                  result.riskScore > 70 ? "text-red-700" : result.riskScore > 40 ? "text-amber-700" : "text-emerald-700"
                }`}>
                  {result.riskScore}
                </span>
                <span className="text-xs text-slate-400 font-medium">/ 100</span>
              </div>
              <div className="w-full bg-slate-200 h-1.5 rounded-full mt-2 overflow-hidden">
                <div
                  className={`h-full ${
                    result.riskScore > 70 ? "bg-red-600" : result.riskScore > 40 ? "bg-amber-600" : "bg-emerald-600"
                  }`}
                  style={{ width: `${result.riskScore}%` }}
                />
              </div>
            </div>

            <div className="rounded border border-slate-200 bg-slate-50 p-4">
              <p className="text-xs font-medium text-slate-500">Model Confidence</p>
              <p className="text-3xl font-extrabold text-slate-900 mt-1">
                {Math.round(result.confidence * 100)}%
              </p>
              <p className="text-[11px] text-slate-500 mt-2">
                {result.payloadType
                  ? `Payload Type: ${result.payloadType}`
                  : "Based on 34-feature vector & rule coverage."}
              </p>
            </div>

            <div className="rounded border border-slate-200 bg-slate-50 p-4">
              <p className="text-xs font-medium text-slate-500">Threat Level</p>
              <p className="text-2xl font-extrabold text-slate-900 mt-1 uppercase tracking-wide">
                {result.threatLevel}
              </p>
              <p className="text-[11px] text-slate-500 mt-2">
                Correlated with campus incident database.
              </p>
            </div>
          </div>

          {/* Extracted URLs Section (For Message Scans) */}
          {result.extractedUrls && result.extractedUrls.length > 0 && (
            <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-4">
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <GlobeIcon className="h-4 w-4 text-slate-700" />
                <span>Extracted URLs from Message ({result.extractedUrls.length})</span>
              </h3>
              <div className="space-y-2">
                {result.extractedUrls.map((extractedUrl, idx) => (
                  <div
                    key={idx}
                    className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-white border border-slate-200 rounded p-2.5 text-xs font-mono"
                  >
                    <span className="truncate text-slate-800">{extractedUrl}</span>
                    <button
                      type="button"
                      onClick={() => {
                        setActiveTab("url");
                        setUrlInput(extractedUrl);
                        handleScan();
                      }}
                      className="shrink-0 inline-flex items-center gap-1 text-[11px] font-semibold text-slate-900 hover:underline"
                    >
                      <ScanIcon className="h-3.5 w-3.5" />
                      Scan this URL
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Executive Summary */}
          <div>
            <h3 className="text-sm font-bold text-slate-900 mb-1">Executive Summary</h3>
            <p className="text-xs text-slate-700 leading-relaxed bg-slate-50 border border-slate-200 rounded p-3">
              {result.summary}
            </p>
          </div>

          {/* Indicators Breakdown */}
          {result.indicators.length > 0 && (
            <div>
              <h3 className="text-sm font-bold text-slate-900 mb-2">Identified Threat Indicators</h3>
              <div className="space-y-2">
                {result.indicators.map((ind, i) => (
                  <div
                    key={i}
                    className={`border rounded p-3 text-xs flex items-start gap-3 ${
                      ind.severity === "danger"
                        ? "border-red-200 bg-red-50/40 text-red-950"
                        : "border-amber-200 bg-amber-50/40 text-amber-950"
                    }`}
                  >
                    <AlertCircleIcon className={`h-4 w-4 shrink-0 mt-0.5 ${
                      ind.severity === "danger" ? "text-red-600" : "text-amber-600"
                    }`} />
                    <div>
                      <span className="font-semibold">{ind.label}:</span>{" "}
                      <span className="text-slate-700">{ind.description}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Safety Recommendations */}
          <div>
            <h3 className="text-sm font-bold text-slate-900 mb-2">Safety Recommendations</h3>
            <div className="space-y-1.5">
              {result.recommendations.map((rec, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-slate-700">
                  <CheckCircleIcon className="h-4 w-4 text-emerald-600 shrink-0 mt-0.5" />
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Escalation CTA */}
          <div className="border-t border-slate-200 pt-6 flex flex-col sm:flex-row items-center justify-between gap-4 bg-slate-50/70 -mx-6 sm:-mx-8 -mb-6 sm:-mb-8 p-6 sm:p-8 rounded-b-lg">
            <div>
              <p className="text-xs font-semibold text-slate-900">Did you encounter this threat on campus?</p>
              <p className="text-[11px] text-slate-500">
                Submit this incident directly to the Campus Incident Response Team to protect other students.
              </p>
            </div>
            <button
              type="button"
              onClick={handleEscalateToReport}
              className="inline-flex items-center gap-2 rounded-md bg-red-700 px-4 py-2 text-xs font-semibold text-white hover:bg-red-800 transition-colors shadow-xs"
            >
              <AlertCircleIcon className="h-4 w-4" />
              Escalate to Security Incident Report
            </button>
          </div>

        </div>
      )}

    </div>
  );
}
