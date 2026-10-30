"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { apiClient } from "../../services/api";
import { ScanResult } from "../../lib/types";
import { ScanIcon, ShieldIcon, AlertCircleIcon, CheckCircleIcon, LockIcon } from "../../components/Icons";
import { SkeletonCard } from "../../components/SkeletonLoader";

export default function ScanPage() {
  const router = useRouter();

  const [url, setUrl] = useState("");
  const [messageText, setMessageText] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [errorMsg, setErrorMsg] = useState("");

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!url.trim() && !messageText.trim()) {
      setErrorMsg("Please enter either a URL or suspicious message text to analyze.");
      return;
    }
    setErrorMsg("");
    setLoading(true);

    try {
      const scanRes = await apiClient.submitScan({
        url: url.trim() || undefined,
        messageText: messageText.trim() || undefined,
      });
      setResult(scanRes);
    } catch {
      setErrorMsg("Failed to complete scan. Please try again or verify your connection.");
    } finally {
      setLoading(false);
    }
  };

  const handleLoadPreset = (presetUrl: string, presetText: string) => {
    setUrl(presetUrl);
    setMessageText(presetText);
    setErrorMsg("");
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
    <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      
      {/* Title & Introduction */}
      <div>
        <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">
          <ScanIcon className="h-4 w-4 text-slate-700" />
          <span>Threat Recognition Engine</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
          Suspicious URL & Message Scanner
        </h1>
        <p className="mt-1 text-sm text-slate-600">
          Analyze suspicious links, email headers, SMS text, or QR destinations against known campus threat signatures.
        </p>
      </div>

      {/* Preset Scenarios for quick Hackathon Testing */}
      <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-xs">
        <p className="text-xs font-semibold text-slate-700 mb-2">
          Quick Test Scenarios (Click to test):
        </p>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() =>
              handleLoadPreset(
                "https://campus-portal-refunds.org/auth/verify?session=9812",
                "URGENT: Dean of Student Affairs requires your bank verification to process 5,000 INR mess balance refund. Failure to claim within 3 hours will forfeit funds."
              )
            }
            className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
          >
            Malicious: Fake Mess Refund Phishing
          </button>

          <button
            type="button"
            onClick={() =>
              handleLoadPreset(
                "https://univ-portal-login.xyz/student-portal",
                "Action Required: Your student account is scheduled for deactivation due to missing academic paperwork. Click here to confirm credentials."
              )
            }
            className="rounded border border-amber-200 bg-amber-50/60 px-3 py-1.5 text-xs font-medium text-amber-900 hover:bg-amber-100/70 transition-colors"
          >
            Suspicious: Cloned Portal Login
          </button>

          <button
            type="button"
            onClick={() =>
              handleLoadPreset(
                "https://library.campus.edu/resources/research-databases",
                "Library Notice: Spring semester access to IEEE Xplore and ACM Digital Library has been renewed for enrolled students."
              )
            }
            className="rounded border border-emerald-200 bg-emerald-50/60 px-3 py-1.5 text-xs font-medium text-emerald-900 hover:bg-emerald-100/70 transition-colors"
          >
            Legitimate: Official Campus Library
          </button>
        </div>
      </div>

      {/* Input Form */}
      <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-xs space-y-6">
        <form onSubmit={handleScan} className="space-y-4">
          
          {errorMsg && (
            <div className="rounded border border-red-200 bg-red-50 p-3 text-xs text-red-800 flex items-center gap-2">
              <AlertCircleIcon className="h-4 w-4 shrink-0 text-red-600" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-slate-800 mb-1">
              Target URL or QR-Decoded Link
            </label>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="e.g. https://unverified-portal.xyz/verify or payment link"
              className="w-full rounded border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 font-mono text-xs focus:border-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900"
            />
            <p className="mt-1 text-[11px] text-slate-500">
              Only explicitly submitted links are analyzed. Zero background browsing inspection.
            </p>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-800 mb-1">
              Accompanying Message Text / Email Body / SMS (Optional)
            </label>
            <textarea
              rows={4}
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              placeholder="Paste email headers, WhatsApp message, or SMS text..."
              className="w-full rounded border border-slate-300 p-3 text-sm text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900"
            />
          </div>

          <div className="flex items-center justify-between pt-2">
            <span className="text-[11px] text-slate-500 flex items-center gap-1.5">
              <LockIcon className="h-3.5 w-3.5 text-slate-400" />
              Analyzed via isolated heuristic sandbox.
            </span>
            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-md bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 disabled:bg-slate-400 transition-colors shadow-xs"
            >
              <ScanIcon className="h-4 w-4" />
              {loading ? "Analyzing Content..." : "Run Security Scan"}
            </button>
          </div>
        </form>
      </div>

      {/* Loading Skeleton */}
      {loading && <SkeletonCard />}

      {/* Analysis Results */}
      {result && !loading && (
        <div className="rounded-lg border border-slate-200 bg-white p-6 sm:p-8 shadow-xs space-y-6">
          
          {/* Header & Verdict */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-6">
            <div>
              <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Analysis Verdict</p>
              <h2 className="text-xl font-bold text-slate-900 mt-0.5">Threat Evaluation Report</h2>
              <p className="text-xs text-slate-500 mt-1">Scan ID: {result.id} • Analyzed at {new Date(result.analyzedAt).toLocaleTimeString()}</p>
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

          {/* Risk Score & Confidence Gauge */}
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
              <p className="text-[11px] text-slate-500 mt-2">Based on rule coverage and domain reputation.</p>
            </div>

            <div className="rounded border border-slate-200 bg-slate-50 p-4">
              <p className="text-xs font-medium text-slate-500">Threat Level</p>
              <p className="text-2xl font-extrabold text-slate-900 mt-1 uppercase tracking-wide">
                {result.threatLevel}
              </p>
              <p className="text-[11px] text-slate-500 mt-2">Correlated with campus incident database.</p>
            </div>
          </div>

          {/* Detailed Summary */}
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
