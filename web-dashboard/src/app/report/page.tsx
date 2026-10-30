"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { apiClient } from "../../services/api";
import { useAuth } from "../../lib/auth-context";
import { Incident, IncidentCategory, IncidentSeverity, ScanResult } from "../../lib/types";
import { AlertCircleIcon, CheckCircleIcon, LockIcon } from "../../components/Icons";

export default function ReportPage() {
  const { user } = useAuth();

  const [linkedScan, setLinkedScan] = useState<ScanResult | null>(null);
  const [category, setCategory] = useState<IncidentCategory>("PHISHING_EMAIL");
  const [severity, setSeverity] = useState<IncidentSeverity>("MEDIUM");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [affectedPlatform, setAffectedPlatform] = useState("Campus Webmail / Outlook");
  const [isAnonymous, setIsAnonymous] = useState(false);
  const [evidenceList, setEvidenceList] = useState<{ name: string; size: number }[]>([]);

  const [submitting, setSubmitting] = useState(false);
  const [submittedIncident, setSubmittedIncident] = useState<Incident | null>(null);
  const [errorMsg, setErrorMsg] = useState("");

  useEffect(() => {
    try {
      const savedScan = sessionStorage.getItem("signalsafe_pending_scan");
      if (savedScan) {
        const parsed: ScanResult = JSON.parse(savedScan);
        setLinkedScan(parsed);
        setTitle(
          parsed.targetUrl
            ? `Malicious Link Encountered: ${parsed.targetUrl.substring(0, 45)}...`
            : `Suspicious Message Analyzed`
        );
        setDescription(parsed.summary);
        if (parsed.riskScore >= 75) {
          setSeverity("HIGH");
          setCategory("PHISHING_EMAIL");
        }
        sessionStorage.removeItem("signalsafe_pending_scan");
      }
    } catch {
      // ignore
    }
  }, []);

  const handleAddEvidence = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file.size > 10 * 1024 * 1024) {
        setErrorMsg("Attachment exceeds maximum allowed limit of 10MB.");
        return;
      }
      setEvidenceList((prev) => [...prev, { name: file.name, size: file.size }]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !description.trim()) {
      setErrorMsg("Please provide both an incident title and context description.");
      return;
    }
    setErrorMsg("");
    setSubmitting(true);

    try {
      const created = await apiClient.createIncident({
        title: title.trim(),
        description: description.trim(),
        category,
        severity,
        affectedPlatform,
        isAnonymous,
        reporterId: user?.id || "usr-anonymous",
        reporterName: isAnonymous ? undefined : user?.fullName || "Campus Member",
        reporterEmail: isAnonymous ? undefined : user?.email || "anonymous@campus.edu",
        linkedScan: linkedScan || undefined,
        evidenceFiles: evidenceList.map((f, i) => ({
          id: `ev-${Date.now()}-${i}`,
          name: f.name,
          sizeBytes: f.size,
          mimeType: f.name.endsWith(".png") ? "image/png" : "application/octet-stream",
          uploadedAt: new Date().toISOString(),
        })),
      });

      setSubmittedIncident(created);
    } catch {
      setErrorMsg("Failed to submit incident report. Please try again.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      
      {/* Title */}
      <div>
        <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">
          <AlertCircleIcon className="h-4 w-4 text-slate-700" />
          <span>Incident Escalation</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
          Report Digital Threat or Cyber Incident
        </h1>
        <p className="mt-1 text-sm text-slate-600">
          Your report immediately alerts the Campus Incident Response Team (CIRT). Evidence is cryptographically logged.
        </p>
      </div>

      {/* Success Confirmation State */}
      {submittedIncident ? (
        <div className="rounded-lg border border-emerald-300 bg-white p-6 sm:p-8 shadow-sm space-y-6">
          <div className="flex items-start gap-4">
            <div className="rounded-full bg-emerald-100 p-2 text-emerald-700">
              <CheckCircleIcon className="h-8 w-8" />
            </div>
            <div className="space-y-1">
              <h2 className="text-xl font-bold text-slate-900">Incident Reported Successfully</h2>
              <p className="text-xs text-slate-600">
                The Campus Incident Response Team has been notified. You can track this case using your reference number.
              </p>
            </div>
          </div>

          <div className="rounded border border-slate-200 bg-slate-50 p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-500 uppercase">Incident Reference Number</span>
              <span className="font-mono text-base font-bold text-slate-900 px-2 py-0.5 rounded bg-white border border-slate-300">
                {submittedIncident.referenceNumber}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs text-slate-600 border-t border-slate-200 pt-2">
              <span>Current Status:</span>
              <span className="font-semibold text-blue-700">Queued for SOC Triage (NEW)</span>
            </div>
            <div className="flex items-center justify-between text-xs text-slate-600">
              <span>Reporter Privacy:</span>
              <span>{submittedIncident.isAnonymous ? "Anonymous Submission" : user?.email}</span>
            </div>
          </div>

          <div className="flex flex-wrap gap-3 pt-2">
            <Link
              href="/my-reports"
              className="rounded-md bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 transition-colors shadow-sm"
            >
              View in My Reports
            </Link>
            <button
              type="button"
              onClick={() => {
                setSubmittedIncident(null);
                setTitle("");
                setDescription("");
                setEvidenceList([]);
                setLinkedScan(null);
              }}
              className="rounded-md border border-slate-300 bg-white px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors"
            >
              Submit Another Report
            </button>
          </div>
        </div>
      ) : (
        /* Incident Submission Form */
        <form onSubmit={handleSubmit} className="rounded-lg border border-slate-200 bg-white p-6 sm:p-8 shadow-sm space-y-6">
          
          {errorMsg && (
            <div className="rounded border border-red-200 bg-red-50 p-3 text-xs text-red-800 flex items-center gap-2">
              <AlertCircleIcon className="h-4 w-4 shrink-0 text-red-600" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Linked scan banner if pre-populated */}
          {linkedScan && (
            <div className="rounded border border-blue-200 bg-blue-50/60 p-4 flex items-start justify-between gap-3">
              <div className="text-xs text-blue-900">
                <span className="font-bold">Linked Threat Scan Attached:</span>
                <p className="font-mono text-[11px] text-blue-800 mt-0.5 truncate max-w-md">
                  {linkedScan.targetUrl || linkedScan.messageText?.substring(0, 80)}
                </p>
                <p className="text-[11px] text-blue-700 mt-1">
                  Risk Score: {linkedScan.riskScore}/100 ({linkedScan.threatLevel})
                </p>
              </div>
              <button
                type="button"
                onClick={() => setLinkedScan(null)}
                className="text-xs font-semibold text-blue-700 hover:text-blue-900 underline"
              >
                Detach Scan
              </button>
            </div>
          )}

          {/* Incident Category & Severity */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-800 mb-1">
                Incident Category
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as IncidentCategory)}
                className="w-full rounded border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-900 focus:border-slate-900 focus:outline-none"
              >
                <option value="PHISHING_EMAIL">Phishing Email / Fake Campus Notice</option>
                <option value="MALICIOUS_URL">Suspicious / Cloned Portal Link</option>
                <option value="QR_CODE_SCAM">Tampered QR Code / Quishing Scam</option>
                <option value="PAYMENT_FRAUD">Fee / Mess / Stipend Payment Fraud</option>
                <option value="STAFF_IMPERSONATION">Dean / Faculty / Staff Impersonation</option>
                <option value="CYBERBULLYING">Cyberbullying / Harassment / Extortion</option>
                <option value="ACCOUNT_TAKEOVER">Compromised Account / Unauthorized Access</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-800 mb-1">
                Assessed Severity Level
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as IncidentSeverity)}
                className="w-full rounded border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-900 focus:border-slate-900 focus:outline-none"
              >
                <option value="LOW">Low (Inconvenience / Spam)</option>
                <option value="MEDIUM">Medium (Suspicious link / Unverified solicitation)</option>
                <option value="HIGH">High (Active credential phishing / Impersonation)</option>
                <option value="CRITICAL">Critical (Immediate financial loss / Compromised credentials)</option>
              </select>
            </div>
          </div>

          {/* Affected Platform */}
          <div>
            <label className="block text-xs font-semibold text-slate-800 mb-1">
              Affected Platform / Campus Location
            </label>
            <input
              type="text"
              value={affectedPlatform}
              onChange={(e) => setAffectedPlatform(e.target.value)}
              placeholder="e.g. Student Webmail, Main Canteen Counter 2, WhatsApp Class Group, Campus Wi-Fi"
              className="w-full rounded border border-slate-300 px-3 py-2 text-xs text-slate-900 focus:border-slate-900 focus:outline-none"
            />
          </div>

          {/* Incident Title */}
          <div>
            <label className="block text-xs font-semibold text-slate-800 mb-1">
              Incident Summary / Title
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Brief summary of what happened"
              required
              className="w-full rounded border border-slate-300 px-3 py-2 text-xs text-slate-900 font-medium focus:border-slate-900 focus:outline-none"
            />
          </div>

          {/* Context & Description */}
          <div>
            <label className="block text-xs font-semibold text-slate-800 mb-1">
              Detailed Description & Timeline
            </label>
            <textarea
              rows={4}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Include how you received the communication, sender address or phone number, what action was requested, and any credentials or funds involved..."
              required
              className="w-full rounded border border-slate-300 p-3 text-xs text-slate-900 focus:border-slate-900 focus:outline-none"
            />
          </div>

          {/* Evidence Attachments */}
          <div>
            <label className="block text-xs font-semibold text-slate-800 mb-1">
              Attach Evidence Files (Screenshots, Email Headers, .eml, .txt)
            </label>
            <div className="border border-dashed border-slate-300 rounded p-4 text-center bg-slate-50/50">
              <input
                type="file"
                onChange={handleAddEvidence}
                className="text-xs text-slate-600 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-slate-900 file:text-white hover:file:bg-slate-800 cursor-pointer"
              />
              <p className="text-[11px] text-slate-400 mt-1">Maximum file size: 10MB. Files are encrypted upon storage.</p>
            </div>

            {evidenceList.length > 0 && (
              <div className="mt-2 space-y-1">
                {evidenceList.map((file, i) => (
                  <div key={i} className="flex items-center justify-between bg-slate-100 px-3 py-1.5 rounded text-xs text-slate-700">
                    <span className="font-mono text-[11px] truncate">{file.name}</span>
                    <span className="text-[10px] text-slate-500">{(file.size / 1024).toFixed(1)} KB</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Privacy & Anonymous Reporting Toggle */}
          <div className="rounded border border-slate-200 bg-slate-50 p-4 flex items-start gap-3">
            <input
              type="checkbox"
              id="anon-checkbox"
              checked={isAnonymous}
              onChange={(e) => setIsAnonymous(e.target.checked)}
              className="mt-0.5 rounded border-slate-300 text-slate-900 focus:ring-slate-900"
            />
            <div className="text-xs">
              <label htmlFor="anon-checkbox" className="font-semibold text-slate-900 cursor-pointer">
                Submit this incident anonymously
              </label>
              <p className="text-slate-500 mt-0.5 leading-relaxed">
                Your name, campus ID, and email address will be completely stripped from the report. Recommended for sensitive cyberbullying or peer harassment reports.
              </p>
            </div>
          </div>

          {/* Submission CTA */}
          <div className="border-t border-slate-200 pt-4 flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-xs text-slate-500">
              <LockIcon className="h-4 w-4 text-slate-400" />
              <span>Assigned unique tamper-resistant reference code.</span>
            </div>
            <button
              type="submit"
              disabled={submitting}
              className="rounded-md bg-slate-900 px-5 py-2.5 text-xs font-semibold text-white hover:bg-slate-800 disabled:bg-slate-400 transition-colors shadow-sm"
            >
              {submitting ? "Submitting Incident..." : "Submit Incident Report"}
            </button>
          </div>

        </form>
      )}

    </div>
  );
}
