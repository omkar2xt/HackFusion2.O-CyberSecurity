"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { apiClient } from "../../services/api";
import { useAuth } from "../../lib/auth-context";
import { Incident, IncidentCategory, IncidentSeverity, ScanResult } from "../../lib/types";
import { AlertCircleIcon, CheckCircleIcon, LockIcon, ChevronRightIcon } from "../../components/Icons";

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
        if (parsed.qrPayload) {
          setTitle(`Tampered QR Code Scam: ${parsed.qrPayload.substring(0, 45)}...`);
          setCategory("QR_CODE_SCAM");
          setAffectedPlatform("Campus Cafeteria / Kiosk / Bulletin Board");
        } else if (parsed.targetUrl) {
          setTitle(`Malicious Link Encountered: ${parsed.targetUrl.substring(0, 45)}...`);
          setCategory("PHISHING_EMAIL");
        } else {
          setTitle("Suspicious Message / Phishing Lure Analyzed");
          setCategory("PHISHING_EMAIL");
        }
        setDescription(parsed.summary);
        if (parsed.riskScore >= 75) {
          setSeverity("HIGH");
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
    <div className="mx-auto max-w-4xl px-5 sm:px-8 md:px-12 py-10 space-y-8">
      
      {/* Title & Badge */}
      <div>
        <div className="inline-block border-l-2 border-white bg-white/15 px-3 py-1.5 backdrop-blur-md mb-3">
          <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/90">
            Incident Escalation Vault
          </span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-normal tracking-tight text-white drop-shadow-md">
          Report Digital Threat or Cyber Incident
        </h1>
        <p className="mt-2 text-sm text-white/70 max-w-2xl leading-relaxed">
          Your report immediately alerts the Campus Incident Response Team (CIRT). Digital evidence is cryptographically preserved upon intake.
        </p>
      </div>

      {submittedIncident ? (
        <div className="rounded-2xl border border-emerald-400/40 bg-emerald-500/10 p-6 sm:p-8 backdrop-blur-md shadow-2xl space-y-6">
          <div className="flex items-start gap-4">
            <div className="rounded-full bg-emerald-400/20 p-2 text-emerald-300">
              <CheckCircleIcon className="h-8 w-8" />
            </div>
            <div className="space-y-1">
              <h2 className="text-2xl font-normal text-white">Incident Reported Successfully</h2>
              <p className="text-xs text-white/70">
                The Campus Incident Response Team has been notified. You can track this case using your reference number.
              </p>
            </div>
          </div>

          <div className="rounded-xl border border-white/15 bg-white/10 p-5 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/60">Reference Code</span>
              <span className="font-mono text-base font-bold text-white px-3 py-1 rounded-full bg-white/15 border border-white/20">
                {submittedIncident.referenceNumber}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs text-white/70 border-t border-white/10 pt-2.5">
              <span>Status:</span>
              <span className="font-mono uppercase tracking-wide text-white">Queued for Triage (NEW)</span>
            </div>
            <div className="flex items-center justify-between text-xs text-white/70">
              <span>Privacy Mode:</span>
              <span>{submittedIncident.isAnonymous ? "Anonymous Submission" : user?.email}</span>
            </div>
          </div>

          <div className="flex flex-wrap gap-3 pt-2">
            <Link
              href="/my-reports"
              className="rounded-full bg-white px-5 py-2.5 text-xs font-medium text-black hover:bg-white/85 transition-colors shadow-sm inline-flex items-center gap-1.5"
            >
              <span>View in My Reports</span>
              <ChevronRightIcon className="h-3.5 w-3.5" />
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
              className="rounded-full border border-white/25 bg-white/10 backdrop-blur-md px-5 py-2.5 text-xs font-medium text-white hover:bg-white/20 transition-colors"
            >
              Submit Another Report
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="rounded-2xl border border-white/15 bg-white/10 p-6 sm:p-8 backdrop-blur-md shadow-2xl space-y-6">
          
          {errorMsg && (
            <div className="rounded-xl border border-red-400/30 bg-red-500/10 p-3.5 text-xs text-red-200 flex items-center gap-2">
              <AlertCircleIcon className="h-4 w-4 shrink-0 text-red-400" />
              <span>{errorMsg}</span>
            </div>
          )}

          {linkedScan && (
            <div className="rounded-xl border border-white/20 bg-white/10 p-4 flex items-start justify-between gap-3">
              <div className="text-xs text-white">
                <span className="font-mono uppercase tracking-[0.15em] text-white/60">Attached Threat Scan:</span>
                <p className="font-mono text-xs text-white/90 mt-1 truncate max-w-md">
                  {linkedScan.targetUrl || linkedScan.messageText?.substring(0, 80)}
                </p>
                <p className="font-mono text-[11px] text-white/60 mt-1">
                  Risk Score: {linkedScan.riskScore}/100 ({linkedScan.threatLevel})
                </p>
              </div>
              <button
                type="button"
                onClick={() => setLinkedScan(null)}
                className="font-mono text-[10px] uppercase tracking-[0.1em] text-white/60 hover:text-white underline"
              >
                Detach
              </button>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-2">
                Incident Category
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as IncidentCategory)}
                className="w-full rounded-xl border border-white/20 bg-[#0a0a0a]/90 px-3.5 py-2.5 text-xs text-white focus:border-white focus:outline-none"
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
              <label className="block font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-2">
                Assessed Severity Level
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as IncidentSeverity)}
                className="w-full rounded-xl border border-white/20 bg-[#0a0a0a]/90 px-3.5 py-2.5 text-xs text-white focus:border-white focus:outline-none"
              >
                <option value="LOW">Low (Inconvenience / Spam)</option>
                <option value="MEDIUM">Medium (Suspicious link / Unverified solicitation)</option>
                <option value="HIGH">High (Active credential phishing / Impersonation)</option>
                <option value="CRITICAL">Critical (Immediate financial loss / Compromised credentials)</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-2">
              Affected Platform / Campus Location
            </label>
            <input
              type="text"
              value={affectedPlatform}
              onChange={(e) => setAffectedPlatform(e.target.value)}
              placeholder="e.g. Student Webmail, Main Canteen Counter 2, WhatsApp Class Group, Campus Wi-Fi"
              className="w-full rounded-xl border border-white/20 bg-white/5 px-4 py-2.5 text-xs text-white focus:border-white focus:outline-none"
            />
          </div>

          <div>
            <label className="block font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-2">
              Incident Summary / Title
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Brief summary of what happened"
              required
              className="w-full rounded-xl border border-white/20 bg-white/5 px-4 py-2.5 text-xs text-white focus:border-white focus:outline-none"
            />
          </div>

          <div>
            <label className="block font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-2">
              Detailed Description & Timeline
            </label>
            <textarea
              rows={4}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Include how you received the communication, sender address or phone number, what action was requested, and any credentials or funds involved..."
              required
              className="w-full rounded-xl border border-white/20 bg-white/5 p-4 text-xs text-white focus:border-white focus:outline-none"
            />
          </div>

          <div>
            <label className="block font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-2">
              Evidence Vault (Screenshots, Headers, .eml, .txt)
            </label>
            <div className="rounded-xl border border-dashed border-white/25 bg-white/5 p-5 text-center">
              <input
                type="file"
                onChange={handleAddEvidence}
                className="text-xs text-white/70 file:mr-3 file:py-1.5 file:px-4 file:rounded-full file:border-0 file:text-xs file:font-mono file:bg-white file:text-black hover:file:bg-white/85 cursor-pointer"
              />
              <p className="font-mono text-[10px] text-white/40 mt-2 uppercase tracking-wide">
                Maximum file size: 10MB • Cryptographic SHA-256 seal
              </p>
            </div>

            {evidenceList.length > 0 && (
              <div className="mt-3 space-y-1.5">
                {evidenceList.map((file, i) => (
                  <div key={i} className="flex items-center justify-between rounded-lg border border-white/10 bg-white/5 px-4 py-2 text-xs">
                    <span className="font-mono text-xs text-white/90 truncate">{file.name}</span>
                    <span className="font-mono text-[10px] text-white/50">{(file.size / 1024).toFixed(1)} KB</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Anonymity toggle */}
          <div className="rounded-xl border border-white/15 bg-white/5 p-4 flex items-start gap-3">
            <input
              type="checkbox"
              id="anon-checkbox"
              checked={isAnonymous}
              onChange={(e) => setIsAnonymous(e.target.checked)}
              className="mt-1 h-4 w-4 rounded border-white/20 bg-white/5 text-white focus:ring-0"
            />
            <div className="text-xs">
              <label htmlFor="anon-checkbox" className="font-medium text-white cursor-pointer">
                Submit this incident anonymously
              </label>
              <p className="text-white/60 mt-1 leading-relaxed">
                Your name, campus ID, and email address will be completely stripped from the report. Recommended for sensitive cyberbullying or peer harassment reports.
              </p>
            </div>
          </div>

          <div className="border-t border-white/15 pt-4 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.1em] text-white/50">
              <LockIcon className="h-3.5 w-3.5 text-white/40" />
              <span>Assigned unique tamper-resistant reference code.</span>
            </div>
            <button
              type="submit"
              disabled={submitting}
              className="w-full sm:w-auto rounded-full bg-white px-6 py-2.5 text-xs font-medium text-black hover:bg-white/85 disabled:bg-white/40 transition-colors shadow-lg"
            >
              {submitting ? "Submitting Incident..." : "Submit Incident Report"}
            </button>
          </div>

        </form>
      )}

    </div>
  );
}
