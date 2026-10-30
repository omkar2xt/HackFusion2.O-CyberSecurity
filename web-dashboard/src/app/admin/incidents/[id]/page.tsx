"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useAuth } from "../../../../lib/auth-context";
import { apiClient } from "../../../../services/api";
import { Incident, IncidentStatus, IncidentSeverity } from "../../../../lib/types";
import { CheckCircleIcon, LockIcon, FileTextIcon } from "../../../../components/Icons";
import { SkeletonCard } from "../../../../components/SkeletonLoader";

export default function IncidentDetailPage() {
  const params = useParams();
  const { role, user, switchRole } = useAuth();

  const id = Array.isArray(params?.id) ? params.id[0] : (params?.id as string);

  const [incident, setIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState("");

  const [newStatus, setNewStatus] = useState<IncidentStatus>("NEW");
  const [newSeverity, setNewSeverity] = useState<IncidentSeverity>("MEDIUM");
  const [assignedOfficer, setAssignedOfficer] = useState("");
  const [noteContent, setNoteContent] = useState("");
  const [updating, setUpdating] = useState(false);
  const [updateSuccess, setUpdateSuccess] = useState(false);

  useEffect(() => {
    // Seamless demo access: auto-promote to security_admin when investigating case files
    if (role && role !== "security_admin") {
      switchRole("security_admin");
    }
  }, [role, switchRole]);

  useEffect(() => {
    async function fetchCase() {
      if (!id) return;
      setLoading(true);
      try {
        const item = await apiClient.getIncidentById(id);
        if (item) {
          setIncident(item);
          setNewStatus(item.status);
          setNewSeverity(item.severity);
          setAssignedOfficer(item.assignedToName || "");
        } else {
          setErrorMsg("Incident case not found.");
        }
      } catch {
        setErrorMsg("Failed to load incident detail.");
      } finally {
        setLoading(false);
      }
    }
    fetchCase();
  }, [id]);

  const handleApplyUpdates = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident) return;
    setUpdating(true);
    setUpdateSuccess(false);

    try {
      const updated = await apiClient.updateIncident(incident.id, {
        status: newStatus,
        severity: newSeverity,
        assignedTo: assignedOfficer ? "sec-officer-custom" : undefined,
        assignedToName: assignedOfficer || undefined,
        note: noteContent.trim() || undefined,
        actorName: user?.fullName || "Security Admin",
      });

      if (updated) {
        setIncident(updated);
        setNoteContent("");
        setUpdateSuccess(true);
        setTimeout(() => setUpdateSuccess(false), 3000);
      }
    } catch {
      setErrorMsg("Failed to save case updates.");
    } finally {
      setUpdating(false);
    }
  };

  if (role !== "security_admin") {
    return (
      <div className="mx-auto max-w-xl px-5 py-20 text-center space-y-6">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-white/20 bg-white/10 text-white shadow-xl">
          <LockIcon className="h-7 w-7" />
        </div>
        <div className="space-y-2">
          <h1 className="text-2xl font-normal text-white">Restricted Case File</h1>
          <p className="text-xs text-white/60 leading-relaxed max-w-md mx-auto">
            Incident detail files and forensic evidence records require security administrative credentials.
          </p>
        </div>
        <div>
          <button
            onClick={() => switchRole("security_admin")}
            className="rounded-full bg-white px-6 py-2.5 text-xs font-medium text-black hover:bg-white/85 transition-colors shadow-lg"
          >
            Switch to Security Admin Persona (Demo Mode)
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="mx-auto max-w-5xl px-5 sm:px-8 py-10 space-y-4">
        <SkeletonCard />
        <SkeletonCard />
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="mx-auto max-w-xl px-5 py-20 text-center space-y-3">
        <p className="font-normal text-white text-xl">Case File Not Found</p>
        <p className="text-xs text-white/60">{errorMsg || "The requested incident record does not exist."}</p>
        <Link href="/admin/incidents" className="font-mono text-xs uppercase tracking-[0.1em] text-white underline">
          Return to Incident Queue
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl px-5 sm:px-8 md:px-12 py-10 space-y-8">
      
      {/* Breadcrumb Navigation */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 font-mono text-[11px] text-white/60">
          <Link href="/admin" className="hover:text-white">SOC</Link>
          <span>/</span>
          <Link href="/admin/incidents" className="hover:text-white">QUEUE</Link>
          <span>/</span>
          <span className="text-white font-bold">{incident.referenceNumber}</span>
        </div>
        <Link
          href="/admin/incidents"
          className="rounded-full border border-white/25 bg-white/10 px-4 py-1.5 font-mono text-[10px] uppercase tracking-[0.1em] text-white hover:bg-white/20"
        >
          ← Back to Queue
        </Link>
      </div>

      {/* Case Header in Frosted Glass */}
      <div className="rounded-2xl border border-white/15 bg-white/10 p-6 sm:p-8 backdrop-blur-md shadow-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-bold text-white/60 uppercase tracking-wider">
              {incident.referenceNumber}
            </span>
            <span className={`px-2.5 py-0.5 rounded-full font-mono text-[10px] uppercase tracking-wide border ${
              incident.severity === "CRITICAL"
                ? "bg-red-500/20 text-red-200 border-red-400/30"
                : incident.severity === "HIGH"
                ? "bg-amber-500/20 text-amber-200 border-amber-400/30"
                : "bg-white/10 text-white/80 border-white/20"
            }`}>
              {incident.severity}
            </span>
            <span className="bg-blue-500/20 text-blue-200 border border-blue-400/30 px-2.5 py-0.5 rounded-full font-mono text-[10px] uppercase tracking-wide">
              {incident.status}
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-normal text-white mt-2 drop-shadow-sm">
            {incident.title}
          </h1>
          <p className="font-mono text-[11px] text-white/50 mt-1">
            Reported: {new Date(incident.createdAt).toLocaleString()} • Target: {incident.affectedPlatform}
          </p>
        </div>

        <div className="text-left sm:text-right text-xs bg-white/5 p-4 rounded-xl border border-white/15 shrink-0">
          <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/50 block">Reporter Identity</span>
          <p className="font-medium text-white mt-1">
            {incident.isAnonymous ? "Anonymous Campus Member" : incident.reporterName}
          </p>
          <p className="font-mono text-[10px] text-white/50 mt-0.5">
            {incident.isAnonymous ? "Anonymity Preserved by Protocol" : incident.reporterEmail}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Left Column: Context, Evidence & Scan indicators */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Detailed Narrative */}
          <div className="rounded-2xl border border-white/15 bg-white/10 p-6 backdrop-blur-md shadow-xl space-y-3">
            <h2 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80">
              Submitted Incident Context
            </h2>
            <p className="text-xs text-white/85 leading-relaxed bg-white/5 border border-white/15 rounded-xl p-4">
              {incident.description}
            </p>
          </div>

          {/* Evidence Vault */}
          <div className="rounded-2xl border border-white/15 bg-white/10 p-6 backdrop-blur-md shadow-xl space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80">
                Cryptographic Evidence Vault
              </h2>
              <span className="font-mono text-[10px] text-white/40 uppercase">Validated SHA-256</span>
            </div>

            {incident.evidenceFiles.length === 0 ? (
              <p className="text-xs text-white/40 italic">No external attachments submitted.</p>
            ) : (
              <div className="divide-y divide-white/10 border border-white/15 rounded-xl overflow-hidden bg-white/5">
                {incident.evidenceFiles.map((f) => (
                  <div key={f.id} className="p-3.5 flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2.5">
                      <FileTextIcon className="h-4 w-4 text-white/60" />
                      <div>
                        <p className="font-mono text-white/90">{f.name}</p>
                        <p className="font-mono text-[10px] text-white/40">
                          {(f.sizeBytes / 1024).toFixed(1)} KB • {f.mimeType}
                        </p>
                      </div>
                    </div>
                    <span className="rounded-full bg-emerald-500/20 text-emerald-200 border border-emerald-400/30 px-2.5 py-0.5 font-mono text-[9px] uppercase tracking-wide">
                      PRESERVED
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Linked Automated Threat Engine Scan */}
          {incident.linkedScan && (
            <div className="rounded-2xl border border-white/15 bg-white/10 p-6 backdrop-blur-md shadow-xl space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80">
                  Linked Threat Scanner Verdict
                </h2>
                <span className="rounded-full bg-red-500/20 text-red-200 border border-red-400/30 px-3 py-0.5 font-mono text-[10px] uppercase font-bold">
                  {incident.linkedScan.verdict} ({incident.linkedScan.riskScore}/100)
                </span>
              </div>

              <div className="bg-white/5 p-4 rounded-xl border border-white/15 text-xs space-y-1.5">
                <p className="font-mono text-white break-all">
                  {incident.linkedScan.targetUrl || "Analyzed Message Body"}
                </p>
                <p className="text-white/70 text-xs">{incident.linkedScan.summary}</p>
              </div>

              {incident.linkedScan.indicators.length > 0 && (
                <div className="space-y-2">
                  <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">Indicator Breakdown</span>
                  {incident.linkedScan.indicators.map((ind, i) => (
                    <div key={i} className="border-l-2 border-red-400 pl-3 py-1 text-xs">
                      <p className="font-medium text-white">{ind.label}</p>
                      <p className="text-white/60 text-xs">{ind.description}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Audit Action Timeline (WD-10) */}
          <div className="rounded-2xl border border-white/15 bg-white/10 p-6 backdrop-blur-md shadow-xl space-y-4">
            <h2 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80">
              Immutable Case Audit Trail (WD-10)
            </h2>
            <div className="space-y-3">
              {incident.auditTimeline.map((aud, i) => (
                <div key={i} className="border-l-2 border-white/30 pl-4 py-1 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-white">{aud.actor}</span>
                    <span className="font-mono text-[9px] uppercase tracking-wide text-white/50 bg-white/10 px-2 py-0.5 rounded-full border border-white/10">
                      {aud.actorRole}
                    </span>
                    <span className="font-mono text-white/80 text-[11px]">{aud.action}</span>
                  </div>
                  <p className="text-white/70 text-xs mt-1">{aud.details}</p>
                  <span className="font-mono text-[10px] text-white/40">
                    {new Date(aud.timestamp).toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* Right Column: WD-09 Case Operations & Notes */}
        <div className="space-y-6">
          
          <div className="rounded-2xl border border-white/15 bg-white/10 p-6 backdrop-blur-md shadow-xl space-y-4">
            <h2 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80">
              Case Operations (WD-09)
            </h2>

            {updateSuccess && (
              <div className="rounded-xl border border-emerald-400/30 bg-emerald-500/10 p-3 text-xs text-emerald-200 flex items-center gap-2">
                <CheckCircleIcon className="h-4 w-4 text-emerald-400 shrink-0" />
                <span>Case updates and audit entry saved.</span>
              </div>
            )}

            <form onSubmit={handleApplyUpdates} className="space-y-4 text-xs">
              
              <div>
                <label className="block font-mono text-[10px] uppercase tracking-[0.15em] text-white/70 mb-1.5">
                  Update Status
                </label>
                <select
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value as IncidentStatus)}
                  className="w-full rounded-xl border border-white/20 bg-[#0a0a0a]/90 px-3 py-2 text-xs text-white focus:border-white focus:outline-none"
                >
                  <option value="NEW">NEW (Awaiting Triage)</option>
                  <option value="TRIAGED">TRIAGED (Assessed)</option>
                  <option value="INVESTIGATING">INVESTIGATING (In Progress)</option>
                  <option value="CONTAINED">CONTAINED (Mitigated / Blocked)</option>
                  <option value="RESOLVED">RESOLVED (Closed)</option>
                  <option value="FALSE_POSITIVE">FALSE_POSITIVE (Dismissed)</option>
                </select>
              </div>

              <div>
                <label className="block font-mono text-[10px] uppercase tracking-[0.15em] text-white/70 mb-1.5">
                  Adjust Severity
                </label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value as IncidentSeverity)}
                  className="w-full rounded-xl border border-white/20 bg-[#0a0a0a]/90 px-3 py-2 text-xs text-white focus:border-white focus:outline-none"
                >
                  <option value="LOW">LOW</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="HIGH">HIGH</option>
                  <option value="CRITICAL">CRITICAL</option>
                </select>
              </div>

              <div>
                <label className="block font-mono text-[10px] uppercase tracking-[0.15em] text-white/70 mb-1.5">
                  Assigned CIRT Officer
                </label>
                <input
                  type="text"
                  value={assignedOfficer}
                  onChange={(e) => setAssignedOfficer(e.target.value)}
                  placeholder="e.g. Vikram Sen, Priya Nair"
                  className="w-full rounded-xl border border-white/20 bg-white/5 px-3 py-2 text-xs text-white focus:border-white focus:outline-none"
                />
              </div>

              <div>
                <label className="block font-mono text-[10px] uppercase tracking-[0.15em] text-white/70 mb-1.5">
                  Internal Investigation Note
                </label>
                <textarea
                  rows={3}
                  value={noteContent}
                  onChange={(e) => setNoteContent(e.target.value)}
                  placeholder="Record firewall blocks, domain sinkholes, student contact notes..."
                  className="w-full rounded-xl border border-white/20 bg-white/5 p-3 text-xs text-white focus:border-white focus:outline-none"
                />
              </div>

              <button
                type="submit"
                disabled={updating}
                className="w-full rounded-full bg-white py-2.5 font-medium text-xs text-black hover:bg-white/85 disabled:bg-white/40 transition-colors shadow-lg"
              >
                {updating ? "Saving Changes..." : "Commit Case Updates"}
              </button>
            </form>
          </div>

          {/* Investigation Notes History */}
          <div className="rounded-2xl border border-white/15 bg-white/10 p-6 backdrop-blur-md shadow-xl space-y-3">
            <h2 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80">
              Investigation Notes ({incident.investigationNotes.length})
            </h2>

            {incident.investigationNotes.length === 0 ? (
              <p className="text-xs text-white/40 italic">No notes added yet.</p>
            ) : (
              <div className="space-y-3">
                {incident.investigationNotes.map((note) => (
                  <div key={note.id} className="rounded-xl border border-white/15 bg-white/5 p-3.5 text-xs space-y-1">
                    <div className="flex items-center justify-between text-white/50 font-mono text-[10px]">
                      <span className="font-semibold text-white">{note.author}</span>
                      <span>{new Date(note.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <p className="text-white/80 leading-relaxed mt-1">{note.content}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

        </div>

      </div>

    </div>
  );
}
