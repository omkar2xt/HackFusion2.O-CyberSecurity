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

  // Case management inputs
  const [newStatus, setNewStatus] = useState<IncidentStatus>("NEW");
  const [newSeverity, setNewSeverity] = useState<IncidentSeverity>("MEDIUM");
  const [assignedOfficer, setAssignedOfficer] = useState("");
  const [noteContent, setNoteContent] = useState("");
  const [updating, setUpdating] = useState(false);
  const [updateSuccess, setUpdateSuccess] = useState(false);

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
      <div className="mx-auto max-w-xl px-4 py-16 text-center space-y-4">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 text-amber-800">
          <LockIcon className="h-6 w-6" />
        </div>
        <h1 className="text-xl font-bold text-slate-900">Restricted Case File</h1>
        <p className="text-xs text-slate-600 leading-relaxed">
          Incident detail files and forensic evidence records require security administrative credentials.
        </p>
        <div className="pt-2">
          <button
            onClick={() => switchRole("security_admin")}
            className="rounded-md bg-blue-700 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-800 transition-colors shadow-sm"
          >
            Switch to Security Admin Persona (Demo Mode)
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="mx-auto max-w-5xl px-4 py-8 space-y-4">
        <SkeletonCard />
        <SkeletonCard />
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="mx-auto max-w-xl px-4 py-16 text-center space-y-3">
        <p className="font-semibold text-slate-900 text-base">Case File Not Found</p>
        <p className="text-xs text-slate-500">{errorMsg || "The requested incident record does not exist."}</p>
        <Link href="/admin/incidents" className="text-xs font-bold text-blue-700 underline">
          Return to Incident Queue
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      
      {/* Breadcrumb & Navigation */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <Link href="/admin" className="hover:text-slate-800">SOC Dashboard</Link>
          <span>/</span>
          <Link href="/admin/incidents" className="hover:text-slate-800">Incidents Queue</Link>
          <span>/</span>
          <span className="font-mono text-slate-900 font-bold">{incident.referenceNumber}</span>
        </div>
        <Link
          href="/admin/incidents"
          className="rounded border border-slate-300 bg-white px-3 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50"
        >
          ← Back to Queue
        </Link>
      </div>

      {/* Case Header */}
      <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-bold text-slate-500 uppercase tracking-wider">
              {incident.referenceNumber}
            </span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
              incident.severity === "CRITICAL"
                ? "bg-red-100 text-red-900"
                : incident.severity === "HIGH"
                ? "bg-amber-100 text-amber-900"
                : "bg-slate-100 text-slate-800"
            }`}>
              {incident.severity}
            </span>
            <span className="bg-blue-50 text-blue-900 border border-blue-200 px-2 py-0.5 rounded text-[10px] font-bold">
              STATUS: {incident.status}
            </span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 mt-2">
            {incident.title}
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Reported on {new Date(incident.createdAt).toLocaleString()} • Target: {incident.affectedPlatform}
          </p>
        </div>

        <div className="text-left sm:text-right text-xs bg-slate-50 p-3 rounded border border-slate-200 shrink-0">
          <p className="text-slate-500 text-[11px]">Reporter Identity</p>
          <p className="font-semibold text-slate-900 mt-0.5">
            {incident.isAnonymous ? "Anonymous Campus Member" : incident.reporterName}
          </p>
          <p className="text-slate-500 text-[11px]">
            {incident.isAnonymous ? "Anonymity Preserved by Protocol" : incident.reporterEmail}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Left Column: Context, Evidence & Scan indicators */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Detailed Narrative */}
          <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm space-y-3">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
              Submitted Incident Context
            </h2>
            <p className="text-xs text-slate-800 leading-relaxed bg-slate-50 border border-slate-200 rounded p-4">
              {incident.description}
            </p>
          </div>

          {/* Evidence Vault */}
          <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                Cryptographic Evidence Vault
              </h2>
              <span className="text-[11px] text-slate-400">Validated checksums</span>
            </div>

            {incident.evidenceFiles.length === 0 ? (
              <p className="text-xs text-slate-500 italic">No external attachments submitted.</p>
            ) : (
              <div className="divide-y divide-slate-100 border border-slate-200 rounded overflow-hidden">
                {incident.evidenceFiles.map((f) => (
                  <div key={f.id} className="p-3 bg-slate-50/50 flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <FileTextIcon className="h-4 w-4 text-slate-600" />
                      <div>
                        <p className="font-mono font-medium text-slate-800">{f.name}</p>
                        <p className="text-[10px] text-slate-400">
                          {(f.sizeBytes / 1024).toFixed(1)} KB • {f.mimeType}
                        </p>
                      </div>
                    </div>
                    <span className="rounded bg-emerald-100 px-2 py-0.5 text-[10px] font-bold text-emerald-800">
                      PRESERVED
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Linked Automated Threat Engine Scan */}
          {incident.linkedScan && (
            <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                  Linked Heuristic Scanner Verdict
                </h2>
                <span className="rounded bg-red-100 px-2 py-0.5 text-[11px] font-bold text-red-900">
                  {incident.linkedScan.verdict} ({incident.linkedScan.riskScore}/100)
                </span>
              </div>

              <div className="bg-slate-50 p-3 rounded border border-slate-200 text-xs space-y-1">
                <p className="font-mono text-slate-800 font-semibold break-all">
                  {incident.linkedScan.targetUrl || "Analyzed Message Body"}
                </p>
                <p className="text-slate-600 text-[11px]">{incident.linkedScan.summary}</p>
              </div>

              {incident.linkedScan.indicators.length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs font-bold text-slate-800">Rule Trigger Breakdown:</p>
                  {incident.linkedScan.indicators.map((ind, i) => (
                    <div key={i} className="border-l-2 border-red-500 pl-3 py-1 text-xs">
                      <p className="font-semibold text-slate-900">{ind.label}</p>
                      <p className="text-slate-600 text-[11px]">{ind.description}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* WD-10: Audit Action Timeline */}
          <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm space-y-4">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
              Immutable Case Audit Trail (WD-10)
            </h2>
            <div className="space-y-3">
              {incident.auditTimeline.map((aud, i) => (
                <div key={i} className="border-l-2 border-slate-300 pl-3 py-1 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-900">{aud.actor}</span>
                    <span className="text-[10px] uppercase font-bold text-slate-500 bg-slate-100 px-1 py-0.5 rounded">
                      {aud.actorRole}
                    </span>
                    <span className="font-mono text-blue-700 font-semibold text-[11px]">{aud.action}</span>
                  </div>
                  <p className="text-slate-700 text-xs mt-0.5">{aud.details}</p>
                  <span className="text-[10px] text-slate-400">
                    {new Date(aud.timestamp).toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* Right Column: WD-09 Case Management & Investigation Notes */}
        <div className="space-y-6">
          
          {/* Action Box */}
          <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm space-y-4">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
              Case Operations (WD-09)
            </h2>

            {updateSuccess && (
              <div className="rounded border border-emerald-300 bg-emerald-50 p-2.5 text-xs text-emerald-900 flex items-center gap-2">
                <CheckCircleIcon className="h-4 w-4 text-emerald-700 shrink-0" />
                <span>Case updates and audit entry saved.</span>
              </div>
            )}

            <form onSubmit={handleApplyUpdates} className="space-y-4 text-xs">
              
              <div>
                <label className="block font-semibold text-slate-700 mb-1">Update Status</label>
                <select
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value as IncidentStatus)}
                  className="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:border-slate-900 focus:outline-none"
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
                <label className="block font-semibold text-slate-700 mb-1">Adjust Severity</label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value as IncidentSeverity)}
                  className="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:border-slate-900 focus:outline-none"
                >
                  <option value="LOW">LOW</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="HIGH">HIGH</option>
                  <option value="CRITICAL">CRITICAL</option>
                </select>
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">Assigned CIRT Officer</label>
                <input
                  type="text"
                  value={assignedOfficer}
                  onChange={(e) => setAssignedOfficer(e.target.value)}
                  placeholder="e.g. Vikram Sen, Priya Nair"
                  className="w-full rounded border border-slate-300 px-2.5 py-1.5 text-xs text-slate-900 focus:border-slate-900 focus:outline-none"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">
                  Add Internal Investigation Note
                </label>
                <textarea
                  rows={3}
                  value={noteContent}
                  onChange={(e) => setNoteContent(e.target.value)}
                  placeholder="Record firewall blocks, domain sinkholes, student contact notes..."
                  className="w-full rounded border border-slate-300 p-2 text-xs text-slate-900 focus:border-slate-900 focus:outline-none"
                />
              </div>

              <button
                type="submit"
                disabled={updating}
                className="w-full rounded bg-slate-900 py-2 font-semibold text-white hover:bg-slate-800 disabled:bg-slate-400 transition-colors shadow-sm"
              >
                {updating ? "Saving Case Changes..." : "Commit Case Updates"}
              </button>
            </form>
          </div>

          {/* Internal Notes History */}
          <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm space-y-3">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
              Investigation Notes ({incident.investigationNotes.length})
            </h2>

            {incident.investigationNotes.length === 0 ? (
              <p className="text-xs text-slate-500 italic">No notes added yet.</p>
            ) : (
              <div className="space-y-3">
                {incident.investigationNotes.map((note) => (
                  <div key={note.id} className="rounded border border-slate-200 bg-slate-50 p-3 text-xs space-y-1">
                    <div className="flex items-center justify-between text-slate-500 text-[11px]">
                      <span className="font-bold text-slate-800">{note.author}</span>
                      <span>{new Date(note.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <p className="text-slate-700 leading-relaxed">{note.content}</p>
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
