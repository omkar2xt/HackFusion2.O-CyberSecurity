"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "../../lib/auth-context";
import { apiClient } from "../../services/api";
import { Incident, IncidentStatus } from "../../lib/types";
import { FileTextIcon, AlertCircleIcon } from "../../components/Icons";
import { SkeletonTable } from "../../components/SkeletonLoader";

export default function MyReportsPage() {
  const { user } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState<string>("ALL");
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);

  useEffect(() => {
    async function loadReports() {
      setLoading(true);
      try {
        const data = await apiClient.getMyIncidents(user?.id || "usr-student-41");
        setIncidents(data);
      } catch {
        // handled
      } finally {
        setLoading(false);
      }
    }
    loadReports();
  }, [user]);

  const filtered = incidents.filter((inc) => {
    if (filterStatus === "ALL") return true;
    return inc.status === filterStatus;
  });

  const getStatusBadge = (status: IncidentStatus) => {
    switch (status) {
      case "NEW":
        return "bg-white/10 text-white/80 border-white/20";
      case "TRIAGED":
        return "bg-blue-500/20 text-blue-200 border-blue-400/30";
      case "INVESTIGATING":
        return "bg-amber-500/20 text-amber-200 border-amber-400/30";
      case "CONTAINED":
      case "RESOLVED":
        return "bg-emerald-500/20 text-emerald-200 border-emerald-400/30";
      default:
        return "bg-white/10 text-white/70 border-white/15";
    }
  };

  return (
    <div className="mx-auto max-w-6xl px-5 sm:px-8 md:px-12 py-10 space-y-8">
      
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-block border-l-2 border-white bg-white/15 px-3 py-1.5 backdrop-blur-md mb-3">
            <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/90">
              Reporter Case History
            </span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-normal tracking-tight text-white drop-shadow-md">
            My Submitted Incident Reports
          </h1>
          <p className="mt-1 text-sm text-white/70">
            Track investigation updates and security actions taken on threats you have flagged.
          </p>
        </div>

        <Link
          href="/report"
          className="self-start sm:self-center inline-flex items-center gap-1.5 rounded-full bg-white px-5 py-2.5 text-xs font-medium text-black hover:bg-white/85 transition-colors shadow-lg"
        >
          <AlertCircleIcon className="h-3.5 w-3.5" />
          <span>File New Report</span>
        </Link>
      </div>

      {/* Filter Tabs */}
      <div className="flex border-b border-white/15 gap-6 text-xs font-mono uppercase tracking-[0.15em]">
        {[
          { id: "ALL", label: `All (${incidents.length})` },
          { id: "NEW", label: "Queued" },
          { id: "INVESTIGATING", label: "Investigating" },
          { id: "RESOLVED", label: "Resolved" },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setFilterStatus(tab.id)}
            className={`pb-3 border-b-2 transition-colors ${
              filterStatus === tab.id
                ? "border-white font-bold text-white"
                : "border-transparent text-white/50 hover:text-white/80"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Content State */}
      {loading ? (
        <SkeletonTable rows={3} />
      ) : filtered.length === 0 ? (
        <div className="rounded-2xl border border-white/15 bg-white/10 p-12 text-center backdrop-blur-md shadow-2xl space-y-4">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-white/10 text-white/60">
            <FileTextIcon className="h-6 w-6" />
          </div>
          <h3 className="font-medium text-white text-base">No Incidents Found</h3>
          <p className="text-xs text-white/60 max-w-sm mx-auto">
            You currently have no submitted reports matching this filter.
          </p>
          <div className="pt-2">
            <Link
              href="/report"
              className="inline-flex items-center gap-1.5 rounded-full bg-white px-5 py-2 text-xs font-medium text-black hover:bg-white/85"
            >
              Report a suspicious threat
            </Link>
          </div>
        </div>
      ) : (
        <div className="overflow-hidden rounded-2xl border border-white/15 bg-white/10 backdrop-blur-md shadow-2xl">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-white/15 bg-white/5 text-white/60 font-mono uppercase tracking-[0.15em] text-[10px]">
                <th className="px-5 py-4">Reference</th>
                <th className="px-5 py-4">Title & Platform</th>
                <th className="px-5 py-4">Category</th>
                <th className="px-5 py-4">Severity</th>
                <th className="px-5 py-4">Status</th>
                <th className="px-5 py-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/10">
              {filtered.map((inc) => (
                <tr key={inc.id} className="hover:bg-white/5 transition-colors">
                  <td className="px-5 py-4 font-mono font-bold text-white">
                    {inc.referenceNumber}
                  </td>
                  <td className="px-5 py-4 max-w-xs">
                    <p className="font-medium text-white truncate">{inc.title}</p>
                    <p className="font-mono text-[10px] text-white/50 mt-0.5 truncate">{inc.affectedPlatform}</p>
                  </td>
                  <td className="px-5 py-4 text-white/70 whitespace-nowrap font-mono text-[11px]">
                    {inc.category.replace(/_/g, " ")}
                  </td>
                  <td className="px-5 py-4 whitespace-nowrap">
                    <span className={`inline-block font-mono text-[10px] uppercase tracking-wide px-2.5 py-0.5 rounded-full border ${
                      inc.severity === "CRITICAL"
                        ? "bg-red-500/20 text-red-200 border-red-400/30"
                        : inc.severity === "HIGH"
                        ? "bg-amber-500/20 text-amber-200 border-amber-400/30"
                        : "bg-white/10 text-white/80 border-white/20"
                    }`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="px-5 py-4 whitespace-nowrap">
                    <span className={`inline-block border px-2.5 py-0.5 rounded-full font-mono text-[10px] uppercase tracking-wide ${getStatusBadge(inc.status)}`}>
                      {inc.status}
                    </span>
                  </td>
                  <td className="px-5 py-4 text-right whitespace-nowrap">
                    <button
                      onClick={() => setSelectedIncident(inc)}
                      className="rounded-full border border-white/25 bg-white/10 px-3.5 py-1 font-mono text-[10px] uppercase tracking-[0.1em] text-white hover:bg-white/20 transition-colors"
                    >
                      View File
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Case Details Drawer / Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-md p-4">
          <div className="w-full max-w-2xl rounded-2xl border border-white/20 bg-[#0a0a0a]/95 backdrop-blur-xl p-6 sm:p-8 shadow-2xl space-y-6 max-h-[90vh] overflow-y-auto text-white">
            
            <div className="flex items-center justify-between border-b border-white/15 pb-4">
              <div>
                <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">
                  Case Record: {selectedIncident.referenceNumber}
                </span>
                <h3 className="text-xl font-normal text-white mt-1">
                  {selectedIncident.title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="rounded-full p-2 text-white/60 hover:text-white hover:bg-white/10"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs bg-white/5 p-4 rounded-xl border border-white/15">
              <div>
                <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/50 block">Reported At:</span>
                <span className="font-medium text-white mt-0.5 block">
                  {new Date(selectedIncident.createdAt).toLocaleString()}
                </span>
              </div>
              <div>
                <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/50 block">Status:</span>
                <span className="font-mono uppercase font-bold text-white mt-0.5 block">{selectedIncident.status}</span>
              </div>
              <div>
                <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/50 block">Category:</span>
                <span className="text-white mt-0.5 block">{selectedIncident.category}</span>
              </div>
              <div>
                <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/50 block">Assigned Unit:</span>
                <span className="text-white mt-0.5 block">{selectedIncident.assignedToName || "CIRT Triaging Queue"}</span>
              </div>
            </div>

            <div>
              <h4 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-2">Submitted Narrative</h4>
              <p className="text-xs text-white/80 leading-relaxed bg-white/5 border border-white/15 rounded-xl p-4">
                {selectedIncident.description}
              </p>
            </div>

            {selectedIncident.linkedScan && (
              <div className="border border-white/20 bg-white/10 p-4 rounded-xl text-xs space-y-1.5">
                <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">Automated Scanner Verdict</span>
                <p className="text-white font-medium">
                  Risk Score: {selectedIncident.linkedScan.riskScore}/100 ({selectedIncident.linkedScan.threatLevel})
                </p>
                <p className="text-white/60 font-mono text-[11px] truncate">
                  Target: {selectedIncident.linkedScan.targetUrl || "Message Text"}
                </p>
              </div>
            )}

            <div>
              <h4 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-3">Investigation Milestones</h4>
              <div className="space-y-3">
                {selectedIncident.auditTimeline.map((aud, i) => (
                  <div key={i} className="border-l-2 border-white/40 pl-4 py-1 text-xs">
                    <p className="font-semibold text-white">{aud.action.replace(/_/g, " ")}</p>
                    <p className="text-white/70 mt-0.5">{aud.details}</p>
                    <span className="font-mono text-[10px] text-white/40">{new Date(aud.timestamp).toLocaleTimeString()}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="border-t border-white/15 pt-4 flex justify-end">
              <button
                type="button"
                onClick={() => setSelectedIncident(null)}
                className="rounded-full border border-white/25 bg-white/10 px-5 py-2 text-xs font-medium text-white hover:bg-white/20"
              >
                Close File
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
