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
        return "bg-slate-100 text-slate-800 border-slate-300";
      case "TRIAGED":
        return "bg-blue-50 text-blue-800 border-blue-200";
      case "INVESTIGATING":
        return "bg-amber-50 text-amber-800 border-amber-300";
      case "CONTAINED":
      case "RESOLVED":
        return "bg-emerald-50 text-emerald-800 border-emerald-300";
      default:
        return "bg-slate-100 text-slate-700 border-slate-200";
    }
  };

  return (
    <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">
            <FileTextIcon className="h-4 w-4 text-slate-700" />
            <span>Reporter Case History</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
            My Submitted Incident Reports
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            Track investigation updates and security actions taken on threats you have flagged.
          </p>
        </div>

        <Link
          href="/report"
          className="self-start sm:self-center inline-flex items-center gap-2 rounded-md bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 transition-colors shadow-xs"
        >
          <AlertCircleIcon className="h-3.5 w-3.5" />
          File New Report
        </Link>
      </div>

      {/* Filter Tabs */}
      <div className="flex border-b border-slate-200 gap-6 text-xs font-medium">
        {[
          { id: "ALL", label: `All Reports (${incidents.length})` },
          { id: "NEW", label: "Queued" },
          { id: "INVESTIGATING", label: "Under Investigation" },
          { id: "RESOLVED", label: "Resolved" },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setFilterStatus(tab.id)}
            className={`pb-3 border-b-2 transition-colors ${
              filterStatus === tab.id
                ? "border-slate-900 font-bold text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-800"
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
        <div className="rounded-lg border border-slate-200 bg-white p-12 text-center shadow-xs space-y-3">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-slate-100 text-slate-500">
            <FileTextIcon className="h-6 w-6" />
          </div>
          <h3 className="font-semibold text-slate-900 text-sm">No Incidents Found</h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            You currently have no submitted reports matching this filter.
          </p>
          <div className="pt-2">
            <Link
              href="/report"
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-900 underline"
            >
              Report a suspicious URL or message
            </Link>
          </div>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-xs">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/70 text-slate-600 font-semibold uppercase tracking-wider text-[11px]">
                <th className="px-4 py-3">Reference</th>
                <th className="px-4 py-3">Title & Platform</th>
                <th className="px-4 py-3">Category</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filtered.map((inc) => (
                <tr key={inc.id} className="hover:bg-slate-50/60 transition-colors">
                  <td className="px-4 py-3 font-mono font-bold text-slate-900">
                    {inc.referenceNumber}
                  </td>
                  <td className="px-4 py-3 max-w-xs">
                    <p className="font-semibold text-slate-900 truncate">{inc.title}</p>
                    <p className="text-[11px] text-slate-500 mt-0.5 truncate">{inc.affectedPlatform}</p>
                  </td>
                  <td className="px-4 py-3 text-slate-600 whitespace-nowrap">
                    {inc.category.replace(/_/g, " ")}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className={`inline-block font-semibold px-2 py-0.5 rounded text-[10px] ${
                      inc.severity === "CRITICAL"
                        ? "bg-red-100 text-red-900"
                        : inc.severity === "HIGH"
                        ? "bg-amber-100 text-amber-900"
                        : "bg-slate-100 text-slate-800"
                    }`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className={`inline-block border px-2 py-0.5 rounded text-[10px] font-bold ${getStatusBadge(inc.status)}`}>
                      {inc.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right whitespace-nowrap">
                    <button
                      onClick={() => setSelectedIncident(inc)}
                      className="rounded border border-slate-300 bg-white px-2.5 py-1 font-semibold text-slate-700 hover:bg-slate-50 text-[11px]"
                    >
                      View Details
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-2xs p-4">
          <div className="w-full max-w-2xl rounded-lg border border-slate-200 bg-white p-6 shadow-xl space-y-5 max-h-[90vh] overflow-y-auto">
            
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <span className="font-mono text-xs font-bold text-slate-500 uppercase tracking-wider">
                  Case File: {selectedIncident.referenceNumber}
                </span>
                <h3 className="text-base font-bold text-slate-900 mt-0.5">
                  {selectedIncident.title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="rounded p-1 text-slate-400 hover:text-slate-700"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs bg-slate-50 p-3 rounded border border-slate-200">
              <div>
                <span className="text-slate-500 block text-[11px]">Reported At:</span>
                <span className="font-medium text-slate-800">
                  {new Date(selectedIncident.createdAt).toLocaleString()}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px]">Current Status:</span>
                <span className="font-bold text-blue-700">{selectedIncident.status}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px]">Category:</span>
                <span className="text-slate-800">{selectedIncident.category}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px]">Assigned Unit:</span>
                <span className="text-slate-800">{selectedIncident.assignedToName || "CIRT Triaging Queue"}</span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-bold text-slate-900 mb-1">Incident Summary & Narrative</h4>
              <p className="text-xs text-slate-700 leading-relaxed bg-white border border-slate-200 rounded p-3">
                {selectedIncident.description}
              </p>
            </div>

            {selectedIncident.linkedScan && (
              <div className="border border-amber-200 bg-amber-50/50 p-3 rounded text-xs space-y-1">
                <span className="font-bold text-amber-950">Linked Automated Scanner Verdict:</span>
                <p className="text-amber-900">
                  Risk Score: {selectedIncident.linkedScan.riskScore}/100 ({selectedIncident.linkedScan.threatLevel})
                </p>
                <p className="text-amber-800 text-[11px] font-mono">
                  Target: {selectedIncident.linkedScan.targetUrl || "Message Text"}
                </p>
              </div>
            )}

            <div>
              <h4 className="text-xs font-bold text-slate-900 mb-2">Investigation Milestones</h4>
              <div className="space-y-2">
                {selectedIncident.auditTimeline.map((aud, i) => (
                  <div key={i} className="border-l-2 border-slate-300 pl-3 py-0.5 text-xs">
                    <p className="font-semibold text-slate-800">{aud.action.replace(/_/g, " ")}</p>
                    <p className="text-[11px] text-slate-500">{aud.details}</p>
                    <span className="text-[10px] text-slate-400">{new Date(aud.timestamp).toLocaleTimeString()}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="border-t border-slate-100 pt-3 flex justify-end">
              <button
                type="button"
                onClick={() => setSelectedIncident(null)}
                className="rounded border border-slate-300 bg-white px-4 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50"
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
