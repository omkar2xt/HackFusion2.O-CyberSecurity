"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useAuth } from "../../../lib/auth-context";
import { apiClient } from "../../../services/api";
import { Incident } from "../../../lib/types";
import { ShieldIcon, SearchIcon, LockIcon } from "../../../components/Icons";
import { SkeletonTable } from "../../../components/SkeletonLoader";

export default function AdminIncidentQueuePage() {
  const { role, switchRole } = useAuth();

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  const loadIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiClient.getAdminIncidents({
        status: statusFilter,
        severity: severityFilter,
        search: searchQuery,
      });
      setIncidents(res.items);
    } catch {
      // handled
    } finally {
      setLoading(false);
    }
  }, [statusFilter, severityFilter, searchQuery]);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadIncidents();
  };

  if (role !== "security_admin") {
    return (
      <div className="mx-auto max-w-xl px-4 py-16 text-center space-y-4">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 text-amber-800">
          <LockIcon className="h-6 w-6" />
        </div>
        <h1 className="text-xl font-bold text-slate-900">Restricted Security Queue</h1>
        <p className="text-xs text-slate-600 leading-relaxed">
          The incident queue contains sensitive campus report data and is restricted to the security operations team.
        </p>
        <div className="pt-2">
          <button
            onClick={() => switchRole("security_admin")}
            className="rounded-md bg-blue-700 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-800 transition-colors shadow-xs"
          >
            Switch to Security Admin Persona (Demo Mode)
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-700 uppercase tracking-wider mb-1">
            <ShieldIcon className="h-4 w-4 text-blue-700" />
            <span>Case Management Pipeline</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
            Security Incident Queue
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            Search, filter, and triage submitted digital threats across campus.
          </p>
        </div>

        <Link
          href="/admin"
          className="self-start sm:self-center rounded border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors"
        >
          Back to SOC Metrics
        </Link>
      </div>

      {/* Filter and Search Bar */}
      <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-xs space-y-3">
        <div className="flex flex-col sm:flex-row gap-3">
          
          {/* Search bar */}
          <form onSubmit={handleSearchSubmit} className="flex-1 flex gap-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by reference (e.g. SSC-2026-8941), title, or keywords..."
                className="w-full rounded border border-slate-300 pl-8 pr-3 py-1.5 text-xs text-slate-900 focus:border-slate-900 focus:outline-none"
              />
              <SearchIcon className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
            </div>
            <button
              type="submit"
              className="rounded bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800"
            >
              Search
            </button>
          </form>

          {/* Status Filter */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 font-medium">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-800 focus:border-slate-900 focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="NEW">New (Queued)</option>
              <option value="TRIAGED">Triaged</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="CONTAINED">Contained</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 font-medium">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-800 focus:border-slate-900 focus:outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

        </div>
      </div>

      {/* Incident Table */}
      {loading ? (
        <SkeletonTable rows={4} />
      ) : incidents.length === 0 ? (
        <div className="rounded-lg border border-slate-200 bg-white p-12 text-center shadow-xs space-y-3">
          <p className="font-semibold text-slate-900 text-sm">No Incidents Found</p>
          <p className="text-xs text-slate-500">
            No incidents matched your query. Try resetting filters.
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-xs">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/70 text-slate-600 font-semibold uppercase tracking-wider text-[11px]">
                <th className="px-4 py-3">Case ID</th>
                <th className="px-4 py-3">Threat Summary</th>
                <th className="px-4 py-3">Category</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Assigned Officer</th>
                <th className="px-4 py-3 text-right">Triage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {incidents.map((inc) => (
                <tr key={inc.id} className="hover:bg-slate-50/70 transition-colors">
                  <td className="px-4 py-3 font-mono font-bold text-slate-900">
                    <Link
                      href={`/admin/incidents/${inc.id}`}
                      className="text-blue-700 hover:underline"
                    >
                      {inc.referenceNumber}
                    </Link>
                  </td>
                  <td className="px-4 py-3 max-w-sm">
                    <Link
                      href={`/admin/incidents/${inc.id}`}
                      className="font-semibold text-slate-900 hover:text-blue-700 block truncate"
                    >
                      {inc.title}
                    </Link>
                    <div className="flex items-center gap-2 mt-0.5 text-[11px] text-slate-500">
                      <span>{inc.affectedPlatform}</span>
                      <span>•</span>
                      <span>{inc.isAnonymous ? "Anonymous User" : inc.reporterName || "Campus Member"}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-slate-600 whitespace-nowrap">
                    {inc.category.replace(/_/g, " ")}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span
                      className={`inline-block font-semibold px-2 py-0.5 rounded text-[10px] ${
                        inc.severity === "CRITICAL"
                          ? "bg-red-100 text-red-900"
                          : inc.severity === "HIGH"
                          ? "bg-amber-100 text-amber-900"
                          : "bg-slate-100 text-slate-800"
                      }`}
                    >
                      {inc.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span
                      className={`inline-block border px-2 py-0.5 rounded text-[10px] font-bold ${
                        inc.status === "NEW"
                          ? "bg-slate-100 text-slate-800 border-slate-300"
                          : inc.status === "INVESTIGATING"
                          ? "bg-amber-50 text-amber-800 border-amber-300"
                          : inc.status === "RESOLVED"
                          ? "bg-emerald-50 text-emerald-800 border-emerald-300"
                          : "bg-blue-50 text-blue-800 border-blue-200"
                      }`}
                    >
                      {inc.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-600 whitespace-nowrap">
                    {inc.assignedToName || (
                      <span className="text-slate-400 italic">Unassigned</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right whitespace-nowrap">
                    <Link
                      href={`/admin/incidents/${inc.id}`}
                      className="rounded bg-slate-900 px-2.5 py-1 text-[11px] font-semibold text-white hover:bg-slate-800 shadow-2xs"
                    >
                      Investigate →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

    </div>
  );
}
