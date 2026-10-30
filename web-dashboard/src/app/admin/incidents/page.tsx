"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useAuth } from "../../../lib/auth-context";
import { apiClient } from "../../../services/api";
import { Incident } from "../../../lib/types";
import { SearchIcon, LockIcon, ChevronRightIcon } from "../../../components/Icons";
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
    // Seamless demo access: auto-promote to security_admin when accessing the Incident Queue
    if (role && role !== "security_admin") {
      switchRole("security_admin");
    }
  }, [role, switchRole]);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents, role]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadIncidents();
  };

  if (role !== "security_admin") {
    return (
      <div className="mx-auto max-w-xl px-5 py-20 text-center space-y-6">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-white/20 bg-white/10 text-white shadow-xl">
          <LockIcon className="h-7 w-7" />
        </div>
        <div className="space-y-2">
          <h1 className="text-2xl font-normal text-white">Restricted Security Queue</h1>
          <p className="text-xs text-white/60 leading-relaxed max-w-md mx-auto">
            The incident queue contains sensitive campus report data and is restricted to the security operations team.
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

  return (
    <div className="mx-auto max-w-7xl px-5 sm:px-8 md:px-12 py-10 space-y-8">
      
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-block border-l-2 border-white bg-white/15 px-3 py-1.5 backdrop-blur-md mb-3">
            <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/90">
              Case Management Pipeline
            </span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-normal tracking-tight text-white drop-shadow-md">
            Security Incident Queue
          </h1>
          <p className="mt-1 text-sm text-white/70">
            Search, filter, and triage submitted digital threats across campus.
          </p>
        </div>

        <Link
          href="/admin"
          className="self-start sm:self-center rounded-full border border-white/25 bg-white/10 px-4 py-2 text-xs font-mono uppercase tracking-[0.1em] text-white hover:bg-white/20 transition-colors"
        >
          Back to SOC Metrics
        </Link>
      </div>

      {/* Filter and Search Bar in Frosted Glass */}
      <div className="rounded-2xl border border-white/15 bg-white/10 p-5 backdrop-blur-md shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          
          {/* Search bar */}
          <form onSubmit={handleSearchSubmit} className="flex-1 flex gap-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search reference (e.g. SSC-2026-8941), title, or keywords..."
                className="w-full rounded-xl border border-white/20 bg-white/5 pl-9 pr-4 py-2 text-xs text-white placeholder:text-white/40 focus:border-white focus:outline-none"
              />
              <SearchIcon className="absolute left-3 top-2.5 h-3.5 w-3.5 text-white/40" />
            </div>
            <button
              type="submit"
              className="rounded-full bg-white px-4 py-2 text-xs font-medium text-black hover:bg-white/85"
            >
              Search
            </button>
          </form>

          {/* Status Filter */}
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-xl border border-white/20 bg-[#0a0a0a]/90 px-3 py-2 text-xs text-white focus:border-white focus:outline-none"
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
            <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="rounded-xl border border-white/20 bg-[#0a0a0a]/90 px-3 py-2 text-xs text-white focus:border-white focus:outline-none"
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
        <div className="rounded-2xl border border-white/15 bg-white/10 p-12 text-center backdrop-blur-md shadow-2xl space-y-3">
          <p className="text-white text-base font-medium">No Incidents Found</p>
          <p className="text-xs text-white/60">
            No incidents matched your query. Try resetting filters.
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-2xl border border-white/15 bg-white/10 backdrop-blur-md shadow-2xl">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-white/15 bg-white/5 text-white/60 font-mono uppercase tracking-[0.15em] text-[10px]">
                <th className="px-5 py-4">Case ID</th>
                <th className="px-5 py-4">Threat Summary</th>
                <th className="px-5 py-4">Category</th>
                <th className="px-5 py-4">Severity</th>
                <th className="px-5 py-4">Status</th>
                <th className="px-5 py-4">Officer</th>
                <th className="px-5 py-4 text-right">Triage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/10">
              {incidents.map((inc) => (
                <tr key={inc.id} className="hover:bg-white/5 transition-colors">
                  <td className="px-5 py-4 font-mono font-bold text-white">
                    <Link
                      href={`/admin/incidents/${inc.id}`}
                      className="hover:underline text-white/90"
                    >
                      {inc.referenceNumber}
                    </Link>
                  </td>
                  <td className="px-5 py-4 max-w-sm">
                    <Link
                      href={`/admin/incidents/${inc.id}`}
                      className="font-medium text-white hover:text-white/80 block truncate"
                    >
                      {inc.title}
                    </Link>
                    <div className="flex items-center gap-2 mt-0.5 font-mono text-[10px] text-white/50">
                      <span>{inc.affectedPlatform}</span>
                      <span>•</span>
                      <span>{inc.isAnonymous ? "Anonymous User" : inc.reporterName || "Campus Member"}</span>
                    </div>
                  </td>
                  <td className="px-5 py-4 text-white/70 whitespace-nowrap font-mono text-[11px]">
                    {inc.category.replace(/_/g, " ")}
                  </td>
                  <td className="px-5 py-4 whitespace-nowrap">
                    <span
                      className={`inline-block font-mono text-[10px] uppercase tracking-wide px-2.5 py-0.5 rounded-full border ${
                        inc.severity === "CRITICAL"
                          ? "bg-red-500/20 text-red-200 border-red-400/30"
                          : inc.severity === "HIGH"
                          ? "bg-amber-500/20 text-amber-200 border-amber-400/30"
                          : "bg-white/10 text-white/80 border-white/20"
                      }`}
                    >
                      {inc.severity}
                    </span>
                  </td>
                  <td className="px-5 py-4 whitespace-nowrap">
                    <span
                      className={`inline-block border px-2.5 py-0.5 rounded-full font-mono text-[10px] uppercase tracking-wide ${
                        inc.status === "NEW"
                          ? "bg-white/10 text-white/80 border-white/20"
                          : inc.status === "INVESTIGATING"
                          ? "bg-amber-500/20 text-amber-200 border-amber-400/30"
                          : inc.status === "RESOLVED"
                          ? "bg-emerald-500/20 text-emerald-200 border-emerald-400/30"
                          : "bg-blue-500/20 text-blue-200 border-blue-400/30"
                      }`}
                    >
                      {inc.status}
                    </span>
                  </td>
                  <td className="px-5 py-4 text-white/70 whitespace-nowrap">
                    {inc.assignedToName || (
                      <span className="text-white/30 italic">Unassigned</span>
                    )}
                  </td>
                  <td className="px-5 py-4 text-right whitespace-nowrap">
                    <Link
                      href={`/admin/incidents/${inc.id}`}
                      className="inline-flex items-center gap-1 rounded-full bg-white px-3.5 py-1 font-mono text-[10px] uppercase tracking-[0.1em] text-black hover:bg-white/85 shadow-sm"
                    >
                      <span>Investigate</span>
                      <ChevronRightIcon className="h-3 w-3" />
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
