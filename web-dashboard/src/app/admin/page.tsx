"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "../../lib/auth-context";
import { apiClient } from "../../services/api";
import { AdminMetrics } from "../../lib/types";
import { ActivityIcon, ShieldIcon, LockIcon } from "../../components/Icons";
import { SkeletonCard } from "../../components/SkeletonLoader";

export default function AdminDashboardPage() {
  const { role, switchRole } = useAuth();
  const [metrics, setMetrics] = useState<AdminMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchMetrics() {
      setLoading(true);
      try {
        const data = await apiClient.getAdminMetrics();
        setMetrics(data);
      } catch {
        // handled
      } finally {
        setLoading(false);
      }
    }
    fetchMetrics();
  }, []);

  // Role Access Guard
  if (role !== "security_admin") {
    return (
      <div className="mx-auto max-w-xl px-4 py-16 text-center space-y-4">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 text-amber-800">
          <LockIcon className="h-6 w-6" />
        </div>
        <h1 className="text-xl font-bold text-slate-900">Restricted Security Operations Console</h1>
        <p className="text-xs text-slate-600 leading-relaxed">
          Access to campus-wide incident triage and security metrics is restricted to authorized
          Campus Incident Response Team (CIRT) personnel. Your current active role is:{" "}
          <span className="font-semibold uppercase text-slate-800">{role || "Guest"}</span>.
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

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      
      {/* Executive Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-6">
        <div>
          <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-700 uppercase tracking-wider mb-1">
            <ActivityIcon className="h-4 w-4 text-blue-700" />
            <span>Campus Incident Response Team (CIRT)</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
            Security Operations Dashboard
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            Real-time threat telemetry, triage velocity, and campus-wide incident oversight.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/admin/incidents"
            className="rounded-md bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 transition-colors shadow-sm inline-flex items-center gap-2"
          >
            <ShieldIcon className="h-3.5 w-3.5" />
            Open Incident Triage Queue
          </Link>
        </div>
      </div>

      {loading || !metrics ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : (
        <>
          {/* Key Metric KPI Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            
            <div className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Total Recorded Cases</p>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-slate-900">{metrics.totalIncidents}</span>
                <span className="text-xs text-slate-500">all time</span>
              </div>
              <p className="mt-2 text-[11px] text-slate-500">Cross-channel incident intake</p>
            </div>

            <div className="rounded-lg border border-amber-200 bg-amber-50/40 p-5 shadow-sm">
              <p className="text-xs font-semibold text-amber-800 uppercase tracking-wider">Pending Investigation</p>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-amber-900">{metrics.openIncidents}</span>
                <span className="text-xs text-amber-700 font-medium">active cases</span>
              </div>
              <p className="mt-2 text-[11px] text-amber-800">Requires triage review or containment</p>
            </div>

            <div className="rounded-lg border border-red-200 bg-red-50/40 p-5 shadow-sm">
              <p className="text-xs font-semibold text-red-800 uppercase tracking-wider">Critical Urgency</p>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-red-900">{metrics.criticalPending}</span>
                <span className="text-xs text-red-700 font-medium">immediate threat</span>
              </div>
              <p className="mt-2 text-[11px] text-red-800">Payment scams / active credentials</p>
            </div>

            <div className="rounded-lg border border-emerald-200 bg-emerald-50/40 p-5 shadow-sm">
              <p className="text-xs font-semibold text-emerald-800 uppercase tracking-wider">Resolved Cases</p>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-emerald-900">{metrics.resolvedIncidents}</span>
                <span className="text-xs text-emerald-700 font-medium">contained</span>
              </div>
              <p className="mt-2 text-[11px] text-emerald-800">Advisories sent & domains sinkholed</p>
            </div>

          </div>

          {/* Severity & Threat Category Distributions */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Severity Distribution */}
            <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm space-y-4">
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                Threat Severity Distribution
              </h2>
              <div className="space-y-3 pt-2">
                <div>
                  <div className="flex justify-between text-xs font-medium text-slate-700 mb-1">
                    <span className="text-red-700 font-bold">Critical Urgency</span>
                    <span>{metrics.severityDistribution.critical} cases</span>
                  </div>
                  <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-red-600 h-full"
                      style={{
                        width: `${(metrics.severityDistribution.critical / metrics.totalIncidents) * 100}%`,
                      }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-medium text-slate-700 mb-1">
                    <span className="text-amber-700 font-bold">High Risk</span>
                    <span>{metrics.severityDistribution.high} cases</span>
                  </div>
                  <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-amber-600 h-full"
                      style={{
                        width: `${(metrics.severityDistribution.high / metrics.totalIncidents) * 100}%`,
                      }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-medium text-slate-700 mb-1">
                    <span className="text-slate-800 font-medium">Medium</span>
                    <span>{metrics.severityDistribution.medium} cases</span>
                  </div>
                  <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-slate-500 h-full"
                      style={{
                        width: `${(metrics.severityDistribution.medium / metrics.totalIncidents) * 100}%`,
                      }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-medium text-slate-700 mb-1">
                    <span className="text-slate-600 font-medium">Low</span>
                    <span>{metrics.severityDistribution.low} cases</span>
                  </div>
                  <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-slate-400 h-full"
                      style={{
                        width: `${(metrics.severityDistribution.low / metrics.totalIncidents) * 100}%`,
                      }}
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Category Breakdown */}
            <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm space-y-4">
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                Threat Breakdown by Category
              </h2>
              <div className="divide-y divide-slate-100 pt-1">
                {metrics.categoryBreakdown.map((cat, i) => (
                  <div key={i} className="py-2.5 flex items-center justify-between text-xs">
                    <span className="font-medium text-slate-800">{cat.label}</span>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-slate-900 bg-slate-100 px-2 py-0.5 rounded">
                        {cat.count}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

          </div>

          {/* Recent Audit Timeline Feed */}
          <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                Live SOC Audit & Case Activity
              </h2>
              <span className="text-[11px] text-slate-400">Recorded via backend audit logger</span>
            </div>

            <div className="divide-y divide-slate-100">
              {metrics.recentActivity.map((aud, i) => (
                <div key={i} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-900">{aud.actor}</span>
                      <span className="text-[10px] uppercase font-bold text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded">
                        {aud.actorRole}
                      </span>
                      <span className="font-mono text-[11px] text-blue-700 font-semibold">{aud.action}</span>
                    </div>
                    <p className="text-slate-600 text-xs">{aud.details}</p>
                  </div>
                  <span className="text-[11px] text-slate-400 shrink-0">
                    {new Date(aud.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

    </div>
  );
}
