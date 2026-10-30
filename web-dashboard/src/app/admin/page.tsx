"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "../../lib/auth-context";
import { apiClient } from "../../services/api";
import { AdminMetrics } from "../../lib/types";
import {
  ShieldIcon,
  LockIcon,
  ChevronRightIcon,
  ActivityIcon,
  ScanIcon,
  QrCodeIcon,
  CheckCircleIcon,
} from "../../components/Icons";
import { SkeletonCard } from "../../components/SkeletonLoader";

type AdminTab = "metrics" | "engine";

export default function AdminDashboardPage() {
  const { role, switchRole } = useAuth();
  const [metrics, setMetrics] = useState<AdminMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<AdminTab>("metrics");

  useEffect(() => {
    // Seamless demo access: auto-promote to security_admin when accessing the SOC Console
    if (role && role !== "security_admin") {
      switchRole("security_admin");
    }
  }, [role, switchRole]);

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
  }, [role]);

  if (role !== "security_admin") {
    return (
      <div className="mx-auto max-w-xl px-5 py-20 text-center space-y-6">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-white/20 bg-white/10 text-white shadow-xl">
          <LockIcon className="h-7 w-7" />
        </div>
        <div className="space-y-2">
          <h1 className="text-2xl font-normal text-white">Restricted Security Console</h1>
          <p className="text-xs text-white/60 leading-relaxed max-w-md mx-auto">
            Access to campus-wide threat telemetry and incident triage is restricted to the Campus Incident Response Team (CIRT). Active role:{" "}
            <span className="font-mono uppercase text-white font-semibold">{role || "Guest"}</span>.
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
      
      {/* Executive Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/15 pb-6">
        <div>
          <div className="inline-block border-l-2 border-white bg-white/15 px-3 py-1.5 backdrop-blur-md mb-3">
            <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/90">
              Campus Incident Response Team (CIRT)
            </span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-normal tracking-tight text-white drop-shadow-md">
            Security Operations Console
          </h1>
          <p className="mt-1 text-sm text-white/70">
            Real-time threat telemetry, triage velocity, and authoritative detection engine oversight.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/admin/incidents"
            className="rounded-full bg-white px-5 py-2.5 text-xs font-medium text-black hover:bg-white/85 transition-colors shadow-lg inline-flex items-center gap-2"
          >
            <ShieldIcon className="h-4 w-4" />
            <span>Open Triage Queue</span>
            <ChevronRightIcon className="h-3.5 w-3.5" />
          </Link>
        </div>
      </div>

      {/* Admin View Tabs */}
      <div className="flex border-b border-white/15 gap-6 text-xs font-mono uppercase tracking-[0.15em]">
        <button
          type="button"
          onClick={() => setActiveTab("metrics")}
          className={`pb-3 border-b-2 flex items-center gap-2 transition-colors ${
            activeTab === "metrics"
              ? "border-white font-bold text-white"
              : "border-transparent text-white/50 hover:text-white/80"
          }`}
        >
          <ActivityIcon className="h-4 w-4" />
          <span>SOC Telemetry & Case Metrics</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("engine")}
          className={`pb-3 border-b-2 flex items-center gap-2 transition-colors ${
            activeTab === "engine"
              ? "border-white font-bold text-white"
              : "border-transparent text-white/50 hover:text-white/80"
          }`}
        >
          <ScanIcon className="h-4 w-4 text-emerald-400" />
          <span>Hybrid Detection Engine & Rules Catalog</span>
          <span className="rounded-full bg-emerald-500/20 border border-emerald-400/30 text-[9px] px-2 py-0.5 text-emerald-300">
            v1.0.0 Live
          </span>
        </button>
      </div>

      {loading || !metrics ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : activeTab === "metrics" ? (
        <>
          {/* KPI Metric Cards in Frosted Glass */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            
            <div className="rounded-2xl border border-white/15 bg-white/10 p-6 backdrop-blur-md shadow-xl">
              <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">Total Incidents</span>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-4xl font-light text-white">{metrics.totalIncidents}</span>
                <span className="font-mono text-xs text-white/40">all time</span>
              </div>
              <p className="mt-2 font-mono text-[10px] text-white/50">Cross-channel telemetry</p>
            </div>

            <div className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-6 backdrop-blur-md shadow-xl">
              <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-amber-200/80">Pending Triage</span>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-4xl font-light text-amber-200">{metrics.openIncidents}</span>
                <span className="font-mono text-xs text-amber-300/60">active cases</span>
              </div>
              <p className="mt-2 font-mono text-[10px] text-amber-200/60">Requires review or containment</p>
            </div>

            <div className="rounded-2xl border border-red-400/30 bg-red-500/10 p-6 backdrop-blur-md shadow-xl">
              <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-red-200/80">Critical Urgency</span>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-4xl font-light text-red-200">{metrics.criticalPending}</span>
                <span className="font-mono text-xs text-red-300/60">immediate threat</span>
              </div>
              <p className="mt-2 font-mono text-[10px] text-red-200/60">Credential & payment scams</p>
            </div>

            <div className="rounded-2xl border border-emerald-400/30 bg-emerald-500/10 p-6 backdrop-blur-md shadow-xl">
              <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-emerald-200/80">Resolved Cases</span>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-4xl font-light text-emerald-200">{metrics.resolvedIncidents}</span>
                <span className="font-mono text-xs text-emerald-300/60">contained</span>
              </div>
              <p className="mt-2 font-mono text-[10px] text-emerald-200/60">Advisories & firewall blocks</p>
            </div>

          </div>

          {/* Severity & Threat Category Distributions */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Severity Distribution */}
            <div className="rounded-2xl border border-white/15 bg-white/10 p-6 sm:p-8 backdrop-blur-md shadow-xl space-y-4">
              <h2 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80">
                Threat Severity Distribution
              </h2>
              <div className="space-y-4 pt-2">
                <div>
                  <div className="flex justify-between text-xs font-mono text-white/80 mb-1.5">
                    <span className="text-red-300">Critical Urgency</span>
                    <span>{metrics.severityDistribution.critical} cases</span>
                  </div>
                  <div className="w-full bg-white/10 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-red-400 h-full"
                      style={{
                        width: `${(metrics.severityDistribution.critical / (metrics.totalIncidents || 1)) * 100}%`,
                      }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono text-white/80 mb-1.5">
                    <span className="text-amber-300">High Risk</span>
                    <span>{metrics.severityDistribution.high} cases</span>
                  </div>
                  <div className="w-full bg-white/10 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-amber-400 h-full"
                      style={{
                        width: `${(metrics.severityDistribution.high / (metrics.totalIncidents || 1)) * 100}%`,
                      }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono text-white/80 mb-1.5">
                    <span className="text-white/80">Medium</span>
                    <span>{metrics.severityDistribution.medium} cases</span>
                  </div>
                  <div className="w-full bg-white/10 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-white/40 h-full"
                      style={{
                        width: `${(metrics.severityDistribution.medium / (metrics.totalIncidents || 1)) * 100}%`,
                      }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono text-white/80 mb-1.5">
                    <span className="text-white/60">Low</span>
                    <span>{metrics.severityDistribution.low} cases</span>
                  </div>
                  <div className="w-full bg-white/10 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-white/20 h-full"
                      style={{
                        width: `${(metrics.severityDistribution.low / (metrics.totalIncidents || 1)) * 100}%`,
                      }}
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Category Breakdown */}
            <div className="rounded-2xl border border-white/15 bg-white/10 p-6 sm:p-8 backdrop-blur-md shadow-xl space-y-4">
              <h2 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80">
                Threat Vectors by Category
              </h2>
              <div className="divide-y divide-white/10 pt-1">
                {metrics.categoryBreakdown.map((cat, i) => (
                  <div key={i} className="py-3 flex items-center justify-between text-xs">
                    <span className="text-white/80">{cat.label}</span>
                    <span className="font-mono text-xs font-bold text-white bg-white/10 border border-white/15 px-3 py-1 rounded-full">
                      {cat.count}
                    </span>
                  </div>
                ))}
              </div>
            </div>

          </div>

          {/* Live SOC Audit Feed */}
          <div className="rounded-2xl border border-white/15 bg-white/10 p-6 sm:p-8 backdrop-blur-md shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80">
                Live Incident Audit Telemetry
              </h2>
              <span className="font-mono text-[10px] text-white/40 uppercase tracking-wider">Automated Logger</span>
            </div>

            <div className="divide-y divide-white/10">
              {metrics.recentActivity.map((aud, i) => (
                <div key={i} className="py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2.5">
                      <span className="font-medium text-white">{aud.actor}</span>
                      <span className="font-mono text-[10px] uppercase tracking-wide text-white/50 bg-white/10 px-2 py-0.5 rounded-full border border-white/10">
                        {aud.actorRole}
                      </span>
                      <span className="font-mono text-[11px] text-white/90">{aud.action}</span>
                    </div>
                    <p className="text-white/70 text-xs">{aud.details}</p>
                  </div>
                  <span className="font-mono text-[10px] text-white/40 shrink-0">
                    {new Date(aud.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </>
      ) : (
        /* TAB 2: HYBRID DETECTION ENGINE & RULES CATALOG */
        <div className="space-y-6">
          
          {/* Engine Architecture Card */}
          <div className="rounded-2xl border border-white/15 bg-white/10 p-6 sm:p-8 backdrop-blur-md shadow-xl space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/15 pb-4">
              <div>
                <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-emerald-300">
                  Core Detection Pipeline
                </span>
                <h2 className="text-2xl font-normal text-white mt-1">Hybrid Detection Architecture</h2>
                <p className="text-xs text-white/70 mt-1">
                  Integrates deterministic rule evaluation, external threat intelligence feeds, ML model inference, and multimodal QR analysis.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-emerald-400/30 bg-emerald-500/10 text-emerald-200 text-xs font-mono">
                  <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                  Policy Version: v1.0.0
                </span>
              </div>
            </div>

            {/* The 4 Architectural Pillars */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              
              <div className="rounded-xl border border-white/15 bg-white/5 p-4 space-y-2">
                <div className="flex items-center gap-2 text-white">
                  <ScanIcon className="h-4 w-4 text-blue-400" />
                  <span className="font-mono text-xs uppercase tracking-wider font-semibold">34 URL Features</span>
                </div>
                <p className="text-xs text-white/70">
                  Normalizes schemes, decomposes subdomains, entropy, IP hosts, punycode homographs, and obfuscation tokens.
                </p>
                <div className="pt-2 text-[10px] font-mono text-white/50">Anti-Bias HTTPS Safeguards</div>
              </div>

              <div className="rounded-xl border border-white/15 bg-white/5 p-4 space-y-2">
                <div className="flex items-center gap-2 text-white">
                  <ShieldIcon className="h-4 w-4 text-emerald-400" />
                  <span className="font-mono text-xs uppercase tracking-wider font-semibold">Rule Engine</span>
                </div>
                <p className="text-xs text-white/70">
                  Deterministic heuristics with strict score capping (Max 65 pts) to prevent heuristic false-positive inflation.
                </p>
                <div className="pt-2 text-[10px] font-mono text-white/50">Rule Catalogue: 18 Fired Specs</div>
              </div>

              <div className="rounded-xl border border-white/15 bg-white/5 p-4 space-y-2">
                <div className="flex items-center gap-2 text-white">
                  <ActivityIcon className="h-4 w-4 text-amber-400" />
                  <span className="font-mono text-xs uppercase tracking-wider font-semibold">Threat Intel Feeds</span>
                </div>
                <p className="text-xs text-white/70">
                  Parallel asynchronous queries across Google Safe Browsing, VirusTotal, and URLhaus with TTL circuit breakers.
                </p>
                <div className="pt-2 text-[10px] font-mono text-white/50">300s In-Memory Cache</div>
              </div>

              <div className="rounded-xl border border-white/15 bg-white/5 p-4 space-y-2">
                <div className="flex items-center gap-2 text-white">
                  <QrCodeIcon className="h-4 w-4 text-purple-400" />
                  <span className="font-mono text-xs uppercase tracking-wider font-semibold">Multimodal QR / NLP</span>
                </div>
                <p className="text-xs text-white/70">
                  Decodes physical cafeteria placards, detects fake UPI VPA switches, rogue Wi-Fi configs, and message urgency cues.
                </p>
                <div className="pt-2 text-[10px] font-mono text-white/50">Quishing & Payload Defense</div>
              </div>

            </div>
          </div>

          {/* Active Heuristic Rules Catalog */}
          <div className="rounded-2xl border border-white/15 bg-white/10 p-6 sm:p-8 backdrop-blur-md shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-white/15 pb-4">
              <div>
                <h3 className="text-lg font-normal text-white">Active Detection Indicators</h3>
                <p className="text-xs text-white/60">
                  Deterministic rules evaluated across /api/v1/scan/url, /api/v1/scan/message, and /api/v1/scan/qr.
                </p>
              </div>
              <span className="font-mono text-[10px] text-white/50">Backend Rule Engine Spec</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
              {[
                {
                  code: "LOOKALIKE_HOST",
                  label: "Campus Portal Lookalike / Typo-Squatting",
                  desc: "Detects campus keywords on unauthorized TLDs or unregistered domains imitating university services.",
                  sev: "HIGH",
                },
                {
                  code: "RAW_IP_HOST",
                  label: "Raw IPv4 / IPv6 Destination",
                  desc: "Blocks destination addresses utilizing raw numeric IPs in place of registered institutional domain names.",
                  sev: "HIGH",
                },
                {
                  code: "PUNYCODE_HOMOGRAPH",
                  label: "Internationalized Domain (IDN) Punycode Homograph",
                  desc: "Identifies Cyrillic or unicode homoglyph character substitutions designed to spoof legitimate Latin campus URLs.",
                  sev: "CRITICAL",
                },
                {
                  code: "USERINFO_OBFUSCATION",
                  label: "URL Userinfo '@' Obfuscation Vector",
                  desc: "Detects embedded credentials and '@' symbols positioned to mislead users regarding the actual destination host.",
                  sev: "HIGH",
                },
                {
                  code: "DOUBLE_SLASH_EVASION",
                  label: "Path Double-Slash Navigation Evasion",
                  desc: "Catches protocol evasion tricks where multiple slashes are placed within path parameters to evade proxies.",
                  sev: "MEDIUM",
                },
                {
                  code: "NON_STANDARD_PORT",
                  label: "Non-Standard Web Service Port",
                  desc: "Flags web destinations bound to unusual ports (e.g. 8080, 8443, 8888, 10000) common in quick phishing kits.",
                  sev: "MEDIUM",
                },
                {
                  code: "URGENCY_LANGUAGE",
                  label: "Coercive Urgency & Social Engineering NLP",
                  desc: "Detects artificial time limits, threats of academic debarment, and payment deadlines used to bypass caution.",
                  sev: "MEDIUM",
                },
                {
                  code: "UNVERIFIED_PAYMENT",
                  label: "Unverified Quishing / UPI Redirect Intent",
                  desc: "Blocks physical QR codes initiating direct funds transfers without authenticated campus merchant identification.",
                  sev: "CRITICAL",
                },
              ].map((rule, idx) => (
                <div
                  key={idx}
                  className="rounded-xl border border-white/10 bg-white/5 p-4 flex items-start gap-3 text-xs"
                >
                  <CheckCircleIcon className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-white">{rule.label}</span>
                      <span
                        className={`font-mono text-[9px] uppercase px-1.5 py-0.2 rounded-full border ${
                          rule.sev === "CRITICAL"
                            ? "border-red-400/30 bg-red-500/20 text-red-300"
                            : rule.sev === "HIGH"
                            ? "border-amber-400/30 bg-amber-500/20 text-amber-300"
                            : "border-blue-400/30 bg-blue-500/20 text-blue-300"
                        }`}
                      >
                        {rule.sev}
                      </span>
                    </div>
                    <p className="font-mono text-[10px] text-white/50">{rule.code}</p>
                    <p className="text-white/70 text-xs leading-relaxed">{rule.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>
      )}

    </div>
  );
}
