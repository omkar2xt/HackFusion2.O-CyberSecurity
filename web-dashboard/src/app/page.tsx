"use client";

import React, { useState } from "react";
import Link from "next/link";
import { ShieldIcon, ScanIcon, AlertCircleIcon, LockIcon, ExternalLinkIcon, CheckCircleIcon } from "../components/Icons";

export default function HomePage() {
  const [activeAdvisory] = useState({
    id: "ADV-2026-04",
    title: "Advisory: Fraudulent Mess Fee Refund SMS and WhatsApp Messages",
    date: "October 30, 2026",
    summary:
      "A circulating SMS directs students to 'campus-portal-refunds.org' to collect semester mess refunds. This is an unauthorized phishing campaign. Do not enter credentials or bank account details.",
  });

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-10">
      
      {/* High Priority Active Campus Advisory Banner */}
      <div className="rounded-lg border border-amber-300 bg-amber-50/70 p-4 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-start gap-3">
            <div className="mt-0.5 rounded-full bg-amber-200/80 p-1 text-amber-900">
              <AlertCircleIcon className="h-4 w-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-amber-950 text-sm">{activeAdvisory.title}</span>
                <span className="rounded bg-amber-200 px-1.5 py-0.5 text-[10px] font-bold text-amber-900 tracking-wider">
                  ACTIVE
                </span>
              </div>
              <p className="mt-1 text-xs text-amber-900/90 leading-relaxed">{activeAdvisory.summary}</p>
            </div>
          </div>
          <Link
            href="/scan"
            className="self-start sm:self-center shrink-0 rounded border border-amber-400 bg-white px-3 py-1.5 text-xs font-semibold text-amber-950 hover:bg-amber-100/60 transition-colors"
          >
            Scan Suspicious Link
          </Link>
        </div>
      </div>

      {/* Hero & Executive Summary */}
      <div className="border-b border-slate-200 pb-10">
        <div className="max-w-3xl space-y-4">
          <div className="inline-flex items-center gap-2 rounded-full border border-slate-300 bg-white px-3 py-1 text-xs font-medium text-slate-700 shadow-2xs">
            <ShieldIcon className="h-3.5 w-3.5 text-slate-800" />
            <span>Campus Digital Threat Protection Protocol</span>
          </div>

          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-slate-900">
            Recognize, Resist, and Report Digital Threats Before They Cause Harm
          </h1>

          <p className="text-base text-slate-600 leading-relaxed">
            SignalSafe Campus provides instant detection for phishing emails, malicious portals,
            fraudulent QR payment codes, and social engineering targeting university students,
            faculty, and staff.
          </p>

          <div className="pt-2 flex flex-wrap gap-3">
            <Link
              href="/scan"
              className="inline-flex items-center gap-2 rounded-md bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 transition-colors shadow-sm"
            >
              <ScanIcon className="h-4 w-4" />
              Analyze Suspicious URL / Message
            </Link>

            <Link
              href="/report"
              className="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold text-slate-800 hover:bg-slate-50 transition-colors shadow-sm"
            >
              <AlertCircleIcon className="h-4 w-4 text-slate-600" />
              File Security Incident Report
            </Link>
          </div>
        </div>
      </div>

      {/* The 3 Core Pillars */}
      <div>
        <div className="mb-6">
          <h2 className="text-lg font-bold text-slate-900">The 3-Step Campus Defense Model</h2>
          <p className="text-xs text-slate-500">How SignalSafe protects the academic community at every stage of an encounter.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          
          <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-md bg-slate-100 text-slate-900 border border-slate-200">
                <ScanIcon className="h-5 w-5" />
              </div>
              <h3 className="font-semibold text-slate-900 text-base">1. Recognize</h3>
              <p className="text-xs text-slate-600 leading-relaxed">
                Submit suspicious links, email headers, SMS text, or QR codes. The detection engine extracts threat indicators, domain age, typosquatting, and payment coercion patterns.
              </p>
            </div>
            <div className="mt-6 pt-4 border-t border-slate-100">
              <Link href="/scan" className="text-xs font-semibold text-slate-900 hover:underline inline-flex items-center gap-1">
                Open Scanner <ExternalLinkIcon className="h-3 w-3" />
              </Link>
            </div>
          </div>

          <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-md bg-slate-100 text-slate-900 border border-slate-200">
                <ShieldIcon className="h-5 w-5" />
              </div>
              <h3 className="font-semibold text-slate-900 text-base">2. Resist</h3>
              <p className="text-xs text-slate-600 leading-relaxed">
                Receive plain-language explainability breakdowns. Learn exactly why a request is untrusted, inspect risk confidence scores, and get clear safety directives before taking action.
              </p>
            </div>
            <div className="mt-6 pt-4 border-t border-slate-100">
              <span className="text-xs font-medium text-slate-500">Real-time contextual coaching</span>
            </div>
          </div>

          <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-md bg-slate-100 text-slate-900 border border-slate-200">
                <AlertCircleIcon className="h-5 w-5" />
              </div>
              <h3 className="font-semibold text-slate-900 text-base">3. Report</h3>
              <p className="text-xs text-slate-600 leading-relaxed">
                Securely escalate threats to the Campus Incident Response Team (CIRT). Preserve digital evidence, attach screenshots, or submit sensitive reports anonymously.
              </p>
            </div>
            <div className="mt-6 pt-4 border-t border-slate-100">
              <Link href="/report" className="text-xs font-semibold text-slate-900 hover:underline inline-flex items-center gap-1">
                File a Report <ExternalLinkIcon className="h-3 w-3" />
              </Link>
            </div>
          </div>

        </div>
      </div>

      {/* Real Threat Matrix Section */}
      <div className="rounded-lg border border-slate-200 bg-white p-6 sm:p-8 shadow-sm space-y-6">
        <div>
          <h2 className="text-lg font-bold text-slate-900">Monitored Threat Vectors Across Campus</h2>
          <p className="text-xs text-slate-500">Categories prioritized by campus security operations.</p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="border border-slate-200 rounded p-4 bg-slate-50/50">
            <p className="font-semibold text-slate-900 text-sm">Credential Harvesting</p>
            <p className="text-xs text-slate-600 mt-1">Cloned portals imitating campus Single Sign-On (SSO), LMS, or grading portals.</p>
          </div>
          <div className="border border-slate-200 rounded p-4 bg-slate-50/50">
            <p className="font-semibold text-slate-900 text-sm">Payment & QR Tampering</p>
            <p className="text-xs text-slate-600 mt-1">Tampered cafeteria UPI QR codes, fake examination fee payment demands, and bogus stipends.</p>
          </div>
          <div className="border border-slate-200 rounded p-4 bg-slate-50/50">
            <p className="font-semibold text-slate-900 text-sm">Faculty Impersonation</p>
            <p className="text-xs text-slate-600 mt-1">Spoofed emails from Deans or Professors requesting urgent gift cards or emergency transfers.</p>
          </div>
          <div className="border border-slate-200 rounded p-4 bg-slate-50/50">
            <p className="font-semibold text-slate-900 text-sm">Harassment & Bullying</p>
            <p className="text-xs text-slate-600 mt-1">Hostile communications with dedicated anonymous reporting and encrypted evidence preservation.</p>
          </div>
        </div>

        <div className="border-t border-slate-100 pt-4 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-2">
          <div className="flex items-center gap-2">
            <CheckCircleIcon className="h-4 w-4 text-emerald-600" />
            <span>Strict privacy: No background browser history or private chat monitoring.</span>
          </div>
          <div className="flex items-center gap-2">
            <LockIcon className="h-4 w-4 text-slate-600" />
            <span>Tamper-proof evidence hashing on report submission.</span>
          </div>
        </div>
      </div>

    </div>
  );
}
