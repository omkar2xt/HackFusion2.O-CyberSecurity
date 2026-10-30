"use client";

import React, { useState } from "react";
import Link from "next/link";
import { ChevronRightIcon, ScanIcon, AlertCircleIcon, ShieldIcon, CheckCircleIcon, LockIcon } from "../components/Icons";

const MITHA_PORTRAIT =
  "https://images.higgs.ai/?default=1&output=webp&url=https%3A%2F%2Fd8j0ntlcm91z4.cloudfront.net%2Fuser_38xzZboKViGWJOttwIXH07lWA1P%2Fhf_20260728_050334_5b076e26-0ce7-4898-b432-d764190e448f.png&w=1280&q=85";

export default function HomePage() {
  const [activeAdvisory] = useState({
    id: "ADV-2026-04",
    title: "Advisory: Fraudulent Mess Fee Refund SMS and WhatsApp Messages",
    date: "October 30, 2026",
    summary:
      "A circulating SMS directs students to 'campus-portal-refunds.org' to collect semester mess refunds. This is an unauthorized phishing campaign. Do not enter credentials or bank account details.",
  });

  return (
    <div className="relative w-full">
      
      {/* SECTION ONE — HERO */}
      <section className="min-h-screen supports-[height:100svh]:min-h-[100svh] flex flex-col justify-between px-5 sm:px-8 md:px-12 pt-24 sm:pt-28 pb-12 md:pb-16 max-w-7xl mx-auto">
        
        {/* Top Row */}
        <div className="flex flex-col gap-8 sm:flex-row justify-between items-start">
          {/* Left — service list */}
          <div className="flex flex-col gap-2">
            <span className="font-mono text-xs uppercase tracking-[0.15em] text-white/90 drop-shadow-md">
              / THREAT RECOGNITION
            </span>
            <span className="font-mono text-xs uppercase tracking-[0.15em] text-white/90 drop-shadow-md">
              / AI PHISHING DETECTION
            </span>
            <span className="font-mono text-xs uppercase tracking-[0.15em] text-white/90 drop-shadow-md">
              / INCIDENT TRIAGE & FORENSICS
            </span>
          </div>

          {/* Right — intro */}
          <div className="max-w-xs sm:text-right">
            <p className="text-lg sm:text-xl leading-relaxed text-white drop-shadow-md font-normal">
              We design intelligence that brings clarity, precision, and efficiency to the way your campus community operates.
            </p>
          </div>
        </div>

        {/* Bottom Row */}
        <div className="flex flex-col gap-8 md:flex-row items-end justify-between mt-16 sm:mt-24">
          {/* Left Title Area */}
          <div className="max-w-2xl">
            {/* Left-accent badge */}
            <div className="inline-block border-l-2 border-white bg-white/15 px-3 py-1.5 backdrop-blur-md mb-5">
              <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/90">
                Securing 100+ Campus Platforms
              </span>
            </div>

            <h1 className="text-5xl sm:text-6xl lg:text-7xl font-normal leading-[1.05] tracking-tight text-white drop-shadow-lg">
              Clear. Precise. <br />
              Automated.
            </h1>
          </div>

          {/* Right — Glass Contact Card */}
          <div className="flex items-center gap-4 rounded-xl border border-white/20 bg-white/15 p-3 backdrop-blur-md shadow-2xl">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={MITHA_PORTRAIT}
              alt="Mitha, co-founder of NovaAI"
              className="h-24 w-20 rounded-lg object-cover"
            />
            <div className="flex flex-col gap-1.5 pr-2">
              <span className="text-sm font-medium text-white drop-shadow-sm">Talk with Mitha</span>
              <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">
                Co-founder of NovaAI
              </span>
              <Link
                href="/scan"
                className="inline-flex items-center gap-1.5 rounded-full bg-white px-4 py-2 text-xs font-medium text-black hover:bg-white/85 transition-colors mt-1.5 shadow-sm"
              >
                <span>Launch Scanner</span>
                <ChevronRightIcon className="h-3.5 w-3.5" />
              </Link>
            </div>
          </div>
        </div>

      </section>

      {/* MID SPACER — Crucial for scroll video scrub length */}
      <div className="h-[80vh]" aria-hidden="true" />

      {/* SECTION TWO — CAPABILITY */}
      <section className="min-h-screen supports-[height:100svh]:min-h-[100svh] flex flex-col justify-between px-5 sm:px-8 md:px-12 pt-24 sm:pt-28 pb-12 md:pb-16 max-w-7xl mx-auto">
        
        {/* Top Row */}
        <div className="flex flex-col gap-8 sm:flex-row justify-between items-start">
          <div className="inline-block border-l-2 border-white bg-white/15 px-3 py-1.5 backdrop-blur-md">
            <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/90">
              Insight On Demand
            </span>
          </div>

          <div className="max-w-sm sm:text-right">
            <p className="text-lg sm:text-xl leading-relaxed text-white drop-shadow-md font-normal">
              Our AI doesn&apos;t just respond — it interprets, sharpens, and delivers the signal you need.
            </p>
          </div>
        </div>

        {/* Bottom Area */}
        <div className="flex-1 flex flex-col justify-end mt-16 sm:mt-24">
          <div className="flex flex-col gap-12 md:flex-row items-end justify-between gap-16">
            
            {/* Left Column */}
            <div className="max-w-xl">
              <h2 className="text-5xl sm:text-6xl lg:text-7xl font-normal leading-[1.05] tracking-tight text-white drop-shadow-lg">
                Learn to see <br />
                brilliantly.
              </h2>
              <p className="mt-6 max-w-md text-sm sm:text-base text-white/80 drop-shadow-md leading-relaxed">
                From the first suspicious URL to the final forensic render, SignalSafe turns raw intent into decisions your campus team can act on — quietly, precisely, at speed.
              </p>
              <div className="mt-8 flex flex-wrap gap-3">
                <Link
                  href="/scan"
                  className="inline-flex items-center gap-1.5 rounded-full bg-white px-5 py-2.5 text-xs sm:text-sm font-medium text-black hover:bg-white/85 transition-colors shadow-sm"
                >
                  <span>Run the scanner</span>
                  <ChevronRightIcon className="h-3.5 w-3.5" />
                </Link>
                <Link
                  href="/report"
                  className="inline-flex items-center gap-1.5 rounded-full border border-white/25 bg-white/10 backdrop-blur-md px-5 py-2.5 text-xs sm:text-sm text-white hover:bg-white/20 transition-colors"
                >
                  <span>Report incident</span>
                </Link>
              </div>
            </div>

            {/* Right — Frosted Capability Panel */}
            <div className="w-full max-w-md rounded-2xl border border-white/15 bg-white/10 backdrop-blur-md px-5 sm:px-6 shadow-2xl">
              
              <div className="flex gap-5 py-5 border-b border-white/15 group">
                <span className="font-mono text-[11px] tracking-[0.15em] text-white/55">01</span>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-base sm:text-lg font-medium text-white">Real-time vision</span>
                    <ChevronRightIcon className="h-4 w-4 text-white/40 group-hover:translate-x-0.5 group-hover:text-white transition-all" />
                  </div>
                  <p className="mt-1.5 text-sm leading-relaxed text-white/70">
                    Reads context as it happens and surfaces threat vectors before users can interact.
                  </p>
                </div>
              </div>

              <div className="flex gap-5 py-5 border-b border-white/15 group">
                <span className="font-mono text-[11px] tracking-[0.15em] text-white/55">02</span>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-base sm:text-lg font-medium text-white">Layered insight</span>
                    <ChevronRightIcon className="h-4 w-4 text-white/40 group-hover:translate-x-0.5 group-hover:text-white transition-all" />
                  </div>
                  <p className="mt-1.5 text-sm leading-relaxed text-white/70">
                    Moves from rough domain heuristics to sharp forensic output with tamper-proof evidence.
                  </p>
                </div>
              </div>

              <div className="flex gap-5 py-5 group">
                <span className="font-mono text-[11px] tracking-[0.15em] text-white/55">03</span>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-base sm:text-lg font-medium text-white">Adaptive speed</span>
                    <ChevronRightIcon className="h-4 w-4 text-white/40 group-hover:translate-x-0.5 group-hover:text-white transition-all" />
                  </div>
                  <p className="mt-1.5 text-sm leading-relaxed text-white/70">
                    Automates incident triage velocity and tightens campus response times across every department.
                  </p>
                </div>
              </div>

            </div>

          </div>
        </div>

      </section>

      {/* SECTION THREE — LIVE CAMPUS SECURITY HUB */}
      <section className="px-5 sm:px-8 md:px-12 py-16 max-w-7xl mx-auto space-y-8">
        
        {/* Active Advisory Banner in Frosted Glass */}
        <div className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-5 backdrop-blur-md shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className="mt-0.5 rounded-full bg-amber-400/20 p-1.5 text-amber-300">
              <AlertCircleIcon className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-white text-sm">{activeAdvisory.title}</span>
                <span className="rounded bg-amber-400/20 px-2 py-0.5 font-mono text-[10px] font-bold text-amber-300 tracking-wider uppercase border border-amber-400/30">
                  ACTIVE
                </span>
              </div>
              <p className="mt-1 text-xs text-white/70 leading-relaxed max-w-2xl">{activeAdvisory.summary}</p>
            </div>
          </div>
          <Link
            href="/scan"
            className="self-start sm:self-center shrink-0 rounded-full border border-amber-400/40 bg-amber-400/10 px-4 py-2 font-mono text-xs uppercase tracking-[0.1em] text-amber-200 hover:bg-amber-400/20 transition-colors"
          >
            Scan Suspicious Link
          </Link>
        </div>

        {/* 3-Step Campus Defense in Frosted Glass */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          
          <div className="rounded-2xl border border-white/15 bg-white/10 p-6 backdrop-blur-md shadow-xl flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-white/20 bg-white/15 text-white">
                <ScanIcon className="h-5 w-5" />
              </div>
              <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">Step 01</span>
              <h3 className="font-medium text-white text-lg">Recognize</h3>
              <p className="text-xs text-white/70 leading-relaxed">
                Submit suspicious links, email headers, SMS text, or QR destinations to detect domain age, typosquatting, and payment coercion patterns.
              </p>
            </div>
            <div className="mt-6 pt-4 border-t border-white/10">
              <Link href="/scan" className="text-xs font-mono uppercase tracking-[0.15em] text-white hover:text-white/80 inline-flex items-center gap-1">
                Open Scanner <ChevronRightIcon className="h-3 w-3" />
              </Link>
            </div>
          </div>

          <div className="rounded-2xl border border-white/15 bg-white/10 p-6 backdrop-blur-md shadow-xl flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-white/20 bg-white/15 text-white">
                <ShieldIcon className="h-5 w-5" />
              </div>
              <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">Step 02</span>
              <h3 className="font-medium text-white text-lg">Resist</h3>
              <p className="text-xs text-white/70 leading-relaxed">
                Receive plain-language explainability breakdowns. Learn exactly why a destination is untrusted and get clear safety directives before taking action.
              </p>
            </div>
            <div className="mt-6 pt-4 border-t border-white/10">
              <span className="text-xs font-mono uppercase tracking-[0.15em] text-white/50">Contextual Defense</span>
            </div>
          </div>

          <div className="rounded-2xl border border-white/15 bg-white/10 p-6 backdrop-blur-md shadow-xl flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-white/20 bg-white/15 text-white">
                <AlertCircleIcon className="h-5 w-5" />
              </div>
              <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">Step 03</span>
              <h3 className="font-medium text-white text-lg">Report</h3>
              <p className="text-xs text-white/70 leading-relaxed">
                Securely escalate threats to the Campus Incident Response Team (CIRT). Preserve digital evidence, attach screenshots, or submit sensitive reports anonymously.
              </p>
            </div>
            <div className="mt-6 pt-4 border-t border-white/10">
              <Link href="/report" className="text-xs font-mono uppercase tracking-[0.15em] text-white hover:text-white/80 inline-flex items-center gap-1">
                File a Report <ChevronRightIcon className="h-3 w-3" />
              </Link>
            </div>
          </div>

        </div>

        {/* Guarantees bar */}
        <div className="rounded-xl border border-white/10 bg-white/5 p-4 backdrop-blur-sm flex flex-col sm:flex-row items-center justify-between text-xs text-white/60 gap-3">
          <div className="flex items-center gap-2">
            <CheckCircleIcon className="h-4 w-4 text-emerald-400" />
            <span>Strict privacy: No background browser history or private chat monitoring.</span>
          </div>
          <div className="flex items-center gap-2">
            <LockIcon className="h-4 w-4 text-white/60" />
            <span>Tamper-proof SHA-256 evidence hashing on report submission.</span>
          </div>
        </div>

        {/* Complete Campus Platform Directory */}
        <div className="rounded-2xl border border-white/15 bg-white/10 p-6 sm:p-8 backdrop-blur-md shadow-2xl mt-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-white/15 pb-4 mb-6">
            <div>
              <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-white/60">
                Quick Platform Access
              </span>
              <h4 className="text-lg font-normal text-white mt-0.5">Explore All Pages & Workflows</h4>
            </div>
            <span className="font-mono text-[10px] text-white/40 uppercase tracking-wider mt-2 sm:mt-0">
              SignalSafe v1.0.0 Architecture
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Link
              href="/scan"
              className="p-4 rounded-xl border border-white/10 bg-white/5 hover:bg-white/15 hover:border-white/25 transition-all group"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-xs uppercase tracking-wider text-white font-semibold">
                  Threat Scanner
                </span>
                <ChevronRightIcon className="h-3.5 w-3.5 text-white/40 group-hover:translate-x-1 transition-transform" />
              </div>
              <p className="text-[11px] text-white/70">
                URL inspector, coercive SMS/message analyzer, and QR / quishing decoder.
              </p>
              <span className="inline-block mt-3 font-mono text-[9px] uppercase px-2 py-0.5 rounded-full bg-white/10 text-white/80">
                /scan
              </span>
            </Link>

            <Link
              href="/report"
              className="p-4 rounded-xl border border-white/10 bg-white/5 hover:bg-white/15 hover:border-white/25 transition-all group"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-xs uppercase tracking-wider text-white font-semibold">
                  Report Incident
                </span>
                <ChevronRightIcon className="h-3.5 w-3.5 text-white/40 group-hover:translate-x-1 transition-transform" />
              </div>
              <p className="text-[11px] text-white/70">
                Submit suspicious links, fake payment VPAs, or credential harvesting campaigns.
              </p>
              <span className="inline-block mt-3 font-mono text-[9px] uppercase px-2 py-0.5 rounded-full bg-white/10 text-white/80">
                /report
              </span>
            </Link>

            <Link
              href="/admin"
              className="p-4 rounded-xl border border-white/10 bg-white/5 hover:bg-white/15 hover:border-white/25 transition-all group"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-xs uppercase tracking-wider text-white font-semibold">
                  SOC Console
                </span>
                <ChevronRightIcon className="h-3.5 w-3.5 text-white/40 group-hover:translate-x-1 transition-transform" />
              </div>
              <p className="text-[11px] text-white/70">
                Campus-wide threat metrics, triage velocity, and hybrid detection rules catalog.
              </p>
              <span className="inline-block mt-3 font-mono text-[9px] uppercase px-2 py-0.5 rounded-full bg-white/10 text-white/80">
                /admin
              </span>
            </Link>

            <Link
              href="/admin/incidents"
              className="p-4 rounded-xl border border-white/10 bg-white/5 hover:bg-white/15 hover:border-white/25 transition-all group"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-xs uppercase tracking-wider text-white font-semibold">
                  Incident Queue
                </span>
                <ChevronRightIcon className="h-3.5 w-3.5 text-white/40 group-hover:translate-x-1 transition-transform" />
              </div>
              <p className="text-[11px] text-white/70">
                Security operations queue to filter, assign, triage, and close reported threats.
              </p>
              <span className="inline-block mt-3 font-mono text-[9px] uppercase px-2 py-0.5 rounded-full bg-white/10 text-white/80">
                /admin/incidents
              </span>
            </Link>
          </div>
        </div>

      </section>

    </div>
  );
}
