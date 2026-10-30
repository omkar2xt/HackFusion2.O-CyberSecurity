import React from "react";
import Link from "next/link";
import { HexagonIcon, LockIcon } from "./Icons";

export function Footer() {
  return (
    <footer className="border-t border-white/15 bg-[#0a0a0a]/80 backdrop-blur-md text-white/70 text-xs mt-auto">
      <div className="mx-auto max-w-7xl px-5 sm:px-8 md:px-12 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          
          <div className="space-y-3">
            <div className="flex items-center gap-2.5">
              <HexagonIcon className="h-5 w-5 text-white" strokeWidth={1.5} />
              <div className="flex items-baseline gap-1.5">
                <span className="font-medium text-white text-base">novaai</span>
                <span className="font-mono text-[10px] text-white/50 uppercase tracking-[0.15em]">/ signalsafe</span>
              </div>
            </div>
            <p className="text-white/60 text-xs leading-relaxed">
              Institutional digital threat recognition, heuristic analysis, and rapid incident response system for students, faculty, and administration.
            </p>
          </div>

          <div>
            <h4 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-3">Threat Operations</h4>
            <ul className="space-y-2">
              <li>
                <Link href="/scan" className="hover:text-white transition-colors">
                  Phishing & URL Scanner
                </Link>
              </li>
              <li>
                <Link href="/report" className="hover:text-white transition-colors">
                  Submit Incident Report
                </Link>
              </li>
              <li>
                <Link href="/my-reports" className="hover:text-white transition-colors">
                  My Incident History
                </Link>
              </li>
              <li>
                <Link href="/admin" className="hover:text-white transition-colors">
                  SOC Admin Console
                </Link>
              </li>
            </ul>
          </div>

          <div>
            <h4 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-3">Compliance & Ethics</h4>
            <ul className="space-y-2">
              <li>
                <Link href="/privacy" className="hover:text-white transition-colors">
                  Privacy Policy & Data Retention
                </Link>
              </li>
              <li>
                <Link href="/terms" className="hover:text-white transition-colors">
                  Terms of Service & Usage
                </Link>
              </li>
              <li>
                <span className="text-white/40">Anonymous Reporting Protocol</span>
              </li>
              <li>
                <span className="text-white/40">Zero Background Surveillance</span>
              </li>
            </ul>
          </div>

          <div>
            <h4 className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/80 mb-3">Campus Emergency</h4>
            <div className="rounded-xl border border-white/15 bg-white/10 p-4 backdrop-blur-md space-y-1.5 shadow-lg">
              <p className="font-medium text-white text-xs">Campus CIRT Hotline</p>
              <p className="font-mono text-white/80 text-xs">+1 (555) 019-CIRT</p>
              <p className="text-[11px] text-white/50">cirt-emergency@campus.edu</p>
              <div className="flex items-center gap-1.5 pt-1 text-[11px] text-white/60">
                <LockIcon className="w-3 h-3 text-emerald-400" />
                <span>Encrypted Evidence Vault</span>
              </div>
            </div>
          </div>

        </div>

        <div className="mt-12 pt-6 border-t border-white/10 flex flex-col sm:flex-row items-center justify-between text-white/40 text-[11px] gap-2">
          <p>© 2026 SignalSafe Campus • NovaAI Design System. All rights reserved.</p>
          <p>
            Explicit User-Submitted Scans Only • End-to-End Audit Logged
          </p>
        </div>
      </div>
    </footer>
  );
}
