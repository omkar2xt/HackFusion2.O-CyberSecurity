import React from "react";
import Link from "next/link";
import { ShieldIcon, LockIcon } from "./Icons";

export function Footer() {
  return (
    <footer className="border-t border-slate-200 bg-white text-slate-600 text-xs mt-auto">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <div className="flex h-6 w-6 items-center justify-center rounded bg-slate-900 text-white">
                <ShieldIcon className="h-3.5 w-3.5" />
              </div>
              <span className="font-semibold text-slate-900 text-sm">SignalSafe Campus</span>
            </div>
            <p className="text-slate-500 text-xs leading-relaxed">
              Institutional digital threat recognition, analysis, and rapid incident response system for students, faculty, and administration.
            </p>
          </div>

          <div>
            <h4 className="font-semibold text-slate-900 text-xs uppercase tracking-wider mb-3">Threat Response</h4>
            <ul className="space-y-2">
              <li>
                <Link href="/scan" className="hover:text-slate-900 transition-colors">
                  Phishing & URL Scanner
                </Link>
              </li>
              <li>
                <Link href="/report" className="hover:text-slate-900 transition-colors">
                  Submit Incident Report
                </Link>
              </li>
              <li>
                <Link href="/my-reports" className="hover:text-slate-900 transition-colors">
                  Check Incident Status
                </Link>
              </li>
              <li>
                <Link href="/admin" className="hover:text-slate-900 transition-colors">
                  SOC Admin Portal
                </Link>
              </li>
            </ul>
          </div>

          <div>
            <h4 className="font-semibold text-slate-900 text-xs uppercase tracking-wider mb-3">Compliance & Ethics</h4>
            <ul className="space-y-2">
              <li>
                <Link href="/privacy" className="hover:text-slate-900 transition-colors">
                  Privacy Policy & Data Retention
                </Link>
              </li>
              <li>
                <Link href="/terms" className="hover:text-slate-900 transition-colors">
                  Terms of Service & Usage
                </Link>
              </li>
              <li>
                <span className="text-slate-500">Anonymous Reporting Protocol</span>
              </li>
              <li>
                <span className="text-slate-500">Zero Background Surveillance</span>
              </li>
            </ul>
          </div>

          <div>
            <h4 className="font-semibold text-slate-900 text-xs uppercase tracking-wider mb-3">Campus Emergency</h4>
            <div className="rounded border border-slate-200 bg-slate-50 p-3 space-y-1">
              <p className="font-medium text-slate-800 text-xs">Campus CIRT Hotline</p>
              <p className="font-mono text-slate-600 text-xs">+1 (555) 019-CIRT</p>
              <p className="text-[11px] text-slate-500">cirt-emergency@campus.edu</p>
              <div className="flex items-center gap-1.5 pt-1 text-[11px] text-slate-500">
                <LockIcon className="w-3 h-3 text-emerald-600" />
                <span>Encrypted Evidence Vault</span>
              </div>
            </div>
          </div>

        </div>

        <div className="mt-8 pt-6 border-t border-slate-100 flex flex-col sm:flex-row items-center justify-between text-slate-400 text-[11px]">
          <p>© 2026 SignalSafe Campus. Developed for HackFusion 2.0. All rights reserved.</p>
          <p className="mt-2 sm:mt-0">
            Explicit User-Submitted Scans Only • End-to-End Audit Logged
          </p>
        </div>
      </div>
    </footer>
  );
}
