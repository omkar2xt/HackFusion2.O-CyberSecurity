import React from "react";
import Link from "next/link";
import { LockIcon } from "../../components/Icons";

export default function PrivacyPolicyPage() {
  return (
    <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8 py-10 space-y-8">
      
      <div>
        <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">
          <LockIcon className="h-4 w-4 text-slate-700" />
          <span>Campus Data Protection</span>
        </div>
        <h1 className="text-3xl font-bold text-slate-900 tracking-tight">Privacy Policy & Data Retention</h1>
        <p className="mt-1 text-xs text-slate-500">Effective Date: October 2026 • SignalSafe Campus Protocol</p>
      </div>

      <div className="rounded-lg border border-slate-200 bg-white p-6 sm:p-8 shadow-sm space-y-6 text-xs text-slate-700 leading-relaxed">
        
        <section className="space-y-2">
          <h2 className="text-sm font-bold text-slate-900">1. Principle of Explicit User Submission</h2>
          <p>
            SignalSafe Campus operates strictly on explicit user action. The system does not silently inspect browsing history, intercept private communications, or monitor student devices in the background. Data is analyzed solely when a user pastes a URL, submits message text, or files an incident report.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-sm font-bold text-slate-900">2. Anonymous Incident Reporting</h2>
          <p>
            When a user selects the <strong>Anonymous Submission</strong> option on the incident reporting form, all personally identifiable markers (student name, email, roll number, and IP address) are stripped from the incident record before transmission to the security triage queue.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-sm font-bold text-slate-900">3. Cryptographic Evidence Vault</h2>
          <p>
            Files uploaded as evidence (such as email headers or screenshots) are hashed with SHA-256 upon intake and stored in an isolated, encrypted campus storage bucket with restricted role-based access controls (RBAC). Evidence is preserved solely for forensic investigation by authorized Campus Incident Response Team (CIRT) personnel.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-sm font-bold text-slate-900">4. Retention and Disposal Policy</h2>
          <p>
            Automated scan outputs with zero threat indicators are pruned after 30 days. Incident records related to active security investigations are retained according to university compliance guidelines (minimum 180 days) and purged securely thereafter.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-sm font-bold text-slate-900">5. Contact Information</h2>
          <p>
            Questions regarding campus privacy protections can be directed to the University Data Privacy Officer at <span className="font-mono text-slate-900">privacy@campus.edu</span>.
          </p>
        </section>

      </div>

      <div>
        <Link href="/" className="text-xs font-semibold text-slate-900 underline">
          ← Return to SignalSafe Campus Home
        </Link>
      </div>

    </div>
  );
}
