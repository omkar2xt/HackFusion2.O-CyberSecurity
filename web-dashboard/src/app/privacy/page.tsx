import React from "react";
import Link from "next/link";

export default function PrivacyPolicyPage() {
  return (
    <div className="mx-auto max-w-4xl px-5 sm:px-8 md:px-12 py-12 space-y-8 text-white">
      
      <div>
        <div className="inline-block border-l-2 border-white bg-white/15 px-3 py-1.5 backdrop-blur-md mb-3">
          <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/90">
            Campus Data Protection
          </span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-normal tracking-tight text-white drop-shadow-md">
          Privacy Policy & Data Retention
        </h1>
        <p className="mt-1 font-mono text-[10px] text-white/50 uppercase tracking-wider">
          Effective Date: October 2026 • SignalSafe Campus Protocol
        </p>
      </div>

      <div className="rounded-2xl border border-white/15 bg-white/10 p-6 sm:p-8 backdrop-blur-md shadow-2xl space-y-6 text-xs text-white/80 leading-relaxed">
        
        <section className="space-y-2">
          <h2 className="text-sm font-medium text-white">1. Principle of Explicit User Submission</h2>
          <p>
            SignalSafe Campus operates strictly on explicit user action. The system does not silently inspect browsing history, intercept private communications, or monitor student devices in the background. Data is analyzed solely when a user pastes a URL, submits message text, or files an incident report.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-sm font-medium text-white">2. Anonymous Incident Reporting</h2>
          <p>
            When a user selects the <strong>Anonymous Submission</strong> option on the incident reporting form, all personally identifiable markers (student name, email, roll number, and IP address) are stripped from the incident record before transmission to the security triage queue.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-sm font-medium text-white">3. Cryptographic Evidence Vault</h2>
          <p>
            Files uploaded as evidence (such as email headers or screenshots) are hashed with SHA-256 upon intake and stored in an isolated, encrypted campus storage bucket with restricted role-based access controls (RBAC). Evidence is preserved solely for forensic investigation by authorized Campus Incident Response Team (CIRT) personnel.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-sm font-medium text-white">4. Retention and Disposal Policy</h2>
          <p>
            Automated scan outputs with zero threat indicators are pruned after 30 days. Incident records related to active security investigations are retained according to university compliance guidelines (minimum 180 days) and purged securely thereafter.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-sm font-medium text-white">5. Contact Information</h2>
          <p>
            Questions regarding campus privacy protections can be directed to the University Data Privacy Officer at <span className="font-mono text-white">privacy@campus.edu</span>.
          </p>
        </section>

      </div>

      <div>
        <Link href="/" className="font-mono text-xs uppercase tracking-[0.1em] text-white hover:text-white/80 underline">
          ← Return to SignalSafe Campus Home
        </Link>
      </div>

    </div>
  );
}
