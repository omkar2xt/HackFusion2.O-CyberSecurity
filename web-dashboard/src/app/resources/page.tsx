"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  BookOpenIcon,
  ShieldIcon,
  AlertCircleIcon,
  CheckCircleIcon,
  LockIcon,
  GlobeIcon,
  QrCodeIcon,
  FileCodeIcon,
  UserXIcon,
} from "../../components/Icons";

interface GuideTopic {
  id: string;
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  tag: string;
  summary: string;
  threats: string[];
  bestPractices: string[];
  emergencyAction: string;
}

const DEFENSE_GUIDES: GuideTopic[] = [
  {
    id: "phishing-defense",
    title: "Recognizing Email & SMS Phishing (Smishing)",
    icon: GlobeIcon,
    tag: "Primary Vector",
    summary:
      "Phishing remains the #1 method adversaries use to steal campus passwords, financial aids, and student identities. Attackers exploit high-stress periods like exam registrations, fee payments, and mess balance refunds.",
    threats: [
      "Artificial Urgency: 'Your account will be suspended within 3 hours unless verified'.",
      "Spoofed Authority: Emails claiming to originate from the Dean, Registrar, or Vice Chancellor.",
      "Lookalike Domains: 'campus-portal-refunds.org' or 'univ-portal-login.xyz' instead of 'campus.edu'.",
      "Hidden Form Redirects: Legitimate-looking buttons that navigate to third-party form builders.",
    ],
    bestPractices: [
      "Always inspect the browser address bar. Legitimate university services strictly end with '.campus.edu'.",
      "Use password managers. A password manager will never autofill your university credentials on an unauthorized domain.",
      "Check the sender's full email address, not just the display name.",
      "Forward suspicious emails to the Threat Scanner before taking any action.",
    ],
    emergencyAction:
      "If you typed your password into a suspicious link: Change your LDAP password immediately at password.campus.edu and notify CIRT.",
  },
  {
    id: "quishing-defense",
    title: "QR Code Safety & Quishing Prevention",
    icon: QrCodeIcon,
    tag: "Physical & Digital",
    summary:
      "Quishing (QR Code Phishing) conceals malicious URLs and direct financial payment intents behind seemingly harmless barcodes posted in dining halls, dorms, and bulletin boards.",
    threats: [
      "Malicious Overlay Stickers: Fraudulent QR stickers pasted over legitimate university payment notices.",
      "Direct UPI Transfer Intents: Scanned codes that trigger instant fund transfers to private individual accounts.",
      "Rogue Wi-Fi Access Points: Codes that silently configure devices to connect to unencrypted Evil Twin networks.",
      "Shortened Hidden URLs: Barcodes resolving to bit.ly or tinyurl links masking credential-harvesting landing pages.",
    ],
    bestPractices: [
      "Always preview the decoded URL in your camera app before clicking 'Open in Browser'.",
      "Physically inspect public posters for tampering or stickers pasted over existing printed QR codes.",
      "Never approve payment requests with merchant names that do not match the official campus vendor.",
      "Upload or paste any untrusted QR payload into the SignalSafe QR Scanner before scanning with your mobile device.",
    ],
    emergencyAction:
      "If you scanned an unverified Wi-Fi QR code: Forget the network immediately, verify no new VPN or configuration profiles were installed, and run an endpoint scan.",
  },
  {
    id: "document-malware",
    title: "Malicious Office Documents & Excel Macros",
    icon: FileCodeIcon,
    tag: "File Safety",
    summary:
      "Adversaries share spreadsheets and documents titled 'Grade Sheet', 'Exam Schedule', or 'Fee Waiver List' embedded with auto-executing Visual Basic for Applications (VBA) macro payloads.",
    threats: [
      "Social Engineering Banners: Documents displaying blurred text with instructions: 'Click Enable Content to View'.",
      "Workbook_Open Macros: Malicious code triggered the moment protected view is disabled.",
      "Dynamic Data Exchange (DDE): Embedded formulas that execute system command prompts.",
      "Unusual File Extensions: Files ending in .xlsm, .docm, or .vbs passed off as regular course material.",
    ],
    bestPractices: [
      "Official campus announcements and timetables are distributed exclusively as verified PDFs.",
      "Never click 'Enable Macros' or 'Enable Editing' on files received from unknown senders or student chat groups.",
      "Keep Microsoft Office Protected View active at all times.",
      "Use static document analyzers to evaluate file structure anomalies without opening them.",
    ],
    emergencyAction:
      "If a macro executed unexpectedly: Disconnect your computer from Wi-Fi immediately to cut off command-and-control communication, and take the device to Campus IT.",
  },
  {
    id: "cyberbullying-defense",
    title: "Digital Harassment & Toxic Communication",
    icon: UserXIcon,
    tag: "Community Well-being",
    summary:
      "A safe campus requires digital resilience against targeted harassment, impersonation, hate speech, and abusive communication across campus Discord servers, WhatsApp groups, and forums.",
    threats: [
      "Doxxing: Public dissemination of a student's personal phone number, hostel room, or private messages.",
      "Impersonation Accounts: Fake profiles created using a student's photo and name to post defamatory statements.",
      "Coordinated Trolling: Targeted abusive messages sent across multiple social channels to cause emotional distress.",
      "Code-Mixed Abuse: Hostile language blended across regional languages and English to bypass standard filters.",
    ],
    bestPractices: [
      "Preserve evidence: Take uncropped screenshots with timestamps and visible user handles.",
      "Do not engage or retaliate: Escalating arguments often fuels coordinated harassment campaigns.",
      "Utilize SignalSafe's confidential and anonymous reporting to alert campus counselors and administrators.",
      "Adjust privacy settings on university social portals to restrict unsolicited messaging from non-contacts.",
    ],
    emergencyAction:
      "If you experience direct physical threats or severe distress: Contact the Campus Student Welfare Hotline (1-800-CAMPUS-CARE) or submit a high-priority incident report immediately.",
  },
];

export default function ResourcesPage() {
  const [activeGuide, setActiveGuide] = useState<string>("phishing-defense");

  const currentTopic = DEFENSE_GUIDES.find((g) => g.id === activeGuide) || DEFENSE_GUIDES[0];
  const TopicIcon = currentTopic.icon;

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-6">
        <div>
          <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">
            <BookOpenIcon className="h-4 w-4 text-slate-700" />
            <span>Campus Cyber Defense Protocol</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
            Security Guidelines & Knowledge Base
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            Actionable defensive guidelines, threat identification heuristics, and incident playbooks for students and faculty.
          </p>
        </div>

        <Link
          href="/scan"
          className="self-start sm:self-center inline-flex items-center gap-2 rounded-md bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 transition-colors shadow-sm"
        >
          <ShieldIcon className="h-3.5 w-3.5" />
          Test Threats in Scanner
        </Link>
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        {/* Topic Selector Sidebar (4 cols) */}
        <div className="lg:col-span-4 space-y-2">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3 px-1">
            Defense Modules
          </p>
          {DEFENSE_GUIDES.map((guide) => {
            const Icon = guide.icon;
            const isSelected = guide.id === activeGuide;
            return (
              <button
                key={guide.id}
                type="button"
                onClick={() => setActiveGuide(guide.id)}
                className={`w-full text-left p-3.5 rounded-lg border transition-all ${
                  isSelected
                    ? "border-slate-900 bg-slate-900 text-white shadow-sm"
                    : "border-slate-200 bg-white hover:border-slate-300 text-slate-900"
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <div className="flex items-center gap-2">
                    <Icon className={`h-4 w-4 ${isSelected ? "text-white" : "text-slate-700"}`} />
                    <span className="font-semibold text-xs">{guide.title}</span>
                  </div>
                </div>
                <span
                  className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${
                    isSelected ? "bg-slate-800 text-slate-300" : "bg-slate-100 text-slate-600"
                  }`}
                >
                  {guide.tag}
                </span>
              </button>
            );
          })}

          <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 mt-6 space-y-2 text-xs">
            <p className="font-semibold text-slate-800 flex items-center gap-1.5">
              <LockIcon className="h-3.5 w-3.5 text-slate-600" />
              <span>Campus CIRT 24/7 Hotline</span>
            </p>
            <p className="text-slate-600">
              For active account lockouts, compromised university email, or urgent assistance:
            </p>
            <p className="font-mono text-slate-900 font-bold">+1 (555) 019-CIRT</p>
            <p className="text-slate-500 text-[11px]">cirt-emergency@campus.edu</p>
          </div>
        </div>

        {/* Detailed Guide View (8 cols) */}
        <div className="lg:col-span-8 space-y-6">
          <div className="rounded-lg border border-slate-200 bg-white p-6 sm:p-8 shadow-sm space-y-6">
            
            {/* Header */}
            <div className="border-b border-slate-200 pb-4">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">
                <TopicIcon className="h-4 w-4 text-slate-700" />
                <span>{currentTopic.tag}</span>
              </div>
              <h2 className="text-xl sm:text-2xl font-bold text-slate-900">{currentTopic.title}</h2>
              <p className="mt-2 text-xs text-slate-700 leading-relaxed bg-slate-50 border border-slate-200 rounded p-3">
                {currentTopic.summary}
              </p>
            </div>

            {/* Common Threat Patterns */}
            <div className="space-y-3">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <AlertCircleIcon className="h-4 w-4 text-amber-600" />
                <span>Recognizing the Threat Indicators</span>
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {currentTopic.threats.map((threat, idx) => (
                  <div
                    key={idx}
                    className="rounded border border-amber-200 bg-amber-50/40 p-3 text-xs text-slate-800 flex items-start gap-2"
                  >
                    <span className="font-bold text-amber-700 mt-0.5">•</span>
                    <span>{threat}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Actionable Best Practices */}
            <div className="space-y-3">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <CheckCircleIcon className="h-4 w-4 text-emerald-600" />
                <span>Mandatory Defense Checklist</span>
              </h3>
              <div className="space-y-2">
                {currentTopic.bestPractices.map((practice, idx) => (
                  <div
                    key={idx}
                    className="rounded border border-slate-200 bg-white p-3 text-xs text-slate-700 flex items-start gap-2.5"
                  >
                    <CheckCircleIcon className="h-4 w-4 text-emerald-600 shrink-0 mt-0.5" />
                    <span>{practice}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Emergency Action Box */}
            <div className="rounded-lg border border-red-200 bg-red-50/70 p-4 space-y-2">
              <p className="text-xs font-bold text-red-950 uppercase tracking-wider flex items-center gap-1.5">
                <AlertCircleIcon className="h-4 w-4 text-red-700" />
                <span>Immediate Action If Encountered / Compromised</span>
              </p>
              <p className="text-xs text-red-900 leading-relaxed font-medium">
                {currentTopic.emergencyAction}
              </p>
              <div className="pt-2 flex flex-wrap gap-2">
                <Link
                  href="/report"
                  className="rounded bg-red-700 px-3 py-1.5 text-xs font-semibold text-white hover:bg-red-800 transition-colors shadow-sm"
                >
                  File Urgent Incident Report
                </Link>
                <Link
                  href="/scan"
                  className="rounded border border-red-300 bg-white px-3 py-1.5 text-xs font-semibold text-red-900 hover:bg-red-100/50 transition-colors"
                >
                  Verify via Scanner First
                </Link>
              </div>
            </div>

          </div>
        </div>

      </div>

    </div>
  );
}
