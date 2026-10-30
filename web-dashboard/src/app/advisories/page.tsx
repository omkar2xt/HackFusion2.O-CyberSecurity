"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  BellIcon,
  ShieldIcon,
  AlertCircleIcon,
  ExternalLinkIcon,
  SearchIcon,
  GlobeIcon,
  QrCodeIcon,
  FileCodeIcon,
} from "../../components/Icons";

interface Advisory {
  id: string;
  referenceNumber: string;
  title: string;
  date: string;
  category: "PHISHING" | "QUISHING" | "MALWARE" | "NETWORK";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: "ACTIVE" | "CONTAINED" | "RESOLVED";
  targetAudience: string;
  summary: string;
  threatDetails: string;
  iocSample: string;
  recommendations: string[];
}

const CAMPUS_ADVISORIES: Advisory[] = [
  {
    id: "adv-1",
    referenceNumber: "ADV-2026-04",
    title: "Circulating Mess Fee Refund SMS & Fake Dean Notification",
    date: "October 30, 2026",
    category: "PHISHING",
    severity: "HIGH",
    status: "ACTIVE",
    targetAudience: "All Residential Students & Hostel Inmates",
    summary:
      "SMS and WhatsApp messages claim students have unclaimed semester mess refunds (5,000 INR) expiring in 3 hours, directing them to an unauthorized .org credential harvesting portal.",
    threatDetails:
      "Adversaries registered 'campus-portal-refunds.org' to impersonate the Dean of Student Affairs. The page requests student roll numbers, net banking passwords, and OTPs.",
    iocSample: "https://campus-portal-refunds.org/auth/verify?session=9812",
    recommendations: [
      "Do not click the link or provide banking or OTP details.",
      "Official campus fee refunds are only processed through finance.campus.edu.",
      "Forward suspicious SMS screenshots to cirt@campus.edu or report them below.",
    ],
  },
  {
    id: "adv-2",
    referenceNumber: "ADV-2026-03",
    title: "Cloned Academic Portal Login Harvesting University Credentials",
    date: "October 29, 2026",
    category: "PHISHING",
    severity: "HIGH",
    status: "ACTIVE",
    targetAudience: "All Students and Faculty",
    summary:
      "Unsolicited emails warning of impending account suspension direct users to 'univ-portal-login.xyz' to verify academic credentials.",
    threatDetails:
      "The cloned site perfectly replicates the institutional single sign-on (SSO) login form to steal master LDAP credentials and bypass multi-factor authentication.",
    iocSample: "https://univ-portal-login.xyz/student-portal",
    recommendations: [
      "Always verify that the browser address bar ends with '.campus.edu'.",
      "Check that your password manager recognizes the official domain.",
      "If you entered credentials on this site, change your password immediately and contact IT.",
    ],
  },
  {
    id: "adv-3",
    referenceNumber: "ADV-2026-02",
    title: "Rogue Wi-Fi Access Points Discovered Near Hostel Complexes",
    date: "October 28, 2026",
    category: "NETWORK",
    severity: "CRITICAL",
    status: "ACTIVE",
    targetAudience: "Hostel Blocks 3, 4, and 7",
    summary:
      "Rogue wireless access points broadcasting SSIDs such as 'Campus_Free_HighSpeed_WiFi' were discovered attempting Evil Twin man-in-the-middle attacks.",
    threatDetails:
      "QR codes posted in common areas automated connection to an unencrypted access point configured to intercept unencrypted traffic and perform SSL stripping.",
    iocSample: "WIFI:S:Campus_Free_HighSpeed_WiFi;T:WPA;P:guest1234;;",
    recommendations: [
      "Only connect to the certified 'eduroam' or 'Campus-Secure-802.1x' wireless networks.",
      "Never scan unverified Wi-Fi setup QR stickers posted in public hallways.",
      "Use university VPN when connected to any wireless access points.",
    ],
  },
  {
    id: "adv-4",
    referenceNumber: "ADV-2026-01",
    title: "Macro-Enabled Excel Spreadsheets Disguised as 'Mid-Term Exam Schedule'",
    date: "October 26, 2026",
    category: "MALWARE",
    severity: "MEDIUM",
    status: "CONTAINED",
    targetAudience: "Undergraduate Students (CSE / ECE / MECH)",
    summary:
      "Circulating .xlsm files claiming to be revised examination time tables prompt recipients to 'Enable Editing' and 'Enable Content' to execute embedded VBA payloads.",
    threatDetails:
      "Static analysis indicates an auto-executing Workbook_Open macro designed to drop PowerShell stage-1 downloaders from external paste services.",
    iocSample: "Revised_Exam_Schedule_Fall2026.xlsm (SHA256: 7a8f9c1b...)",
    recommendations: [
      "Official academic timetables are only published in PDF format on academic.campus.edu.",
      "Never click 'Enable Macros' or 'Enable Editing' on files received through unofficial messaging groups.",
      "Scan any suspicious document in the Threat Scanner before opening.",
    ],
  },
];

export default function AdvisoriesPage() {
  const router = useRouter();
  const [filterCategory, setFilterCategory] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  const filteredAdvisories = CAMPUS_ADVISORIES.filter((adv) => {
    if (filterCategory !== "ALL" && adv.category !== filterCategory) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        adv.title.toLowerCase().includes(q) ||
        adv.referenceNumber.toLowerCase().includes(q) ||
        adv.summary.toLowerCase().includes(q) ||
        adv.threatDetails.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleScanIoc = (ioc: string) => {
    // If URL, navigate to scanner with parameter
    router.push(`/scan?test=${encodeURIComponent(ioc)}`);
  };

  const getSeverityBadge = (severity: Advisory["severity"]) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-red-50 text-red-900 border-red-300";
      case "HIGH":
        return "bg-orange-50 text-orange-900 border-orange-300";
      case "MEDIUM":
        return "bg-amber-50 text-amber-900 border-amber-300";
      default:
        return "bg-blue-50 text-blue-900 border-blue-200";
    }
  };

  const getCategoryIcon = (category: Advisory["category"]) => {
    switch (category) {
      case "PHISHING":
        return GlobeIcon;
      case "QUISHING":
        return QrCodeIcon;
      case "MALWARE":
        return FileCodeIcon;
      default:
        return ShieldIcon;
    }
  };

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      
      {/* Title & Introduction */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-6">
        <div>
          <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-700 uppercase tracking-wider mb-1">
            <BellIcon className="h-4 w-4 text-amber-700" />
            <span>Campus Incident Response Team (CIRT)</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
            Campus Cybersecurity Threat Advisories
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            Authoritative security bulletins on active digital threats, phishing waves, and indicators of compromise (IOCs).
          </p>
        </div>

        <Link
          href="/scan"
          className="self-start sm:self-center inline-flex items-center gap-2 rounded-md bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 transition-colors shadow-sm"
        >
          <ShieldIcon className="h-3.5 w-3.5" />
          Open Threat Scanner
        </Link>
      </div>

      {/* Filter and Search Toolbar */}
      <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm space-y-3">
        <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
          
          {/* Category Tabs */}
          <div className="flex flex-wrap gap-2 text-xs">
            {[
              { id: "ALL", label: "All Threats" },
              { id: "PHISHING", label: "Phishing & URLs" },
              { id: "QUISHING", label: "QR & Quishing" },
              { id: "MALWARE", label: "Office & Malware" },
              { id: "NETWORK", label: "Wi-Fi & Network" },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setFilterCategory(tab.id)}
                className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
                  filterCategory === tab.id
                    ? "bg-slate-900 text-white"
                    : "bg-slate-100 text-slate-700 hover:bg-slate-200"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Search Box */}
          <div className="relative w-full sm:w-72">
            <SearchIcon className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search advisories or IOCs..."
              className="w-full rounded border border-slate-300 pl-9 pr-3 py-1.5 text-xs text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none"
            />
          </div>
        </div>
      </div>

      {/* Advisories Grid */}
      <div className="space-y-4">
        {filteredAdvisories.length === 0 ? (
          <div className="rounded-lg border border-slate-200 bg-white p-12 text-center text-slate-500 text-xs">
            No matching advisories found.
          </div>
        ) : (
          filteredAdvisories.map((adv) => {
            const Icon = getCategoryIcon(adv.category);
            return (
              <div
                key={adv.id}
                className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm space-y-4 hover:border-slate-300 transition-colors"
              >
                {/* Header row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3">
                  <div className="flex items-center gap-3">
                    <div className="flex h-9 w-9 items-center justify-center rounded-md bg-slate-100 text-slate-900">
                      <Icon className="h-4 w-4" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-slate-600">
                          {adv.referenceNumber}
                        </span>
                        <h2 className="font-bold text-slate-900 text-base">{adv.title}</h2>
                      </div>
                      <p className="text-[11px] text-slate-500">
                        Published on {adv.date} • Target: {adv.targetAudience}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded border text-[11px] font-bold ${getSeverityBadge(
                        adv.severity
                      )}`}
                    >
                      {adv.severity} RISK
                    </span>
                    <span className="px-2 py-0.5 rounded border border-emerald-200 bg-emerald-50 text-emerald-800 text-[10px] font-semibold">
                      {adv.status}
                    </span>
                  </div>
                </div>

                {/* Summary */}
                <p className="text-xs text-slate-700 leading-relaxed">{adv.summary}</p>

                {/* Technical Details & Sample IOC */}
                <div className="rounded border border-slate-200 bg-slate-50 p-3 space-y-2 text-xs">
                  <div>
                    <span className="font-semibold text-slate-900">Adversary Tactics: </span>
                    <span className="text-slate-700">{adv.threatDetails}</span>
                  </div>

                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-2 border-t border-slate-200">
                    <div className="font-mono text-[11px] text-slate-800 truncate">
                      <span className="text-slate-500 font-sans font-semibold">Sample IOC: </span>
                      {adv.iocSample}
                    </div>

                    <button
                      type="button"
                      onClick={() => handleScanIoc(adv.iocSample)}
                      className="shrink-0 inline-flex items-center gap-1.5 rounded bg-slate-900 px-3 py-1 text-[11px] font-semibold text-white hover:bg-slate-800 transition-colors"
                    >
                      <span>Analyze in Threat Scanner</span>
                      <ExternalLinkIcon className="h-3 w-3" />
                    </button>
                  </div>
                </div>

                {/* Countermeasures Checklist */}
                <div>
                  <p className="text-xs font-bold text-slate-900 mb-1.5">Actionable Student Countermeasures:</p>
                  <ul className="space-y-1">
                    {adv.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-slate-600">
                        <AlertCircleIcon className="h-3.5 w-3.5 text-amber-600 shrink-0 mt-0.5" />
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            );
          })
        )}
      </div>

    </div>
  );
}
