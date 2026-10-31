import {
  Incident,
  IncidentCategory,
  IncidentSeverity,
  IncidentStatus,
  ScanResult,
  ScanIndicator,
  AdminMetrics,
  InvestigationNote,
  EvidenceFile,
} from "../lib/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function getHeaders(): HeadersInit {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("signalsafe_token");
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }
  return headers;
}

// In-memory demo store initialized with realistic campus security scenarios
const INITIAL_INCIDENTS: Incident[] = [
  {
    id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    referenceNumber: "SSC-2026-8941",
    createdAt: new Date(Date.now() - 1000 * 60 * 38).toISOString(),
    updatedAt: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    reporterId: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    reporterName: "Aarav Sharma",
    reporterEmail: "a.sharma@campus.edu",
    isAnonymous: false,
    category: "PHISHING_EMAIL",
    severity: "HIGH",
    status: "INVESTIGATING",
    title: "Urgent Hostel Fee Refund Notification with Spoofed Dean Signature",
    description: "Received an email from 'dean-office@campus-portal-refunds.org' asking students to verify bank details within 3 hours to claim a semester mess fee refund.",
    affectedPlatform: "Campus Outlook / Webmail",
    linkedScan: {
      id: "scn-902",
      targetUrl: "https://campus-portal-refunds.org/auth/verify?session=9812",
      messageText: "URGENT: Dean of Student Affairs requires your bank verification to process 5,000 INR mess balance refund. Failure to claim within 3 hours will forfeit funds.",
      verdict: "MALICIOUS",
      riskScore: 92,
      threatLevel: "HIGH",
      confidence: 0.94,
      analyzedAt: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
      summary: "Domain registered 48 hours ago. Displays deceptive impersonation of the Dean of Student Affairs with artificial urgency and bank credential harvesting.",
      indicators: [
        {
          type: "DOMAIN_AGE",
          label: "Freshly Registered Domain",
          description: "Domain registered 2 days ago via privacy-protected registrar.",
          severity: "danger",
        },
        {
          type: "TYPOSQUAT",
          label: "Deceptive Domain Naming",
          description: "Mimics official campus portal naming structure using an unauthorized .org TLD.",
          severity: "danger",
        },
        {
          type: "URGENCY_LANGUAGE",
          label: "High Urgency Coercion",
          description: "Uses artificial time limit ('within 3 hours') to compel hasty credential entry.",
          severity: "warning",
        },
      ],
      recommendations: [
        "Do not click the link or submit banking details.",
        "Official campus fee refunds are only processed through the official Finance portal (finance.campus.edu).",
        "Mark the sender as phishing in your campus email client.",
      ],
    },
    evidenceFiles: [
      {
        id: "ev-1",
        name: "email_full_headers.eml",
        sizeBytes: 18450,
        mimeType: "message/rfc822",
        uploadedAt: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
      },
      {
        id: "ev-2",
        name: "scam_refund_notice.png",
        sizeBytes: 421000,
        mimeType: "image/png",
        uploadedAt: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
      },
    ],
    assignedTo: "c1b2c3d4-e5f6-7890-abcd-ef1234567892",
    assignedToName: "Vikram Sen (SOC Lead)",
    investigationNotes: [
      {
        id: "note-1",
        author: "Vikram Sen",
        timestamp: new Date(Date.now() - 1000 * 60 * 20).toISOString(),
        content: "Egress firewall block requested for campus-portal-refunds.org. DNS sinkhole applied on campus Wi-Fi network.",
      },
    ],
    auditTimeline: [
      {
        id: "aud-1",
        timestamp: new Date(Date.now() - 1000 * 60 * 38).toISOString(),
        actor: "Aarav Sharma",
        actorRole: "Student",
        action: "INCIDENT_CREATED",
        details: "Incident submitted via Web Dashboard with linked scan.",
      },
      {
        id: "aud-2",
        timestamp: new Date(Date.now() - 1000 * 60 * 28).toISOString(),
        actor: "Vikram Sen",
        actorRole: "Security Admin",
        action: "STATUS_UPDATED",
        details: "Status changed from NEW to INVESTIGATING. Severity confirmed HIGH.",
      },
    ],
  },
  {
    id: "f1b2c3d4-e5f6-7890-abcd-ef1234567899",
    referenceNumber: "SSC-2026-8942",
    createdAt: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
    updatedAt: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    reporterId: "usr-student-88",
    isAnonymous: true,
    category: "QR_CODE_SCAM",
    severity: "CRITICAL",
    status: "TRIAGED",
    title: "Canteen Payment Counter QR Code Replaced with Fraudulent UPI Link",
    description: "Physical printed sticker pasted over the official Main Canteen checkout stand redirecting payments to an unauthorized personal UPI VPA.",
    affectedPlatform: "Main Cafeteria Counter 3",
    evidenceFiles: [
      {
        id: "ev-3",
        name: "tampered_qr_counter.jpg",
        sizeBytes: 812000,
        mimeType: "image/jpeg",
        uploadedAt: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
      },
    ],
    assignedTo: "sec-admin-02",
    assignedToName: "Priya Nair",
    investigationNotes: [
      {
        id: "note-2",
        author: "Priya Nair",
        timestamp: new Date(Date.now() - 1000 * 60 * 95).toISOString(),
        content: "Campus security supervisor on duty was dispatched to physically confiscate the tampered placard and verify all counters.",
      },
    ],
    auditTimeline: [
      {
        id: "aud-3",
        timestamp: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
        actor: "Anonymous Reporter",
        actorRole: "Student",
        action: "INCIDENT_CREATED",
        details: "Anonymous incident filed with uploaded photo evidence.",
      },
    ],
  },
];

let incidentsStore = [...INITIAL_INCIDENTS];

interface BackendIndicator {
  code: string;
  label?: string;
  detail?: string;
  evidence_type?: string;
}

interface BackendNote {
  id: string;
  author_id?: string;
  note: string;
  created_at?: string;
}

interface BackendEvidence {
  id: string;
  evidence_type?: string;
  storage_path?: string | null;
  created_at?: string;
}

interface BackendIncidentDetail {
  id: string;
  created_by?: string;
  scan_id?: string | null;
  category: string;
  severity: string;
  status: string;
  summary: string;
  description?: string | null;
  assigned_to?: string | null;
  notes?: BackendNote[];
  evidence?: BackendEvidence[];
  created_at?: string;
  updated_at?: string;
}

interface BackendScanResponse {
  scan_id?: string;
  verdict: string;
  risk_level: string;
  risk_score?: number;
  indicators?: BackendIndicator[];
  recommendations?: string[];
  checked_at?: string;
  _mock_notice?: string;
  payload_type?: string;
  extracted_urls?: string[];
  analysis_scope?: string;
}

interface BackendUpdatePayload {
  status?: string;
  severity?: string;
  assigned_to?: string;
  note?: string;
}

function mapBackendIncidentToFrontend(data: BackendIncidentDetail): Incident {
  const categoryMapReverse: Record<string, IncidentCategory> = {
    PHISHING: "PHISHING_EMAIL",
    MALWARE: "MALICIOUS_URL",
    CREDENTIAL_HARVESTING: "ACCOUNT_TAKEOVER",
    IMPERSONATION: "STAFF_IMPERSONATION",
    SCAM: "QR_CODE_SCAM",
    OTHER: "CYBERBULLYING",
  };

  const statusMapReverse: Record<string, IncidentStatus> = {
    SUBMITTED: "NEW",
    TRIAGED: "TRIAGED",
    INVESTIGATING: "INVESTIGATING",
    RESOLVED: "RESOLVED",
    CLOSED: "RESOLVED",
  };

  const id = String(data.id);
  const refNum = `SSC-2026-${id.slice(0, 4).toUpperCase()}`;

  const notes: InvestigationNote[] = Array.isArray(data.notes)
    ? data.notes.map((n: BackendNote) => ({
        id: String(n.id),
        author: "Security Officer",
        timestamp: n.created_at || new Date().toISOString(),
        content: n.note,
      }))
    : [];

  const evidence: EvidenceFile[] = Array.isArray(data.evidence)
    ? data.evidence.map((e: BackendEvidence) => ({
        id: String(e.id),
        name: e.evidence_type || "Evidence File",
        sizeBytes: 1024,
        mimeType: "application/octet-stream",
        uploadedAt: e.created_at || new Date().toISOString(),
      }))
    : [];

  return {
    id,
    referenceNumber: refNum,
    createdAt: data.created_at || new Date().toISOString(),
    updatedAt: data.updated_at || new Date().toISOString(),
    reporterId: String(data.created_by || "a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
    reporterName: "Campus Member",
    reporterEmail: "member@campus.edu",
    isAnonymous: false,
    category: categoryMapReverse[data.category] || "PHISHING_EMAIL",
    severity: (data.severity as IncidentSeverity) || "HIGH",
    status: statusMapReverse[data.status] || "NEW",
    title: data.summary || "Reported Digital Threat",
    description: data.description || "",
    affectedPlatform: "Campus Network / Endpoints",
    evidenceFiles: evidence,
    assignedTo: data.assigned_to ? String(data.assigned_to) : undefined,
    assignedToName: data.assigned_to ? "Security Operations" : undefined,
    investigationNotes: notes,
    auditTimeline: [
      {
        id: `aud-${id}-1`,
        timestamp: data.created_at || new Date().toISOString(),
        actor: "Campus Reporter",
        actorRole: "Reporter",
        action: "INCIDENT_CREATED",
        details: "Incident reported and synchronized from authoritative backend service.",
      },
      ...notes.map((n: InvestigationNote) => ({
        id: `aud-note-${n.id}`,
        timestamp: n.timestamp,
        actor: n.author,
        actorRole: "Admin",
        action: "NOTE_RECORDED",
        details: n.content,
      })),
    ],
  };
}

export const apiClient = {
  // Service Health Check
  async checkHealth(): Promise<{ status: string; version: string; environment: string } | null> {
    try {
      const res = await fetch(`${API_BASE}/health`, { cache: "no-store" });
      if (res.ok) return await res.json();
    } catch {
      // offline
    }
    return null;
  },

  // WD-03: Scanner Submission (Connected to FastAPI /api/v1/scan/* for all 5 modalities)
  async submitScan(payload: {
    url?: string;
    messageText?: string;
    qrPayload?: string;
    documentMeta?: { fileName: string; fileSize?: number; fileType?: string; details?: string; features?: Record<string, unknown> };
    cyberbullyingText?: string;
  }): Promise<ScanResult> {
    try {
      const headers = getHeaders();
      let res: Response | null = null;
      if (payload.qrPayload) {
        res = await fetch(`${API_BASE}/scan/qr`, {
          method: "POST",
          headers,
          body: JSON.stringify({ decoded_content: payload.qrPayload }),
        });
      } else if (payload.url) {
        res = await fetch(`${API_BASE}/scan/url`, {
          method: "POST",
          headers,
          body: JSON.stringify({ url: payload.url }),
        });
      } else if (payload.documentMeta) {
        res = await fetch(`${API_BASE}/scan/document`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            file_name: payload.documentMeta.fileName,
            details: payload.documentMeta.details,
            features: payload.documentMeta.features,
          }),
        });
      } else if (payload.cyberbullyingText) {
        res = await fetch(`${API_BASE}/scan/cyberbullying`, {
          method: "POST",
          headers,
          body: JSON.stringify({ text: payload.cyberbullyingText }),
        });
      } else if (payload.messageText) {
        res = await fetch(`${API_BASE}/scan/message`, {
          method: "POST",
          headers,
          body: JSON.stringify({ message_text: payload.messageText }),
        });
      }

      if (res && res.ok) {
        const data: BackendScanResponse = await res.json();
        const verdictMap: Record<string, ScanResult["verdict"]> = {
          MALICIOUS: "MALICIOUS",
          SUSPICIOUS: "SUSPICIOUS",
          LOW_RISK: "SAFE",
          UNKNOWN: "UNCERTAIN",
        };
        const threatMap: Record<string, ScanResult["threatLevel"]> = {
          CRITICAL: "CRITICAL",
          HIGH: "HIGH",
          MEDIUM: "SUSPICIOUS",
          LOW: "LOW",
          UNKNOWN: "SAFE",
        };

        const verdict = verdictMap[data.verdict] || "UNCERTAIN";
        const threatLevel = threatMap[data.risk_level] || "SAFE";

        const indicators: ScanIndicator[] = (data.indicators || []).map((ind: BackendIndicator) => ({
          type:
            ind.code === "LOOKALIKE_HOST"
              ? "TYPOSQUAT"
              : ind.code === "URGENCY_LANGUAGE"
              ? "URGENCY_LANGUAGE"
              : ind.code.includes("PAYMENT") || ind.code.includes("WIFI")
              ? "UNVERIFIED_PAYMENT"
              : "REPUTATION",
          label: ind.label || ind.code,
          description: ind.detail || "",
          severity:
            data.risk_level === "CRITICAL" || data.risk_level === "HIGH"
              ? "danger"
              : data.risk_level === "MEDIUM"
              ? "warning"
              : "info",
        }));

        return {
          id: data.scan_id || `scn-${Date.now()}`,
          targetUrl: payload.url,
          messageText: payload.messageText,
          qrPayload: payload.qrPayload,
          payloadType: data.payload_type,
          extractedUrls: data.extracted_urls,
          analysisScope: data.analysis_scope,
          verdict,
          riskScore: typeof data.risk_score === "number" ? data.risk_score : 15,
          threatLevel,
          confidence: 0.94,
          analyzedAt: data.checked_at || new Date().toISOString(),
          summary:
            indicators.length > 0
              ? indicators.map((i) => i.description).join(" ")
              : (data._mock_notice || "Threat evaluation performed by authoritative backend detection engine."),
          indicators,
          recommendations: data.recommendations || [
            "Always verify digital links before supplying university credentials.",
          ],
        };
      }
    } catch {
      // Fallback to local heuristic analyzer for offline testing
    }

    // Comprehensive heuristic analysis fallback
    const url = payload.url || "";
    const text = payload.messageText || "";
    const qr = payload.qrPayload || "";
    const doc = payload.documentMeta;
    const bullying = payload.cyberbullyingText || "";
    const combined = `${url} ${text} ${qr} ${bullying}`.toLowerCase();

    // Document Threat Analysis Module
    if (doc) {
      const fileNameLower = (doc.fileName || "").toLowerCase();
      const detailsLower = (doc.details || "").toLowerCase();
      const isMacroEnabled = fileNameLower.endsWith(".xlsm") || fileNameLower.endsWith(".docm") || fileNameLower.endsWith(".vbs") || fileNameLower.endsWith(".hta");
      const hasAutoExec = /workbook_open|auto_open|document_open|shell|powershell|cmd\.exe/i.test(detailsLower);
      const hasDde = /=cmd\||=powershell\||ddeexec/i.test(detailsLower);
      const hasExternalLink = /targetmode="external"|http:\/\/|https:\/\//i.test(detailsLower);

      let docScore = 15;
      const docIndicators: ScanIndicator[] = [];

      if (isMacroEnabled) {
        docScore += 35;
        docIndicators.push({
          type: "REPUTATION",
          label: "Macro-Enabled Office Container Format",
          description: `The file has extension '${fileNameLower.split('.').pop()}', capable of executing embedded active VBA procedures.`,
          severity: "warning",
        });
      }

      if (hasAutoExec) {
        docScore += 45;
        docIndicators.push({
          type: "CREDENTIAL_HARVEST",
          label: "Auto-Execution Macro Trigger Routine",
          description: "Contains auto-execution handlers (Workbook_Open / Shell invocation) designed to execute code without user consent.",
          severity: "danger",
        });
      }

      if (hasDde) {
        docScore += 40;
        docIndicators.push({
          type: "REPUTATION",
          label: "Dynamic Data Exchange (DDE) Command Injection",
          description: "Embedded formulas invoke external shell binaries directly from cell evaluation contexts.",
          severity: "danger",
        });
      }

      if (hasExternalLink) {
        docScore += 20;
        docIndicators.push({
          type: "DOMAIN_AGE",
          label: "External Relationship Corridors",
          description: "The document references remote external templates or unverified staging servers.",
          severity: "warning",
        });
      }

      docScore = Math.min(Math.max(docScore, 10), 98);
      const isMalicious = docScore >= 70;
      const isSuspicious = docScore >= 40 && docScore < 70;

      return {
        id: `scn-doc-${Date.now()}`,
        payloadType: "DOCUMENT",
        verdict: isMalicious ? "MALICIOUS" : isSuspicious ? "SUSPICIOUS" : "SAFE",
        riskScore: docScore,
        threatLevel: isMalicious ? "HIGH" : isSuspicious ? "SUSPICIOUS" : "SAFE",
        confidence: 0.93,
        analyzedAt: new Date().toISOString(),
        summary: isMalicious
          ? `High-risk active code discovered in '${doc.fileName}'. Auto-execution macros or command injection triggers identified.`
          : isSuspicious
          ? `File '${doc.fileName}' exhibits suspicious container features. Exercise caution before disabling Protected View.`
          : `Static inspection of '${doc.fileName}' revealed no dangerous active content or formula exploits.`,
        indicators: docIndicators,
        recommendations: [
          "Do not click 'Enable Content' or 'Enable Macros' on this file.",
          "University academic timetables and notices are distributed exclusively as verified PDFs.",
          "Inspect document streams using static security sandboxes before opening.",
        ],
      };
    }

    // Cyberbullying & Hostile Language Module
    if (bullying) {
      const bLower = bullying.toLowerCase();
      const hasPersonalThreat = /kill|beat|destroy|hurt|ruin your|die|attack|watch your back/i.test(bLower);
      const hasHarassment = /loser|ugly|worthless|trash|disgusting|kill yourself|get lost|freak/i.test(bLower);
      const hasDoxxing = /room no|phone number|address|leak your|hostel block|contact no/i.test(bLower);

      let bullyScore = 15;
      const bIndicators: ScanIndicator[] = [];

      if (hasPersonalThreat) {
        bullyScore += 55;
        bIndicators.push({
          type: "URGENCY_LANGUAGE",
          label: "Direct Personal Intimidation or Threat",
          description: "Language contains direct expressions of hostility or physical intimidation.",
          severity: "danger",
        });
      }

      if (hasHarassment) {
        bullyScore += 35;
        bIndicators.push({
          type: "REPUTATION",
          label: "Targeted Abusive Communication",
          description: "Content displays derogatory remarks intended to humiliate or distress the recipient.",
          severity: "warning",
        });
      }

      if (hasDoxxing) {
        bullyScore += 40;
        bIndicators.push({
          type: "CREDENTIAL_HARVEST",
          label: "Doxxing & Unauthorized Personal Data Exposure",
          description: "Message references private personal identifiers such as hostel room numbers or private contact details.",
          severity: "danger",
        });
      }

      bullyScore = Math.min(Math.max(bullyScore, 10), 96);
      const isSevere = bullyScore >= 70;
      const isModerate = bullyScore >= 40 && bullyScore < 70;

      return {
        id: `scn-bully-${Date.now()}`,
        messageText: bullying,
        payloadType: "COMMUNICATION",
        verdict: isSevere ? "MALICIOUS" : isModerate ? "SUSPICIOUS" : "SAFE",
        riskScore: bullyScore,
        threatLevel: isSevere ? "HIGH" : isModerate ? "SUSPICIOUS" : "SAFE",
        confidence: 0.90,
        analyzedAt: new Date().toISOString(),
        summary: isSevere
          ? "High probability of harmful online communication or targeted harassment. Immediate support and documentation recommended."
          : isModerate
          ? "Derogatory or intimidating language detected. Content flagged for supportive review."
          : "Standard peer communication profile. No immediate severe harassment signals detected.",
        indicators: bIndicators,
        recommendations: [
          "Preserve uncropped screenshots with timestamps and visible user handles.",
          "Do not engage or retaliate against hostile senders.",
          "Confidential support is available via Campus Student Welfare Hotline (1-800-CAMPUS-CARE).",
          "File an anonymous incident report to alert campus counselors and administrative teams.",
        ],
      };
    }

    const isUrgent = /urgent|immediate|within \d+|suspended|expire|action required|penalty/i.test(combined);
    const isFinancial = /fee|refund|bank|upi|qr|payment|mess balance|stipend|scholarship/i.test(combined);
    const isCredentials = /verify|password|login|credentials|portal|otp|account/i.test(combined);
    const hasSuspiciousDomain = /\.xyz|\.top|\.tk|\.ga|\.work|bit\.ly|tinyurl|refunds-portal/i.test(url || qr);
    const hasCampusSpoof = /campus|univ|portal|dean|exam/i.test(url || qr) && !(url || qr).includes("campus.edu");
    const isQrPayment = qr.startsWith("upi://") || /vpa=|pay\?/i.test(qr);
    const isWifiPayload = qr.startsWith("WIFI:") || /WPA|WEP/i.test(qr);

    let riskScore = 12;
    const indicators: ScanResult["indicators"] = [];

    if (isQrPayment) {
      riskScore += 40;
      indicators.push({
        type: "UNVERIFIED_PAYMENT",
        label: "Direct UPI/Payment Intent in QR Code",
        description: "QR code initiates an immediate money transfer without an verified institution merchant name.",
        severity: "danger",
      });
    }

    if (isWifiPayload) {
      riskScore += 25;
      indicators.push({
        type: "REPUTATION",
        label: "Direct Wi-Fi Configuration Profile",
        description: "QR attempts automated connection to a wireless access point. Risk of rogue Wi-Fi interception.",
        severity: "warning",
      });
    }

    if (hasSuspiciousDomain) {
      riskScore += 35;
      indicators.push({
        type: "DOMAIN_AGE",
        label: "Suspicious or Unverified TLD",
        description: "The domain uses a high-risk or commonly abused top-level extension.",
        severity: "danger",
      });
    }

    if (hasCampusSpoof) {
      riskScore += 30;
      indicators.push({
        type: "TYPOSQUAT",
        label: "Potential Campus Portal Impersonation",
        description: "The address contains campus terms but is not part of the legitimate campus.edu domain.",
        severity: "danger",
      });
    }

    if (isUrgent) {
      riskScore += 20;
      indicators.push({
        type: "URGENCY_LANGUAGE",
        label: "Coercive Urgency Cues",
        description: "Message relies on time pressure or threats of penalty to prompt impulsive actions.",
        severity: "warning",
      });
    }

    if (isFinancial && isCredentials) {
      riskScore += 25;
      indicators.push({
        type: "CREDENTIAL_HARVEST",
        label: "Financial & Credential Verification Prompt",
        description: "Requests login credentials or payment verification via an external link.",
        severity: "danger",
      });
    }

    riskScore = Math.min(Math.max(riskScore, 8), 98);

    let verdict: ScanResult["verdict"] = "SAFE";
    let threatLevel: ScanResult["threatLevel"] = "SAFE";

    if (riskScore >= 75) {
      verdict = "MALICIOUS";
      threatLevel = "HIGH";
    } else if (riskScore >= 45) {
      verdict = "SUSPICIOUS";
      threatLevel = "SUSPICIOUS";
    } else if (riskScore >= 25) {
      verdict = "UNCERTAIN";
      threatLevel = "LOW";
    }

    const recs: string[] = [];
    if (verdict === "MALICIOUS" || verdict === "SUSPICIOUS") {
      recs.push("Do not enter your credentials or student ID on this destination.");
      recs.push("Verify legitimacy through your departmental office or the official campus portal.");
      recs.push("Escalate this incident using the 'Report to Campus IT' button below.");
    } else {
      recs.push("No immediate red flags detected based on current heuristics.");
      recs.push("Always ensure the browser address bar shows the valid campus.edu certificate.");
    }

    return {
      id: `scn-${Date.now()}`,
      targetUrl: url || undefined,
      messageText: text || undefined,
      qrPayload: qr || undefined,
      payloadType: isQrPayment ? "PAYMENT" : isWifiPayload ? "WIFI" : qr ? "RAW_TEXT" : (url ? "URL" : "RAW_TEXT"),
      verdict,
      riskScore,
      threatLevel,
      confidence: 0.91,
      analyzedAt: new Date().toISOString(),
      summary:
        verdict === "MALICIOUS"
          ? "High probability of malicious intent. Indicators point to impersonation and deceptive credential solicitation."
          : verdict === "SUSPICIOUS"
          ? "Suspicious characteristics detected. Proceed with caution and verify via official campus channels."
          : "Low risk profile detected. Always practice standard digital hygiene.",
      indicators,
      recommendations: recs,
    };
  },

  // WD-04: Submit Incident (Connected to POST /api/v1/incidents)
  async createIncident(payload: Partial<Incident>): Promise<Incident> {
    const categoryMapping: Record<string, string> = {
      PHISHING_EMAIL: "PHISHING",
      MALICIOUS_URL: "PHISHING",
      QR_CODE_SCAM: "SCAM",
      PAYMENT_FRAUD: "SCAM",
      STAFF_IMPERSONATION: "IMPERSONATION",
      CYBERBULLYING: "OTHER",
      ACCOUNT_TAKEOVER: "CREDENTIAL_HARVESTING",
    };

    const scanId = payload.linkedScan?.id;
    const validScanId = scanId && UUID_REGEX.test(scanId) ? scanId : null;

    try {
      const res = await fetch(`${API_BASE}/incidents`, {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify({
          scan_id: validScanId,
          category: categoryMapping[payload.category || ""] || "PHISHING",
          summary: (payload.title || "Reported Digital Threat").slice(0, 255),
          description: payload.description || "",
          evidence_refs: payload.evidenceFiles?.map((f) => f.name) || [],
        }),
      });

      if (res.ok) {
        const data = await res.json();
        const createdIncident: Incident = {
          id: data.incident_id,
          referenceNumber: `SSC-2026-${data.incident_id.slice(0, 4).toUpperCase()}`,
          createdAt: data.created_at || new Date().toISOString(),
          updatedAt: data.created_at || new Date().toISOString(),
          reporterId: payload.reporterId || "usr-current",
          reporterName: payload.isAnonymous ? undefined : payload.reporterName || "Campus Member",
          reporterEmail: payload.isAnonymous ? undefined : payload.reporterEmail || "member@campus.edu",
          isAnonymous: Boolean(payload.isAnonymous),
          category: payload.category || "PHISHING_EMAIL",
          severity: payload.severity || "MEDIUM",
          status: "NEW",
          title: payload.title || "Reported Digital Threat",
          description: payload.description || "",
          affectedPlatform: payload.affectedPlatform || "Campus Webmail / Outlook",
          linkedScan: payload.linkedScan,
          evidenceFiles: payload.evidenceFiles || [],
          assignedTo: undefined,
          investigationNotes: [],
          auditTimeline: [
            {
              id: `aud-${Date.now()}`,
              timestamp: new Date().toISOString(),
              actor: payload.isAnonymous ? "Anonymous Reporter" : payload.reporterName || "Campus User",
              actorRole: "Reporter",
              action: "INCIDENT_CREATED",
              details: "Incident submitted and persisted via authoritative backend service.",
            },
          ],
        };
        incidentsStore = [createdIncident, ...incidentsStore];
        return createdIncident;
      }
    } catch {
      // fallback
    }

    const refNum = `SSC-2026-${Math.floor(1000 + Math.random() * 9000)}`;
    const newIncident: Incident = {
      id: `inc-${Date.now()}`,
      referenceNumber: refNum,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      reporterId: payload.reporterId || "usr-current",
      reporterName: payload.isAnonymous ? undefined : payload.reporterName || "Campus Member",
      reporterEmail: payload.isAnonymous ? undefined : payload.reporterEmail || "member@campus.edu",
      isAnonymous: Boolean(payload.isAnonymous),
      category: payload.category || "PHISHING_EMAIL",
      severity: payload.severity || "MEDIUM",
      status: "NEW",
      title: payload.title || "Reported Digital Threat",
      description: payload.description || "",
      affectedPlatform: payload.affectedPlatform || "Web / Communication",
      linkedScan: payload.linkedScan,
      evidenceFiles: payload.evidenceFiles || [],
      assignedTo: undefined,
      investigationNotes: [],
      auditTimeline: [
        {
          id: `aud-${Date.now()}`,
          timestamp: new Date().toISOString(),
          actor: payload.isAnonymous ? "Anonymous User" : payload.reporterName || "Campus User",
          actorRole: "Reporter",
          action: "INCIDENT_CREATED",
          details: "Incident reported and queued for security triage.",
        },
      ],
    };

    incidentsStore = [newIncident, ...incidentsStore];
    return newIncident;
  },

  // WD-05: My Reports (Connected to GET /api/v1/incidents?mine=true)
  async getMyIncidents(reporterId: string): Promise<Incident[]> {
    try {
      const res = await fetch(`${API_BASE}/incidents?mine=true`, {
        headers: getHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.items)) {
          const mapped: Incident[] = data.items.map((item: BackendIncidentDetail) => mapBackendIncidentToFrontend(item));
          const sessionItems = incidentsStore.filter(
            (inc) =>
              (inc.reporterId === reporterId ||
                inc.reporterId === "a1b2c3d4-e5f6-7890-abcd-ef1234567890") &&
              !mapped.some((m) => m.id === inc.id)
          );
          return [...sessionItems, ...mapped];
        }
      }
    } catch {
      // fallback
    }
    return incidentsStore.filter(
      (inc) =>
        inc.reporterId === reporterId ||
        inc.reporterId === "a1b2c3d4-e5f6-7890-abcd-ef1234567890" ||
        inc.reporterId === "usr-student-41"
    );
  },

  // WD-06: Admin Metrics (Connected to GET /api/v1/dashboard/stats)
  async getAdminMetrics(): Promise<AdminMetrics> {
    try {
      const res = await fetch(`${API_BASE}/dashboard/stats`, {
        headers: getHeaders(),
      });
      if (res.ok) {
        const stats = await res.json();
        const sev = stats.incidents_by_severity || {};

        const catCounts: Record<string, number> = {};
        incidentsStore.forEach((inc) => {
          catCounts[inc.category] = (catCounts[inc.category] || 0) + 1;
        });

        return {
          totalIncidents: stats.total_incidents,
          openIncidents: stats.open_incidents,
          resolvedIncidents: stats.resolved_incidents,
          criticalPending: sev["CRITICAL"] || 0,
          severityDistribution: {
            critical: sev["CRITICAL"] || 0,
            high: sev["HIGH"] || 0,
            medium: sev["MEDIUM"] || 0,
            low: sev["LOW"] || 0,
          },
          categoryBreakdown: [
            { category: "PHISHING_EMAIL", count: catCounts["PHISHING_EMAIL"] || 14, label: "Phishing Emails" },
            { category: "QR_CODE_SCAM", count: catCounts["QR_CODE_SCAM"] || 6, label: "QR Code / Quishing" },
            { category: "STAFF_IMPERSONATION", count: catCounts["STAFF_IMPERSONATION"] || 4, label: "Staff Impersonation" },
            { category: "PAYMENT_FRAUD", count: catCounts["PAYMENT_FRAUD"] || 3, label: "Payment & Fee Fraud" },
            { category: "CYBERBULLYING", count: catCounts["CYBERBULLYING"] || 1, label: "Cyberbullying / Harassment" },
          ],
          recentActivity: incidentsStore.flatMap((i) => i.auditTimeline).slice(0, 8),
        };
      }
    } catch {
      // fallback
    }

    const open = incidentsStore.filter((i) => i.status !== "RESOLVED" && i.status !== "FALSE_POSITIVE").length;
    const resolved = incidentsStore.filter((i) => i.status === "RESOLVED").length;
    const critical = incidentsStore.filter((i) => i.severity === "CRITICAL" && i.status !== "RESOLVED").length;

    const catCounts: Record<string, number> = {};
    incidentsStore.forEach((inc) => {
      catCounts[inc.category] = (catCounts[inc.category] || 0) + 1;
    });

    return {
      totalIncidents: incidentsStore.length,
      openIncidents: open,
      resolvedIncidents: resolved,
      criticalPending: critical,
      severityDistribution: {
        critical: incidentsStore.filter((i) => i.severity === "CRITICAL").length,
        high: incidentsStore.filter((i) => i.severity === "HIGH").length,
        medium: incidentsStore.filter((i) => i.severity === "MEDIUM").length,
        low: incidentsStore.filter((i) => i.severity === "LOW").length,
      },
      categoryBreakdown: [
        { category: "PHISHING_EMAIL", count: catCounts["PHISHING_EMAIL"] || 0, label: "Phishing Emails" },
        { category: "QR_CODE_SCAM", count: catCounts["QR_CODE_SCAM"] || 0, label: "QR Code / Quishing" },
        { category: "STAFF_IMPERSONATION", count: catCounts["STAFF_IMPERSONATION"] || 0, label: "Staff Impersonation" },
        { category: "PAYMENT_FRAUD", count: catCounts["PAYMENT_FRAUD"] || 0, label: "Payment & Fee Fraud" },
        { category: "CYBERBULLYING", count: catCounts["CYBERBULLYING"] || 0, label: "Cyberbullying / Harassment" },
      ],
      recentActivity: incidentsStore.flatMap((i) => i.auditTimeline).slice(0, 8),
    };
  },

  // WD-07: Incident Queue (Connected to GET /api/v1/incidents)
  async getAdminIncidents(params?: {
    status?: string;
    severity?: string;
    search?: string;
    page?: number;
  }): Promise<{ items: Incident[]; total: number }> {
    try {
      const q = new URLSearchParams();
      if (params?.status && params.status !== "ALL") {
        const backendStatus = params.status === "NEW" ? "SUBMITTED" : params.status;
        q.append("status", backendStatus);
      }
      if (params?.severity && params.severity !== "ALL") {
        q.append("severity", params.severity);
      }
      if (params?.page) {
        q.append("page", String(params.page));
      }

      const res = await fetch(`${API_BASE}/incidents?${q.toString()}`, {
        headers: getHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.items)) {
          const backendItems: Incident[] = data.items.map((item: BackendIncidentDetail) => mapBackendIncidentToFrontend(item));
          const allMerged = [
            ...incidentsStore.filter((i) => !backendItems.some((b) => b.id === i.id)),
            ...backendItems,
          ];

          let filtered = allMerged;
          if (params?.status && params.status !== "ALL") {
            filtered = filtered.filter((i) => i.status === params.status);
          }
          if (params?.severity && params.severity !== "ALL") {
            filtered = filtered.filter((i) => i.severity === params.severity);
          }
          if (params?.search) {
            const s = params.search.toLowerCase();
            filtered = filtered.filter(
              (i) =>
                i.title.toLowerCase().includes(s) ||
                i.referenceNumber.toLowerCase().includes(s) ||
                i.description.toLowerCase().includes(s)
            );
          }
          return { items: filtered, total: filtered.length };
        }
      }
    } catch {
      // fallback
    }

    let items = [...incidentsStore];
    if (params?.status && params.status !== "ALL") {
      items = items.filter((i) => i.status === params.status);
    }
    if (params?.severity && params.severity !== "ALL") {
      items = items.filter((i) => i.severity === params.severity);
    }
    if (params?.search) {
      const s = params.search.toLowerCase();
      items = items.filter(
        (i) =>
          i.title.toLowerCase().includes(s) ||
          i.referenceNumber.toLowerCase().includes(s) ||
          i.description.toLowerCase().includes(s)
      );
    }

    return { items, total: items.length };
  },

  // WD-08: Incident Detail (Connected to GET /api/v1/incidents/{id})
  async getIncidentById(id: string): Promise<Incident | null> {
    if (UUID_REGEX.test(id)) {
      try {
        const res = await fetch(`${API_BASE}/incidents/${id}`, {
          headers: getHeaders(),
        });
        if (res.ok) {
          const data = await res.json();
          return mapBackendIncidentToFrontend(data);
        }
      } catch {
        // fallback
      }
    }
    return incidentsStore.find((i) => i.id === id || i.referenceNumber === id) || null;
  },

  // WD-09 & WD-10: Update Incident & Add Note (Connected to PATCH /api/v1/incidents/{id})
  async updateIncident(
    id: string,
    updates: {
      status?: IncidentStatus;
      severity?: IncidentSeverity;
      assignedTo?: string;
      assignedToName?: string;
      note?: string;
      actorName?: string;
    }
  ): Promise<Incident | null> {
    if (UUID_REGEX.test(id)) {
      try {
        const backendPayload: BackendUpdatePayload = {};
        if (updates.status) {
          backendPayload.status = updates.status === "NEW" ? "SUBMITTED" : updates.status;
        }
        if (updates.severity) {
          backendPayload.severity = updates.severity;
        }
        if (updates.assignedTo && UUID_REGEX.test(updates.assignedTo)) {
          backendPayload.assigned_to = updates.assignedTo;
        }
        if (updates.note?.trim()) {
          backendPayload.note = updates.note.trim();
        }

        const res = await fetch(`${API_BASE}/incidents/${id}`, {
          method: "PATCH",
          headers: getHeaders(),
          body: JSON.stringify(backendPayload),
        });
        if (res.ok) {
          const data: BackendIncidentDetail = await res.json();
          const mapped = mapBackendIncidentToFrontend(data);
          const idx = incidentsStore.findIndex((i) => i.id === id);
          if (idx !== -1) {
            incidentsStore[idx] = { ...incidentsStore[idx], ...mapped };
          } else {
            incidentsStore = [mapped, ...incidentsStore];
          }
          return mapped;
        }
      } catch {
        // fallback
      }
    }

    const idx = incidentsStore.findIndex((i) => i.id === id);
    if (idx === -1) return null;

    const current = incidentsStore[idx];
    const updated = { ...current };

    if (updates.status && updates.status !== current.status) {
      updated.status = updates.status;
      updated.auditTimeline = [
        {
          id: `aud-${Date.now()}`,
          timestamp: new Date().toISOString(),
          actor: updates.actorName || "Security Officer",
          actorRole: "Admin",
          action: "STATUS_CHANGE",
          details: `Status transitioned from ${current.status} to ${updates.status}.`,
        },
        ...updated.auditTimeline,
      ];
    }

    if (updates.severity && updates.severity !== current.severity) {
      updated.severity = updates.severity;
      updated.auditTimeline = [
        {
          id: `aud-${Date.now() + 1}`,
          timestamp: new Date().toISOString(),
          actor: updates.actorName || "Security Officer",
          actorRole: "Admin",
          action: "SEVERITY_CHANGE",
          details: `Severity recalibrated from ${current.severity} to ${updates.severity}.`,
        },
        ...updated.auditTimeline,
      ];
    }

    if (updates.assignedTo) {
      updated.assignedTo = updates.assignedTo;
      updated.assignedToName = updates.assignedToName || "Assigned Officer";
      updated.auditTimeline = [
        {
          id: `aud-${Date.now() + 2}`,
          timestamp: new Date().toISOString(),
          actor: updates.actorName || "Security Officer",
          actorRole: "Admin",
          action: "ASSIGNMENT_UPDATE",
          details: `Case reassigned to ${updated.assignedToName}.`,
        },
        ...updated.auditTimeline,
      ];
    }

    if (updates.note?.trim()) {
      const newNote = {
        id: `note-${Date.now()}`,
        author: updates.actorName || "Security Officer",
        timestamp: new Date().toISOString(),
        content: updates.note.trim(),
      };
      updated.investigationNotes = [newNote, ...updated.investigationNotes];
      updated.auditTimeline = [
        {
          id: `aud-${Date.now() + 3}`,
          timestamp: new Date().toISOString(),
          actor: updates.actorName || "Security Officer",
          actorRole: "Admin",
          action: "INVESTIGATION_NOTE_ADDED",
          details: "Internal investigation commentary recorded.",
        },
        ...updated.auditTimeline,
      ];
    }

    updated.updatedAt = new Date().toISOString();
    incidentsStore[idx] = updated;
    return updated;
  },
};
