export type UserRole = "student" | "faculty" | "security_admin";

export interface UserProfile {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  campusId: string;
  department: string;
  token?: string;
}

export type ThreatLevel = "SAFE" | "LOW" | "SUSPICIOUS" | "HIGH" | "CRITICAL";

export interface ScanIndicator {
  type: "DOMAIN_AGE" | "TYPOSQUAT" | "URGENCY_LANGUAGE" | "UNVERIFIED_PAYMENT" | "CREDENTIAL_HARVEST" | "REPUTATION";
  label: string;
  description: string;
  severity: "info" | "warning" | "danger";
}

export interface ScanResult {
  id: string;
  targetUrl?: string;
  messageText?: string;
  qrPayload?: string;
  payloadType?: string;
  extractedUrls?: string[];
  analysisScope?: string;
  verdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "UNCERTAIN";
  riskScore: number; // 0 - 100
  threatLevel: ThreatLevel;
  confidence: number; // 0.0 - 1.0
  analyzedAt: string;
  summary: string;
  indicators: ScanIndicator[];
  recommendations: string[];
  rawFeatures?: Record<string, number | string | boolean>;
}

export type IncidentCategory =
  | "PHISHING_EMAIL"
  | "MALICIOUS_URL"
  | "QR_CODE_SCAM"
  | "PAYMENT_FRAUD"
  | "STAFF_IMPERSONATION"
  | "CYBERBULLYING"
  | "ACCOUNT_TAKEOVER";

export type IncidentStatus =
  | "NEW"
  | "TRIAGED"
  | "INVESTIGATING"
  | "CONTAINED"
  | "RESOLVED"
  | "FALSE_POSITIVE";

export type IncidentSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface EvidenceFile {
  id: string;
  name: string;
  sizeBytes: number;
  mimeType: string;
  uploadedAt: string;
}

export interface IncidentAuditEntry {
  id: string;
  timestamp: string;
  actor: string;
  actorRole: string;
  action: string;
  details: string;
}

export interface InvestigationNote {
  id: string;
  author: string;
  timestamp: string;
  content: string;
}

export interface Incident {
  id: string;
  referenceNumber: string; // e.g. SSC-2026-8912
  createdAt: string;
  updatedAt: string;
  reporterId: string;
  reporterName?: string;
  reporterEmail?: string;
  isAnonymous: boolean;
  category: IncidentCategory;
  severity: IncidentSeverity;
  status: IncidentStatus;
  title: string;
  description: string;
  affectedPlatform: string;
  linkedScan?: ScanResult;
  evidenceFiles: EvidenceFile[];
  assignedTo?: string;
  assignedToName?: string;
  investigationNotes: InvestigationNote[];
  auditTimeline: IncidentAuditEntry[];
}

export interface AdminMetrics {
  totalIncidents: number;
  openIncidents: number;
  resolvedIncidents: number;
  criticalPending: number;
  severityDistribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  categoryBreakdown: {
    category: IncidentCategory;
    count: number;
    label: string;
  }[];
  recentActivity: IncidentAuditEntry[];
}
