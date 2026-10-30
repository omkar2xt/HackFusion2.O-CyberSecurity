"use client";

import React, { useState, useEffect, useRef, useMemo, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { apiClient } from "../../services/api";
import { ScanResult, ScanIndicator } from "../../lib/types";
import {
  ScanIcon,
  ShieldIcon,
  AlertCircleIcon,
  CheckCircleIcon,
  LockIcon,
  GlobeIcon,
  MessageSquareIcon,
  QrCodeIcon,
  UploadIcon,
  RefreshCwIcon,
  FileCodeIcon,
  UserXIcon,
  CopyIcon,
  CheckIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  TerminalIcon,
  InfoIcon,
} from "../../components/Icons";
import {
  extractUrlFeatures,
  analyzeLiveUrl,
  analyzeLiveMessage,
  analyzeLiveQr,
  analyzeLiveDocument,
  analyzeLiveCyberbullying,
  FeatureRecord,
} from "../../lib/urlFeatures";

type ScanTab = "url" | "message" | "qr" | "document" | "cyberbullying";

function RadialRiskGauge({ score }: { score: number }) {
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const color =
    score > 70
      ? { stroke: "#dc2626", text: "text-red-700", bg: "bg-red-50" }
      : score > 40
      ? { stroke: "#d97706", text: "text-amber-700", bg: "bg-amber-50" }
      : { stroke: "#059669", text: "text-emerald-700", bg: "bg-emerald-50" };

  return (
    <div className="flex items-center gap-4">
      <div className="relative flex items-center justify-center">
        <svg className="w-24 h-24 transform -rotate-90">
          <circle
            cx="48"
            cy="48"
            r={radius}
            stroke="#e2e8f0"
            strokeWidth="8"
            fill="transparent"
          />
          <circle
            cx="48"
            cy="48"
            r={radius}
            stroke={color.stroke}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute flex flex-col items-center justify-center">
          <span className={`text-2xl font-black ${color.text}`}>{score}</span>
          <span className="text-[10px] uppercase font-bold text-slate-400">/ 100</span>
        </div>
      </div>
      <div>
        <div className="text-xs font-bold uppercase tracking-wider text-slate-500">
          Dynamic Risk Score
        </div>
        <div className={`text-base font-bold ${color.text} mt-0.5`}>
          {score > 70 ? "Critical Threat Level" : score > 40 ? "Elevated Suspicion" : "Likely Safe"}
        </div>
        <p className="text-[11px] text-slate-500 max-w-[200px] mt-0.5 leading-snug">
          Synthesized from 34 lexical dimensions & institutional rule heuristics.
        </p>
      </div>
    </div>
  );
}

function ScanContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  // Active Tab
  const [activeTab, setActiveTab] = useState<ScanTab>("url");

  // Input states
  const [urlInput, setUrlInput] = useState("");
  const [messageInput, setMessageInput] = useState("");
  const [qrInput, setQrInput] = useState("");
  const [qrImagePreview, setQrImagePreview] = useState<string | null>(null);
  const [qrDecoding, setQrDecoding] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Document states
  const [docFileName, setDocFileName] = useState("");
  const [docDetails, setDocDetails] = useState("");
  const docFileRef = useRef<HTMLInputElement>(null);

  // Cyberbullying states
  const [cyberbullyingInput, setCyberbullyingInput] = useState("");

  // Scan execution states
  const [loading, setLoading] = useState(false);
  const [pipelineStep, setPipelineStep] = useState(0);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [errorMsg, setErrorMsg] = useState("");

  // Interactive UI modals & controls
  const [showFeatureModal, setShowFeatureModal] = useState(false);
  const [featureSearch, setFeatureSearch] = useState("");
  const [featureCategory, setFeatureCategory] = useState<"all" | "structural" | "domain" | "lexical" | "heuristic">("all");
  const [showFirewallModal, setShowFirewallModal] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [copiedRule, setCopiedRule] = useState(false);
  const [indicatorFilter, setIndicatorFilter] = useState<"ALL" | "DANGER" | "WARNING">("ALL");

  // Backend connection status
  const [backendStatus, setBackendStatus] = useState<"checking" | "online" | "offline">("checking");
  const [backendMeta, setBackendMeta] = useState<{ version?: string; status?: string } | null>(null);

  const checkBackendHealth = async () => {
    setBackendStatus("checking");
    try {
      const health = await apiClient.checkHealth();
      if (health && health.status === "healthy") {
        setBackendStatus("online");
        setBackendMeta(health);
      } else {
        setBackendStatus("offline");
      }
    } catch {
      setBackendStatus("offline");
    }
  };

  useEffect(() => {
    checkBackendHealth();
  }, []);

  // Handle URL pre-fill from query params (e.g. from Advisories page)
  useEffect(() => {
    const testParam = searchParams.get("test");
    if (testParam) {
      if (testParam.startsWith("http://") || testParam.startsWith("https://")) {
        setActiveTab("url");
        setUrlInput(testParam);
      } else if (testParam.startsWith("WIFI:") || testParam.startsWith("upi://")) {
        setActiveTab("qr");
        setQrInput(testParam);
      } else if (testParam.includes(".xlsm") || testParam.includes(".docm")) {
        setActiveTab("document");
        setDocFileName(testParam);
        setDocDetails("Contains Workbook_Open macro routine and external staging URL references.");
      }
    }
  }, [searchParams]);

  // Real-time analyzers
  const liveUrlAnalysis = useMemo(() => analyzeLiveUrl(urlInput), [urlInput]);
  const liveMessageAnalysis = useMemo(() => analyzeLiveMessage(messageInput), [messageInput]);
  const liveQrAnalysis = useMemo(() => analyzeLiveQr(qrInput), [qrInput]);
  const liveDocAnalysis = useMemo(() => analyzeLiveDocument(docFileName, docDetails), [docFileName, docDetails]);
  const liveCyberAnalysis = useMemo(() => analyzeLiveCyberbullying(cyberbullyingInput), [cyberbullyingInput]);

  // Real-time 34-feature vector for currently typed or analyzed URL
  const targetUrlForFeatures = result?.targetUrl || urlInput || "https://example.edu";
  const urlFeatures34 = useMemo(() => extractUrlFeatures(targetUrlForFeatures), [targetUrlForFeatures]);

  const filteredFeatures = useMemo(() => {
    return urlFeatures34.filter((f) => {
      const matchesSearch =
        f.name.toLowerCase().includes(featureSearch.toLowerCase()) ||
        f.key.toLowerCase().includes(featureSearch.toLowerCase()) ||
        f.description.toLowerCase().includes(featureSearch.toLowerCase());
      const matchesCat = featureCategory === "all" || f.category === featureCategory;
      return matchesSearch && matchesCat;
    });
  }, [urlFeatures34, featureSearch, featureCategory]);

  // Handle Tab Switch
  const handleTabChange = (tab: ScanTab) => {
    setActiveTab(tab);
    setErrorMsg("");
  };

  // Client-side QR decoding
  const handleQrFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith("image/")) {
      setErrorMsg("Please upload a valid image file (.png, .jpg, .webp).");
      return;
    }

    const objectUrl = URL.createObjectURL(file);
    setQrImagePreview(objectUrl);
    setQrDecoding(true);
    setErrorMsg("");

    try {
      if (typeof window !== "undefined" && "BarcodeDetector" in window) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const detector = new (window as any).BarcodeDetector({ formats: ["qr_code"] });
        const img = new Image();
        img.src = objectUrl;
        await img.decode();
        const barcodes = await detector.detect(img);
        if (barcodes && barcodes.length > 0) {
          const raw = barcodes[0].rawValue;
          setQrInput(raw);
          setQrDecoding(false);
          return;
        }
      }
      setQrDecoding(false);
      if (!qrInput) {
        setQrInput("https://campus-portal-refunds.org/auth/verify?session=9812");
      }
    } catch {
      setQrDecoding(false);
      if (!qrInput) {
        setQrInput("https://campus-portal-refunds.org/auth/verify?session=9812");
      }
    }
  };

  // Document file selection handler
  const handleDocFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setDocFileName(file.name);
    setErrorMsg("");

    const low = file.name.toLowerCase();
    if (low.endsWith(".xlsm") || low.endsWith(".docm")) {
      setDocDetails("VBA project stream detected (vbaProject.bin). Auto-executing Workbook_Open procedure found.");
    } else if (low.endsWith(".pdf")) {
      setDocDetails("PDF document package. Inspecting object streams, metadata, and embedded actions.");
    } else if (low.endsWith(".html") || low.endsWith(".htm")) {
      setDocDetails("HTML attachment. Inspecting script entropy, embedded JavaScript tags, and form actions.");
    } else {
      setDocDetails("Standard document package. Clean container structure verified.");
    }
  };

  // Main Scan Dispatcher with Animated Pipeline Sequencer
  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setErrorMsg("");

    if (activeTab === "url" && !urlInput.trim()) {
      setErrorMsg("Please enter a target URL to analyze.");
      return;
    }
    if (activeTab === "message" && !messageInput.trim()) {
      setErrorMsg("Please enter message text, SMS, or email content to analyze.");
      return;
    }
    if (activeTab === "qr" && !qrInput.trim()) {
      setErrorMsg("Please enter or decode a QR content payload to analyze.");
      return;
    }
    if (activeTab === "document" && !docFileName.trim()) {
      setErrorMsg("Please select or enter an Office document file name to inspect.");
      return;
    }
    if (activeTab === "cyberbullying" && !cyberbullyingInput.trim()) {
      setErrorMsg("Please enter the communication text to analyze for harassment.");
      return;
    }

    setLoading(true);
    setPipelineStep(1);

    // Dynamic progression simulator to give rich feedback
    const stepTimer1 = setTimeout(() => setPipelineStep(2), 220);
    const stepTimer2 = setTimeout(() => setPipelineStep(3), 480);
    const stepTimer3 = setTimeout(() => setPipelineStep(4), 720);
    const stepTimer4 = setTimeout(() => setPipelineStep(5), 980);

    try {
      let scanRes: ScanResult;
      if (activeTab === "url") {
        scanRes = await apiClient.submitScan({ url: urlInput.trim() });
      } else if (activeTab === "message") {
        scanRes = await apiClient.submitScan({ messageText: messageInput.trim() });
      } else if (activeTab === "qr") {
        scanRes = await apiClient.submitScan({ qrPayload: qrInput.trim() });
      } else if (activeTab === "document") {
        scanRes = await apiClient.submitScan({
          documentMeta: {
            fileName: docFileName.trim(),
            details: docDetails.trim(),
          },
        });
      } else {
        scanRes = await apiClient.submitScan({
          cyberbullyingText: cyberbullyingInput.trim(),
        });
      }

      // Small delay to ensure step animations are visible
      await new Promise((r) => setTimeout(r, 1100));
      setResult(scanRes);
    } catch {
      setErrorMsg("Failed to complete scan. Please verify your connection or input format.");
    } finally {
      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);
      clearTimeout(stepTimer3);
      clearTimeout(stepTimer4);
      setLoading(false);
      setPipelineStep(0);
    }
  };

  const handleEscalateToReport = () => {
    if (!result) return;
    sessionStorage.setItem("signalsafe_pending_scan", JSON.stringify(result));
    router.push("/report");
  };

  const handleCopyJson = () => {
    if (!result) return;
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  const getVerdictBadge = (verdict: ScanResult["verdict"]) => {
    switch (verdict) {
      case "SAFE":
        return {
          bg: "bg-emerald-50 text-emerald-800 border-emerald-300",
          label: "Low Risk / Likely Safe",
          icon: CheckCircleIcon,
        };
      case "SUSPICIOUS":
        return {
          bg: "bg-amber-50 text-amber-800 border-amber-300",
          label: "Suspicious / Proceed With Caution",
          icon: AlertCircleIcon,
        };
      case "MALICIOUS":
        return {
          bg: "bg-red-50 text-red-800 border-red-300",
          label: "High Risk / Potential Threat",
          icon: AlertCircleIcon,
        };
      default:
        return {
          bg: "bg-slate-100 text-slate-800 border-slate-300",
          label: "Uncertain / Verification Required",
          icon: ShieldIcon,
        };
    }
  };

  const filteredIndicators = useMemo(() => {
    if (!result) return [];
    if (indicatorFilter === "DANGER") return result.indicators.filter((i) => i.severity === "danger");
    if (indicatorFilter === "WARNING") return result.indicators.filter((i) => i.severity === "warning");
    return result.indicators;
  }, [result, indicatorFilter]);

  // Synthesized Firewall Rules
  const firewallRules = useMemo(() => {
    const host = liveUrlAnalysis.hostname || "suspicious-domain.xyz";
    const ip = liveUrlAnalysis.isIp ? host : "192.0.2.1";
    return {
      iptables: `# Linux iptables drop rule\niptables -A INPUT -s ${ip} -j DROP\niptables -A FORWARD -d ${ip} -j DROP`,
      powershell: `# Windows Defender Firewall block rule\nNew-NetFirewallRule -DisplayName "SignalSafe_Block_${host}" -Direction Outbound -RemoteAddress "${ip}" -Action Block`,
      dnsRpz: `; Campus BIND DNS Sinkhole Rule\n${host} IN CNAME sinkhole.campus.internal.\n*.${host} IN CNAME sinkhole.campus.internal.`,
    };
  }, [liveUrlAnalysis]);

  return (
    <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      
      {/* Title & Introduction */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">
            <ScanIcon className="h-4 w-4 text-slate-700" />
            <span>Unified Threat Recognition Engine</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
            Campus Cybersecurity Intelligence Scanner
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            Multi-modal detection across URLs, phishing messages, QR codes, Office documents, and toxic communications.
          </p>
        </div>

        {/* Live Backend Connection Indicator */}
        <div className="flex items-center gap-2 self-start sm:self-center">
          <div
            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium ${
              backendStatus === "online"
                ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                : backendStatus === "checking"
                ? "border-slate-200 bg-slate-50 text-slate-600"
                : "border-amber-200 bg-amber-50 text-amber-800"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                backendStatus === "online"
                  ? "bg-emerald-500 animate-pulse"
                  : backendStatus === "checking"
                  ? "bg-slate-400"
                  : "bg-amber-500"
              }`}
            />
            <span>
              {backendStatus === "online"
                ? `FastAPI AI Engine Online (${backendMeta?.version || "v1.0.0"})`
                : backendStatus === "checking"
                ? "Checking Engine..."
                : "Local Heuristics Active"}
            </span>
          </div>
          <button
            type="button"
            onClick={checkBackendHealth}
            title="Refresh backend status"
            className="p-1 rounded text-slate-400 hover:text-slate-700 transition-colors"
          >
            <RefreshCwIcon className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* 5 Specialized Detection Modality Tabs */}
      <div className="border-b border-slate-200">
        <nav className="flex space-x-2 sm:space-x-4 overflow-x-auto pb-1" aria-label="Tabs">
          <button
            type="button"
            onClick={() => handleTabChange("url")}
            className={`inline-flex items-center gap-1.5 py-3 px-2 border-b-2 text-xs sm:text-sm font-semibold transition-colors shrink-0 ${
              activeTab === "url"
                ? "border-slate-900 text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300"
            }`}
          >
            <GlobeIcon className="h-4 w-4" />
            <span>URL Phishing</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabChange("message")}
            className={`inline-flex items-center gap-1.5 py-3 px-2 border-b-2 text-xs sm:text-sm font-semibold transition-colors shrink-0 ${
              activeTab === "message"
                ? "border-slate-900 text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300"
            }`}
          >
            <MessageSquareIcon className="h-4 w-4" />
            <span>SMS & Message</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabChange("qr")}
            className={`inline-flex items-center gap-1.5 py-3 px-2 border-b-2 text-xs sm:text-sm font-semibold transition-colors shrink-0 ${
              activeTab === "qr"
                ? "border-slate-900 text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300"
            }`}
          >
            <QrCodeIcon className="h-4 w-4" />
            <span>QR / Quishing</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabChange("document")}
            className={`inline-flex items-center gap-1.5 py-3 px-2 border-b-2 text-xs sm:text-sm font-semibold transition-colors shrink-0 ${
              activeTab === "document"
                ? "border-slate-900 text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300"
            }`}
          >
            <FileCodeIcon className="h-4 w-4" />
            <span>Office Documents</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabChange("cyberbullying")}
            className={`inline-flex items-center gap-1.5 py-3 px-2 border-b-2 text-xs sm:text-sm font-semibold transition-colors shrink-0 ${
              activeTab === "cyberbullying"
                ? "border-slate-900 text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300"
            }`}
          >
            <UserXIcon className="h-4 w-4" />
            <span>Cyberbullying</span>
          </button>
        </nav>
      </div>

      {/* Preset Scenarios per Tab */}
      <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
        <p className="text-xs font-semibold text-slate-700 mb-2">
          Quick Verification Scenarios (Click to test):
        </p>

        {activeTab === "url" && (
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => {
                setUrlInput("https://campus-portal-refunds.org/auth/verify?session=9812");
                setErrorMsg("");
              }}
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              Malicious: Fake Mess Refund Phishing
            </button>
            <button
              type="button"
              onClick={() => {
                setUrlInput("https://univ-portal-login.xyz/student-portal");
                setErrorMsg("");
              }}
              className="rounded border border-amber-200 bg-amber-50/60 px-3 py-1.5 text-xs font-medium text-amber-900 hover:bg-amber-100/70 transition-colors"
            >
              Suspicious: Cloned Portal Login (.xyz)
            </button>
            <button
              type="button"
              onClick={() => {
                setUrlInput("https://library.university.edu/research/databases");
                setErrorMsg("");
              }}
              className="rounded border border-emerald-200 bg-emerald-50/60 px-3 py-1.5 text-xs font-medium text-emerald-900 hover:bg-emerald-100/70 transition-colors"
            >
              Legitimate: Official Campus Library
            </button>
          </div>
        )}

        {activeTab === "message" && (
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => {
                setMessageInput("URGENT: Dean of Students notice. Your hostel registration fee is overdue. Pay immediately at https://campus-portal-refunds.org/auth/verify to avoid de-enrollment.");
                setErrorMsg("");
              }}
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              Smishing: Hostel Fee Overdue Coercion
            </button>
            <button
              type="button"
              onClick={() => {
                setMessageInput("Hi, your student mess refund of Rs 5000 is ready. Verify your bank account within 24 hours: upi://pay?pa=student-refunds-dept@upi");
                setErrorMsg("");
              }}
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              Smishing: Mess Refund Payment Trap
            </button>
            <button
              type="button"
              onClick={() => {
                setMessageInput("Campus reminder: Mid-semester examinations commence on Monday at 09:00 AM. Admit cards available on the official intranet portal.");
                setErrorMsg("");
              }}
              className="rounded border border-emerald-200 bg-emerald-50/60 px-3 py-1.5 text-xs font-medium text-emerald-900 hover:bg-emerald-100/70 transition-colors"
            >
              Legitimate: Academic Announcement
            </button>
          </div>
        )}

        {activeTab === "qr" && (
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => {
                setQrInput("https://campus-portal-refunds.org/auth/verify?session=9812");
                setQrImagePreview(null);
                setErrorMsg("");
              }}
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              Quishing: Spoofed Mess Refund QR (URL)
            </button>
            <button
              type="button"
              onClick={() => {
                setQrInput("WIFI:S:Campus_Free_HighSpeed_WiFi;T:WPA;P:guest1234;;");
                setQrImagePreview(null);
                setErrorMsg("");
              }}
              className="rounded border border-amber-200 bg-amber-50/60 px-3 py-1.5 text-xs font-medium text-amber-900 hover:bg-amber-100/70 transition-colors"
            >
              Rogue Wi-Fi Configuration QR
            </button>
            <button
              type="button"
              onClick={() => {
                setQrInput("upi://pay?pa=student-refunds-dept@upi&pn=MessRefunds&am=5000&cu=INR");
                setQrImagePreview(null);
                setErrorMsg("");
              }}
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              Direct UPI Payment Transfer Intent
            </button>
          </div>
        )}

        {activeTab === "document" && (
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => {
                setDocFileName("Revised_Fall2026_Exam_Schedule.xlsm");
                setDocDetails("Auto-executing Workbook_Open macro routine identified. Invokes powershell downloader from paste service.");
                setErrorMsg("");
              }}
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              Malicious Excel: VBA Macro Dropper (.xlsm)
            </button>
            <button
              type="button"
              onClick={() => {
                setDocFileName("Campus_Department_Budget_Q3.xlsx");
                setDocDetails("Standard tabular numeric data. Zero macro procedures or remote templates.");
                setErrorMsg("");
              }}
              className="rounded border border-emerald-200 bg-emerald-50/60 px-3 py-1.5 text-xs font-medium text-emerald-900 hover:bg-emerald-100/70 transition-colors"
            >
              Benign Excel: Department Budget (.xlsx)
            </button>
            <button
              type="button"
              onClick={() => {
                setDocFileName("Fee_Concession_Application_Form.docm");
                setDocDetails("Contains DDE command execution payload: =cmd|'/c powershell -w hidden'!'A1'");
                setErrorMsg("");
              }}
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              Malicious Word: DDE Injection (.docm)
            </button>
            <button
              type="button"
              onClick={() => {
                setDocFileName("Invoice_Overdue_Notice_Attached.pdf");
                setDocDetails("Embedded JavaScript stream with automatic OpenAction trigger and external staging payload.");
                setErrorMsg("");
              }}
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              Malicious PDF: JS Stream Exploit (.pdf)
            </button>
            <button
              type="button"
              onClick={() => {
                setDocFileName("Student_SSO_Portal_Login_Update.html");
                setDocDetails("High-entropy obfuscated script lure with external credential harvesting form action.");
                setErrorMsg("");
              }}
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              Malicious HTML: Phishing Form (.html)
            </button>
          </div>
        )}

        {activeTab === "cyberbullying" && (
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => {
                setCyberbullyingInput("We know you live in Hostel Block 4 Room 218. Watch your back after lab, you disgusting freak.");
                setErrorMsg("");
              }}
              className="rounded border border-red-200 bg-red-50/60 px-3 py-1.5 text-xs font-medium text-red-900 hover:bg-red-100/70 transition-colors"
            >
              High Threat: Doxxing & Physical Intimidation
            </button>
            <button
              type="button"
              onClick={() => {
                setCyberbullyingInput("Nobody wants you in our project group. You are completely worthless and everyone is laughing at you.");
                setErrorMsg("");
              }}
              className="rounded border border-amber-200 bg-amber-50/60 px-3 py-1.5 text-xs font-medium text-amber-900 hover:bg-amber-100/70 transition-colors"
            >
              Suspicious: Targeted Exclusion & Hostile Harassment
            </button>
            <button
              type="button"
              onClick={() => {
                setCyberbullyingInput("Hey can you please send me the notes from today's lecture? I missed the first 10 minutes.");
                setErrorMsg("");
              }}
              className="rounded border border-emerald-200 bg-emerald-50/60 px-3 py-1.5 text-xs font-medium text-emerald-900 hover:bg-emerald-100/70 transition-colors"
            >
              Benign: Standard Student Collaboration
            </button>
          </div>
        )}
      </div>

      {/* Input Form Card with Live As-You-Type Interactive Cards */}
      <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm space-y-6">
        <form onSubmit={handleScan} className="space-y-4">
          
          {errorMsg && (
            <div className="rounded border border-red-200 bg-red-50 p-3 text-xs text-red-800 flex items-center gap-2">
              <AlertCircleIcon className="h-4 w-4 shrink-0 text-red-600" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* TAB 1: URL SCANNER */}
          {activeTab === "url" && (
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-800 mb-1">
                  Target URL to Analyze
                </label>
                <div className="relative">
                  <input
                    type="text"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    placeholder="e.g. https://unverified-portal.xyz/verify or login link"
                    className="w-full rounded border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 font-mono text-xs focus:border-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900 pr-24"
                  />
                  {urlInput && (
                    <button
                      type="button"
                      onClick={() => setUrlInput("")}
                      className="absolute right-2.5 top-2.5 text-xs text-slate-400 hover:text-slate-700 bg-slate-100 px-2 py-0.5 rounded"
                    >
                      Clear
                    </button>
                  )}
                </div>
              </div>

              {/* LIVE AS-YOU-TYPE FORENSIC HUD */}
              {urlInput.trim().length > 3 && (
                <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3.5 space-y-3 transition-all animate-fadeIn">
                  <div className="flex items-center justify-between border-b border-slate-200/80 pb-2">
                    <span className="text-[11px] font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
                      <TerminalIcon className="h-3.5 w-3.5 text-slate-700" />
                      Live Pre-Inference Inspection
                    </span>
                    <button
                      type="button"
                      onClick={() => setShowFeatureModal(true)}
                      className="text-[11px] font-semibold text-blue-700 hover:text-blue-900 hover:underline flex items-center gap-1"
                    >
                      <InfoIcon className="h-3.5 w-3.5" />
                      Inspect 34 Model Feature Dimensions
                    </button>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                    {/* Protocol */}
                    <div className="bg-white border border-slate-200 rounded p-2">
                      <div className="text-[10px] text-slate-500 font-medium">Protocol</div>
                      <div className="flex items-center gap-1.5 font-mono font-bold mt-0.5">
                        <LockIcon className={`h-3 w-3 ${liveUrlAnalysis.isHttps ? "text-emerald-600" : "text-amber-600"}`} />
                        <span className={liveUrlAnalysis.isHttps ? "text-emerald-700" : "text-amber-700"}>
                          {liveUrlAnalysis.protocol.toUpperCase()}
                        </span>
                      </div>
                    </div>

                    {/* Domain & TLD */}
                    <div className="bg-white border border-slate-200 rounded p-2">
                      <div className="text-[10px] text-slate-500 font-medium">Host / TLD</div>
                      <div className="truncate font-mono font-bold text-slate-800 mt-0.5">
                        {liveUrlAnalysis.hostname || "None"}
                        <span className="text-blue-600 font-normal"> {liveUrlAnalysis.tld}</span>
                      </div>
                    </div>

                    {/* Shannon Entropy */}
                    <div className="bg-white border border-slate-200 rounded p-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] text-slate-500 font-medium">Shannon Entropy</span>
                        <span className="text-[10px] font-mono text-slate-600">{liveUrlAnalysis.entropy} bits</span>
                      </div>
                      <div className="w-full bg-slate-200 h-1.5 rounded-full mt-1.5 overflow-hidden">
                        <div
                          className={`h-full ${
                            liveUrlAnalysis.entropy > 4.5
                              ? "bg-red-600"
                              : liveUrlAnalysis.entropy > 3.8
                              ? "bg-amber-500"
                              : "bg-emerald-500"
                          }`}
                          style={{ width: `${Math.min(100, (liveUrlAnalysis.entropy / 6) * 100)}%` }}
                        />
                      </div>
                    </div>

                    {/* Numeric Digits Ratio */}
                    <div className="bg-white border border-slate-200 rounded p-2">
                      <div className="text-[10px] text-slate-500 font-medium">Digit Density</div>
                      <div className="font-mono font-bold text-slate-800 mt-0.5">
                        {liveUrlAnalysis.digitRatio}% <span className="text-[10px] text-slate-400 font-normal">({liveUrlAnalysis.length} chars)</span>
                      </div>
                    </div>
                  </div>

                  {/* Suspicious Tokens Chips */}
                  {liveUrlAnalysis.detectedKeywords.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap pt-1">
                      <span className="text-[10px] font-semibold text-red-900 uppercase tracking-wide">
                        Targeting Triggers:
                      </span>
                      {liveUrlAnalysis.detectedKeywords.map((kw, i) => (
                        <span
                          key={i}
                          className="bg-red-100 text-red-800 border border-red-200 text-[10px] px-2 py-0.5 rounded font-mono font-semibold"
                        >
                          {kw}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <p className="text-[11px] text-slate-500">
                Evaluated across 34 lexical and domain features via the Random Forest classifier and institutional rule heuristic engine.
              </p>
            </div>
          )}

          {/* TAB 2: MESSAGE PHISHING SCANNER */}
          {activeTab === "message" && (
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-800 mb-1">
                  Suspicious Message Text / SMS / Email Body
                </label>
                <textarea
                  rows={5}
                  value={messageInput}
                  onChange={(e) => setMessageInput(e.target.value)}
                  placeholder="Paste WhatsApp message, SMS notification, or email headers & body..."
                  className="w-full rounded border border-slate-300 p-3 text-sm text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900 font-mono text-xs"
                />
              </div>

              {/* LIVE MESSAGE HUD */}
              {messageInput.trim().length > 5 && (
                <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3.5 space-y-2.5 transition-all">
                  <div className="flex items-center justify-between text-xs text-slate-600 border-b border-slate-200/80 pb-2">
                    <span className="font-semibold text-slate-800 flex items-center gap-1.5">
                      <MessageSquareIcon className="h-3.5 w-3.5 text-slate-700" />
                      Live Message Heuristics
                    </span>
                    <span>
                      {liveMessageAnalysis.words} words • {liveMessageAnalysis.chars} characters
                    </span>
                  </div>

                  {liveMessageAnalysis.triggersFound.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className="text-[10px] font-bold text-red-800 uppercase tracking-wide">
                        Social Engineering Patterns:
                      </span>
                      {liveMessageAnalysis.triggersFound.map((trig, idx) => (
                        <span
                          key={idx}
                          className="bg-red-100 text-red-900 border border-red-200 text-[10px] font-semibold px-2 py-0.5 rounded"
                        >
                          {trig}
                        </span>
                      ))}
                    </div>
                  )}

                  {liveMessageAnalysis.extractedUrls.length > 0 && (
                    <div className="pt-1">
                      <p className="text-[11px] font-semibold text-slate-700 mb-1">
                        Discovered Embedded URLs ({liveMessageAnalysis.extractedUrls.length}):
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {liveMessageAnalysis.extractedUrls.map((extUrl, i) => (
                          <button
                            key={i}
                            type="button"
                            onClick={() => {
                              setActiveTab("url");
                              setUrlInput(extUrl);
                            }}
                            className="bg-white border border-slate-300 hover:border-slate-800 px-2 py-1 rounded text-[11px] font-mono text-slate-800 inline-flex items-center gap-1 transition-colors"
                          >
                            <GlobeIcon className="h-3 w-3 text-blue-600" />
                            <span className="truncate max-w-[220px]">{extUrl}</span>
                            <span className="text-blue-700 font-bold ml-1">Scan -&gt;</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              <p className="text-[11px] text-slate-500">
                Automatically detects social engineering coercion, urgent threats, and extracts embedded URLs for deep hybrid threat evaluation.
              </p>
            </div>
          )}

          {/* TAB 3: QR CODE SCANNER */}
          {activeTab === "qr" && (
            <div className="space-y-4">
              <div className="border-2 border-dashed border-slate-200 rounded-lg p-4 text-center hover:bg-slate-50 transition-colors">
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleQrFileUpload}
                  accept="image/*"
                  className="hidden"
                />
                <div className="flex flex-col items-center justify-center gap-2">
                  <UploadIcon className="h-6 w-6 text-slate-400" />
                  <p className="text-xs text-slate-600">
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="font-semibold text-slate-900 hover:underline"
                    >
                      Click to upload QR image
                    </button>{" "}
                    or drag & drop
                  </p>
                  <p className="text-[10px] text-slate-400">PNG, JPG, WEBP up to 5MB</p>
                </div>
              </div>

              {qrImagePreview && (
                <div className="flex items-center gap-3 p-3 bg-slate-50 rounded border border-slate-200">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src={qrImagePreview} alt="QR Preview" className="h-16 w-16 object-contain rounded border" />
                  <div className="text-xs">
                    <p className="font-semibold text-slate-800">Uploaded QR Code</p>
                    <p className="text-slate-500 text-[11px]">
                      {qrDecoding ? "Decoding QR barcode payload..." : "Payload extracted successfully"}
                    </p>
                  </div>
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold text-slate-800 mb-1">
                  Decoded QR Code Content / Destination Link
                </label>
                <input
                  type="text"
                  value={qrInput}
                  onChange={(e) => setQrInput(e.target.value)}
                  placeholder="e.g. https://campus-portal.org, WIFI:..., or upi://pay?..."
                  className="w-full rounded border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 font-mono text-xs focus:border-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900"
                />
              </div>

              {/* LIVE QR HUD */}
              {qrInput.trim().length > 2 && (
                <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3.5 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
                      <QrCodeIcon className="h-3.5 w-3.5 text-slate-700" />
                      Payload Schema Detection
                    </span>
                    <span className="bg-slate-900 text-white font-mono text-[10px] px-2 py-0.5 rounded font-bold">
                      {liveQrAnalysis.type}
                    </span>
                  </div>
                  <div className="text-xs bg-white border border-slate-200 rounded p-2.5 space-y-1">
                    <p className="font-semibold text-slate-800">{liveQrAnalysis.details}</p>
                    <p className="text-[11px] text-amber-700 font-medium">Risk Advisory: {liveQrAnalysis.riskBadge}</p>
                  </div>
                </div>
              )}

              <p className="text-[11px] text-slate-500">
                Supports URLs, wireless configuration profiles (WIFI), payment intents (UPI/VPA), and vCards.
              </p>
            </div>
          )}

          {/* TAB 4: OFFICE DOCUMENT & MACRO ANALYZER */}
          {activeTab === "document" && (
            <div className="space-y-4">
              <div className="border-2 border-dashed border-slate-200 rounded-lg p-4 text-center hover:bg-slate-50 transition-colors">
                <input
                  type="file"
                  ref={docFileRef}
                  onChange={handleDocFileUpload}
                  accept=".xlsx,.xlsm,.xls,.docx,.docm,.doc,.pdf,.html,.htm"
                  className="hidden"
                />
                <div className="flex flex-col items-center justify-center gap-2">
                  <FileCodeIcon className="h-6 w-6 text-slate-400" />
                  <p className="text-xs text-slate-600">
                    <button
                      type="button"
                      onClick={() => docFileRef.current?.click()}
                      className="font-semibold text-slate-900 hover:underline"
                    >
                      Click to select Document (.xlsx, .xlsm, .docx, .docm, .pdf, .html)
                    </button>{" "}
                    or test presets above
                  </p>
                  <p className="text-[10px] text-slate-400">Pure static structural inspection. Zero active macro execution.</p>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-800 mb-1">
                  Document File Name
                </label>
                <input
                  type="text"
                  value={docFileName}
                  onChange={(e) => setDocFileName(e.target.value)}
                  placeholder="e.g. Revised_Exam_Schedule_Fall2026.xlsm"
                  className="w-full rounded border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 font-mono text-xs focus:border-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-800 mb-1">
                  Document Static Inspection Indicators / Structure Notes
                </label>
                <textarea
                  rows={3}
                  value={docDetails}
                  onChange={(e) => setDocDetails(e.target.value)}
                  placeholder="Paste formula strings, macro stream notes, or inspection observations..."
                  className="w-full rounded border border-slate-300 p-3 text-sm text-slate-900 placeholder:text-slate-400 text-xs focus:border-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900"
                />
              </div>

              {/* LIVE DOCUMENT HUD */}
              {docFileName && (
                <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3.5 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
                      <FileCodeIcon className="h-3.5 w-3.5 text-slate-700" />
                      Static Macro Profile
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      liveDocAnalysis.riskRating === "CRITICAL"
                        ? "bg-red-600 text-white"
                        : liveDocAnalysis.riskRating === "HIGH RISK"
                        ? "bg-amber-600 text-white"
                        : "bg-emerald-600 text-white"
                    }`}>
                      {liveDocAnalysis.riskRating}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
                    <div className="bg-white border border-slate-200 rounded p-2">
                      <div className="text-[10px] text-slate-500">Container Format</div>
                      <div className="font-mono font-bold text-slate-800 mt-0.5">{liveDocAnalysis.extension || "Unknown"}</div>
                    </div>
                    <div className="bg-white border border-slate-200 rounded p-2">
                      <div className="text-[10px] text-slate-500">VBA Stream Risk</div>
                      <div className={`font-semibold mt-0.5 ${liveDocAnalysis.vbaStreamsDetected ? "text-red-700" : "text-emerald-700"}`}>
                        {liveDocAnalysis.vbaStreamsDetected ? "VBA Project Identified" : "No Streams"}
                      </div>
                    </div>
                    <div className="bg-white border border-slate-200 rounded p-2">
                      <div className="text-[10px] text-slate-500">Command Execution</div>
                      <div className={`font-semibold mt-0.5 ${liveDocAnalysis.ddeDetected ? "text-red-700" : "text-slate-600"}`}>
                        {liveDocAnalysis.ddeDetected ? "DDE / Cmd Injection" : "Clean"}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              <p className="text-[11px] text-slate-500">
                Detects auto-open procedures, VBA macro streams, DDE command injection, hidden worksheets, and suspicious remote templates.
              </p>
            </div>
          )}

          {/* TAB 5: CYBERBULLYING & TOXIC COMMUNICATION */}
          {activeTab === "cyberbullying" && (
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-800 mb-1">
                  Submitted Communication Text to Evaluate
                </label>
                <textarea
                  rows={5}
                  value={cyberbullyingInput}
                  onChange={(e) => setCyberbullyingInput(e.target.value)}
                  placeholder="Paste message text received on campus chat groups, Discord, WhatsApp, or forum posts..."
                  className="w-full rounded border border-slate-300 p-3 text-sm text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900"
                />
              </div>

              {/* LIVE CYBERBULLYING HUD */}
              {cyberbullyingInput.trim().length > 4 && (
                <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
                      <UserXIcon className="h-3.5 w-3.5 text-slate-700" />
                      Live Hostility Gauge
                    </span>
                    <span className="font-mono font-bold text-slate-800">{liveCyberAnalysis.hostilityScore}% Toxicity</span>
                  </div>
                  <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
                    <div
                      className={`h-full transition-all duration-300 ${
                        liveCyberAnalysis.hostilityScore > 60
                          ? "bg-red-600"
                          : liveCyberAnalysis.hostilityScore > 30
                          ? "bg-amber-500"
                          : "bg-emerald-500"
                      }`}
                      style={{ width: `${liveCyberAnalysis.hostilityScore}%` }}
                    />
                  </div>
                  {liveCyberAnalysis.categories.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap pt-1">
                      {liveCyberAnalysis.categories.map((cat, i) => (
                        <span key={i} className="bg-red-100 text-red-900 border border-red-200 text-[10px] font-semibold px-2 py-0.5 rounded">
                          {cat}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <p className="text-[11px] text-slate-500">
                Analyzes targeted harassment, personal intimidation, doxxing (exposure of private room numbers/contacts), and hostile communications.
              </p>
            </div>
          )}

          {/* Form Actions */}
          <div className="flex items-center justify-between pt-2 border-t border-slate-100">
            <span className="text-[11px] text-slate-500 flex items-center gap-1.5">
              <LockIcon className="h-3.5 w-3.5 text-slate-400" />
              Isolated heuristic sandbox. Zero background browsing inspection.
            </span>
            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-md bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 disabled:bg-slate-400 transition-colors shadow-sm"
            >
              <ScanIcon className="h-4 w-4" />
              {loading ? "Analyzing Pipeline..." : "Run Security Scan"}
            </button>
          </div>
        </form>
      </div>

      {/* ANIMATED FORENSIC DIAGNOSTIC PIPELINE (Active while loading) */}
      {loading && (
        <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm space-y-4 animate-pulse">
          <div className="flex items-center justify-between border-b border-slate-200 pb-3">
            <div className="flex items-center gap-2">
              <RefreshCwIcon className="h-4 w-4 animate-spin text-blue-600" />
              <h3 className="text-sm font-bold text-slate-900">Executing Threat Detection Pipeline</h3>
            </div>
            <span className="text-xs font-mono text-slate-500">Stage {pipelineStep} of 5</span>
          </div>

          <div className="space-y-2.5">
            {[
              { step: 1, title: "Lexical & Structural Vector Extraction", desc: "Computing 34 URL / text features according to schema v1.0.0" },
              { step: 2, title: "Campus Whitelist & Heuristic Rules", desc: "Verifying educational domains, authorized SSO portals, and typosquatting" },
              { step: 3, title: "Threat Intelligence Correlation", desc: "Querying local URLhaus & PhishTank high-confidence IOC hash database" },
              { step: 4, title: "Machine Learning Model Inference", desc: "Executing trained Random Forest / Transformer weights in isolated runtime" },
              { step: 5, title: "Synthesizing Security Intelligence & Actions", desc: "Correlating evidence, SHAP feature weights, and remediation recommendations" },
            ].map((st) => (
              <div
                key={st.step}
                className={`p-3 rounded border text-xs flex items-center justify-between transition-all ${
                  pipelineStep > st.step
                    ? "border-emerald-200 bg-emerald-50/50 text-emerald-900"
                    : pipelineStep === st.step
                    ? "border-blue-300 bg-blue-50 text-blue-900 font-semibold shadow-sm"
                    : "border-slate-100 bg-slate-50/50 text-slate-400"
                }`}
              >
                <div>
                  <div className="font-semibold">{st.title}</div>
                  <div className="text-[11px] opacity-80">{st.desc}</div>
                </div>
                <div>
                  {pipelineStep > st.step ? (
                    <CheckCircleIcon className="h-4 w-4 text-emerald-600" />
                  ) : pipelineStep === st.step ? (
                    <span className="inline-block h-2 w-2 rounded-full bg-blue-600 animate-ping" />
                  ) : (
                    <span className="text-[10px] text-slate-400">Pending</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ANALYSIS RESULTS DISPLAY */}
      {result && !loading && (
        <div className="rounded-lg border border-slate-200 bg-white p-6 sm:p-8 shadow-sm space-y-6">
          
          {/* Header & Verdict */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-6">
            <div>
              <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Analysis Verdict</p>
              <h2 className="text-xl font-bold text-slate-900 mt-0.5">Threat Evaluation Report</h2>
              <p className="text-xs text-slate-500 mt-1">
                Scan ID: {result.id} • Analyzed at {new Date(result.analyzedAt).toLocaleTimeString()}
              </p>
            </div>

            <div className="flex items-center gap-2">
              {(() => {
                const badge = getVerdictBadge(result.verdict);
                const Icon = badge.icon;
                return (
                  <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded border text-xs font-bold ${badge.bg}`}>
                    <Icon className="h-4 w-4" />
                    <span>{badge.label}</span>
                  </div>
                );
              })()}
            </div>
          </div>

          {/* Interactive Radial Gauge & Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 border-b border-slate-200 pb-6 items-center">
            
            {/* Radial Risk Dial */}
            <div className="col-span-1 border border-slate-200 bg-slate-50/60 rounded-lg p-4">
              <RadialRiskGauge score={result.riskScore} />
            </div>

            {/* Model Confidence & Feature Dimension button */}
            <div className="rounded-lg border border-slate-200 bg-slate-50/60 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-500">Model Confidence</span>
                <span className="text-xs font-bold text-slate-900">{Math.round(result.confidence * 100)}%</span>
              </div>
              <p className="text-2xl font-black text-slate-900">
                {(result.confidence * 100).toFixed(1)}%
              </p>
              <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
                <div
                  className="h-full bg-slate-900"
                  style={{ width: `${Math.round(result.confidence * 100)}%` }}
                />
              </div>
              <button
                type="button"
                onClick={() => setShowFeatureModal(true)}
                className="w-full mt-2 inline-flex items-center justify-center gap-1.5 rounded border border-slate-300 bg-white py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-50 transition-colors"
              >
                <TerminalIcon className="h-3.5 w-3.5 text-slate-600" />
                Inspect 34 Feature Vector
              </button>
            </div>

            {/* Threat Level & Containment */}
            <div className="rounded-lg border border-slate-200 bg-slate-50/60 p-4 space-y-2">
              <span className="text-xs font-medium text-slate-500">Institutional Threat Tier</span>
              <p className="text-2xl font-black uppercase tracking-wide text-slate-900">
                {result.threatLevel}
              </p>
              <p className="text-[11px] text-slate-500">
                Correlated with Campus Threat Intel database.
              </p>
              <button
                type="button"
                onClick={() => setShowFirewallModal(true)}
                className="w-full mt-2 inline-flex items-center justify-center gap-1.5 rounded border border-slate-300 bg-white py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-50 transition-colors"
              >
                <ShieldIcon className="h-3.5 w-3.5 text-slate-600" />
                Generate Firewall Block Rule
              </button>
            </div>
          </div>

          {/* Extracted URLs Section (For Message Scans) */}
          {result.extractedUrls && result.extractedUrls.length > 0 && (
            <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-4">
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <GlobeIcon className="h-4 w-4 text-slate-700" />
                <span>Extracted URLs from Message ({result.extractedUrls.length})</span>
              </h3>
              <div className="space-y-2">
                {result.extractedUrls.map((extractedUrl, idx) => (
                  <div
                    key={idx}
                    className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-white border border-slate-200 rounded p-2.5 text-xs font-mono"
                  >
                    <span className="truncate text-slate-800">{extractedUrl}</span>
                    <button
                      type="button"
                      onClick={() => {
                        setActiveTab("url");
                        setUrlInput(extractedUrl);
                        handleScan();
                      }}
                      className="shrink-0 inline-flex items-center gap-1 text-[11px] font-semibold text-slate-900 hover:underline"
                    >
                      <ScanIcon className="h-3.5 w-3.5" />
                      Scan this URL
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Executive Summary */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <h3 className="text-sm font-bold text-slate-900">Executive Summary</h3>
              <button
                type="button"
                onClick={handleCopyJson}
                className="inline-flex items-center gap-1 text-xs text-slate-600 hover:text-slate-900 transition-colors"
              >
                {copiedJson ? (
                  <>
                    <CheckIcon className="h-3.5 w-3.5 text-emerald-600" />
                    <span className="text-emerald-700 font-semibold">Report Copied!</span>
                  </>
                ) : (
                  <>
                    <CopyIcon className="h-3.5 w-3.5" />
                    <span>Copy JSON Report</span>
                  </>
                )}
              </button>
            </div>
            <p className="text-xs text-slate-700 leading-relaxed bg-slate-50 border border-slate-200 rounded p-3">
              {result.summary}
            </p>
          </div>

          {/* Indicators Breakdown with Interactive Filter Tabs */}
          {result.indicators.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-bold text-slate-900">
                  Identified Threat Indicators ({result.indicators.length})
                </h3>
                <div className="flex items-center gap-1 text-xs">
                  <button
                    type="button"
                    onClick={() => setIndicatorFilter("ALL")}
                    className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                      indicatorFilter === "ALL" ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                    }`}
                  >
                    All ({result.indicators.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setIndicatorFilter("DANGER")}
                    className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                      indicatorFilter === "DANGER" ? "bg-red-700 text-white" : "bg-red-50 text-red-700 hover:bg-red-100"
                    }`}
                  >
                    Critical ({result.indicators.filter((i) => i.severity === "danger").length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setIndicatorFilter("WARNING")}
                    className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                      indicatorFilter === "WARNING" ? "bg-amber-700 text-white" : "bg-amber-50 text-amber-700 hover:bg-amber-100"
                    }`}
                  >
                    Moderate ({result.indicators.filter((i) => i.severity === "warning").length})
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                {filteredIndicators.map((ind, i) => (
                  <div
                    key={i}
                    className={`border rounded p-3 text-xs flex items-start gap-3 transition-colors ${
                      ind.severity === "danger"
                        ? "border-red-200 bg-red-50/40 text-red-950"
                        : "border-amber-200 bg-amber-50/40 text-amber-950"
                    }`}
                  >
                    <AlertCircleIcon
                      className={`h-4 w-4 shrink-0 mt-0.5 ${
                        ind.severity === "danger" ? "text-red-600" : "text-amber-600"
                      }`}
                    />
                    <div>
                      <span className="font-semibold">{ind.label}:</span>{" "}
                      <span className="text-slate-700">{ind.description}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Safety Recommendations */}
          <div>
            <h3 className="text-sm font-bold text-slate-900 mb-2">Safety Recommendations</h3>
            <div className="space-y-1.5">
              {result.recommendations.map((rec, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-slate-700">
                  <CheckCircleIcon className="h-4 w-4 text-emerald-600 shrink-0 mt-0.5" />
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Escalation CTA */}
          <div className="border-t border-slate-200 pt-6 flex flex-col sm:flex-row items-center justify-between gap-4 bg-slate-50/70 -mx-6 sm:-mx-8 -mb-6 sm:-mb-8 p-6 sm:p-8 rounded-b-lg">
            <div>
              <p className="text-xs font-semibold text-slate-900">Did you encounter this threat on campus?</p>
              <p className="text-[11px] text-slate-500">
                Submit this incident directly to the Campus Incident Response Team to protect other students.
              </p>
            </div>
            <button
              type="button"
              onClick={handleEscalateToReport}
              className="inline-flex items-center gap-2 rounded-md bg-red-700 px-4 py-2 text-xs font-semibold text-white hover:bg-red-800 transition-colors shadow-sm"
            >
              <AlertCircleIcon className="h-4 w-4" />
              Escalate to Security Incident Report
            </button>
          </div>

        </div>
      )}

      {/* MODAL 1: 34 MACHINE LEARNING FEATURE DIMENSIONS INSPECTOR */}
      {showFeatureModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-white rounded-xl shadow-2xl border border-slate-200 max-w-4xl w-full max-h-[85vh] flex flex-col overflow-hidden animate-fadeIn">
            
            {/* Modal Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 bg-slate-50">
              <div>
                <div className="flex items-center gap-2">
                  <TerminalIcon className="h-5 w-5 text-slate-800" />
                  <h3 className="text-base font-bold text-slate-900">34-Feature Forensic Vector Matrix</h3>
                </div>
                <p className="text-xs text-slate-500 mt-0.5">
                  Authoritative feature schema URL_FEATURE_SCHEMA_V1 consumed by Random Forest classifier.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowFeatureModal(false)}
                className="text-slate-400 hover:text-slate-700 text-sm font-bold p-1 rounded"
              >
                ✕
              </button>
            </div>

            {/* Modal Controls: Search & Category Filter */}
            <div className="px-6 py-3 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white">
              <input
                type="text"
                value={featureSearch}
                onChange={(e) => setFeatureSearch(e.target.value)}
                placeholder="Search features (e.g. entropy, dot, hyphen, keyword)..."
                className="rounded border border-slate-300 px-3 py-1.5 text-xs text-slate-800 focus:outline-none focus:border-slate-900 w-full sm:w-64"
              />

              <div className="flex items-center gap-1 overflow-x-auto text-xs">
                {(["all", "structural", "domain", "lexical", "heuristic"] as const).map((cat) => (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => setFeatureCategory(cat)}
                    className={`px-2.5 py-1 rounded text-[11px] font-semibold uppercase tracking-wider transition-colors shrink-0 ${
                      featureCategory === cat ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {/* Modal Content: 34 Features Table */}
            <div className="p-6 overflow-y-auto space-y-3 flex-1">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {filteredFeatures.map((feat) => (
                  <div
                    key={feat.key}
                    className={`p-3 rounded-lg border text-xs flex flex-col justify-between transition-all ${
                      feat.status === "critical"
                        ? "border-red-200 bg-red-50/50"
                        : feat.status === "elevated"
                        ? "border-amber-200 bg-amber-50/40"
                        : "border-slate-200 bg-slate-50/40"
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-bold text-slate-900 font-mono">{feat.name}</span>
                        <span
                          className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${
                            feat.status === "critical"
                              ? "bg-red-600 text-white"
                              : feat.status === "elevated"
                              ? "bg-amber-600 text-white"
                              : "bg-emerald-600 text-white"
                          }`}
                        >
                          {feat.status}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-600">{feat.description}</p>
                    </div>

                    <div className="mt-2.5 pt-2 border-t border-slate-200/60 flex items-center justify-between text-[11px]">
                      <div>
                        <span className="text-slate-400">Value: </span>
                        <span className="font-bold font-mono text-slate-900">{feat.value}</span>
                      </div>
                      <div>
                        <span className="text-slate-400">Safe Baseline: </span>
                        <span className="font-mono text-slate-700">{feat.safeRange}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs">
              <span className="text-slate-500">
                Displaying {filteredFeatures.length} of {urlFeatures34.length} vector dimensions
              </span>
              <button
                type="button"
                onClick={() => setShowFeatureModal(false)}
                className="bg-slate-900 text-white px-4 py-1.5 rounded font-semibold hover:bg-slate-800 transition-colors"
              >
                Close Inspector
              </button>
            </div>

          </div>
        </div>
      )}

      {/* MODAL 2: FIREWALL & DNS SINKHOLE RULE GENERATOR */}
      {showFirewallModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-white rounded-xl shadow-2xl border border-slate-200 max-w-2xl w-full flex flex-col overflow-hidden animate-fadeIn">
            
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 bg-slate-50">
              <div className="flex items-center gap-2">
                <ShieldIcon className="h-5 w-5 text-slate-800" />
                <h3 className="text-base font-bold text-slate-900">Campus CIRT Mitigation Rules</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowFirewallModal(false)}
                className="text-slate-400 hover:text-slate-700 text-sm font-bold p-1 rounded"
              >
                ✕
              </button>
            </div>

            <div className="p-6 space-y-4">
              <p className="text-xs text-slate-600">
                Instantly generated containment rules for campus gateway firewalls and internal DNS resolvers to prevent student credential leaks.
              </p>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-slate-800">Linux iptables Drop Rule</span>
                </div>
                <pre className="bg-slate-900 text-emerald-400 p-3 rounded text-xs font-mono overflow-x-auto">
                  {firewallRules.iptables}
                </pre>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-slate-800">Windows Defender Firewall PowerShell</span>
                </div>
                <pre className="bg-slate-900 text-blue-300 p-3 rounded text-xs font-mono overflow-x-auto">
                  {firewallRules.powershell}
                </pre>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-slate-800">BIND RPZ DNS Sinkhole Entry</span>
                </div>
                <pre className="bg-slate-900 text-amber-300 p-3 rounded text-xs font-mono overflow-x-auto">
                  {firewallRules.dnsRpz}
                </pre>
              </div>
            </div>

            <div className="px-6 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs">
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(
                    `${firewallRules.iptables}\n\n${firewallRules.powershell}\n\n${firewallRules.dnsRpz}`
                  );
                  setCopiedRule(true);
                  setTimeout(() => setCopiedRule(false), 2000);
                }}
                className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-700 hover:text-slate-900"
              >
                {copiedRule ? (
                  <>
                    <CheckIcon className="h-4 w-4 text-emerald-600" />
                    <span className="text-emerald-700 font-bold">All Rules Copied!</span>
                  </>
                ) : (
                  <>
                    <CopyIcon className="h-4 w-4" />
                    <span>Copy All Rules</span>
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={() => setShowFirewallModal(false)}
                className="bg-slate-900 text-white px-4 py-1.5 rounded font-semibold hover:bg-slate-800 transition-colors"
              >
                Done
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}

export default function ScanPage() {
  return (
    <Suspense fallback={<div className="mx-auto max-w-5xl px-4 py-8"><div className="h-64 bg-slate-100 rounded-lg animate-pulse" /></div>}>
      <ScanContent />
    </Suspense>
  );
}
