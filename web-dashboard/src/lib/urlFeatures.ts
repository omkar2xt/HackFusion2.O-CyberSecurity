/**
 * SignalSafe Campus - Client-Side Real-Time Feature Engineering & Security Analyzers
 * Implements authoritative 34-feature vector computation matching URL_FEATURE_SCHEMA_V1
 * and dynamic live text/QR/document/cyberbullying heuristics.
 */

export interface FeatureRecord {
  key: string;
  name: string;
  value: number;
  category: "structural" | "domain" | "lexical" | "heuristic";
  safeRange: string;
  status: "normal" | "elevated" | "critical";
  description: string;
}

const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "verification", "account", "update", "banking", "security",
  "confirm", "password", "credential", "suspend", "secure", "signin", "auth",
  "portal", "admin", "recover", "refund", "support", "helpdesk", "billing",
  "invoice", "wallet", "identity", "validation", "authenticate", "session",
  "token", "mess", "hostel", "concession", "scholarship", "exam"
];

const SUSPICIOUS_EXTENSIONS = [
  ".exe", ".scr", ".bat", ".vbs", ".cmd", ".ps1", ".hta", ".apk",
  ".xlsm", ".docm", ".iso", ".zip", ".rar", ".7z", ".sh", ".dmg"
];

function calcShannonEntropy(str: string): number {
  if (!str) return 0;
  const freq: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(4));
}

function parseUrlParts(rawUrl: string): {
  normalized: string;
  protocol: string;
  hostname: string;
  path: string;
  query: string;
  port: string;
} {
  let url = rawUrl.trim();
  if (!url) {
    return { normalized: "", protocol: "", hostname: "", path: "", query: "", port: "" };
  }
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "http://" + url;
  }
  try {
    const parsed = new URL(url);
    return {
      normalized: url,
      protocol: parsed.protocol.replace(":", ""),
      hostname: parsed.hostname.toLowerCase(),
      path: parsed.pathname,
      query: parsed.search.replace("?", ""),
      port: parsed.port,
    };
  } catch {
    const withoutProto = url.replace(/^[a-zA-Z]+:\/\//, "");
    const slashIdx = withoutProto.indexOf("/");
    const hostname = slashIdx === -1 ? withoutProto : withoutProto.slice(0, slashIdx);
    const path = slashIdx === -1 ? "" : withoutProto.slice(slashIdx);
    return {
      normalized: url,
      protocol: "http",
      hostname: hostname.toLowerCase(),
      path,
      query: "",
      port: "",
    };
  }
}

function isIpAddress(hostname: string): boolean {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(hostname)) return false;
  return hostname.split(".").every(p => {
    const n = parseInt(p, 10);
    return n >= 0 && n <= 255;
  });
}

/**
 * Extracts authoritative 34-feature vector matching URL_FEATURE_NAMES.
 */
export function extractUrlFeatures(rawUrl: string): FeatureRecord[] {
  const parts = parseUrlParts(rawUrl);
  const u = parts.normalized;
  const h = parts.hostname;
  const p = parts.path;
  const q = parts.query;

  const url_length = u.length;
  const hostname_length = h.length;
  const path_length = p.length;
  const query_length = q.length;

  const dot_count = (u.match(/\./g) || []).length;
  const dot_count_domain = (h.match(/\./g) || []).length;
  const hyphen_count = (u.match(/-/g) || []).length;
  const hyphen_count_domain = (h.match(/-/g) || []).length;
  const has_hyphen_in_domain = hyphen_count_domain > 0 ? 1 : 0;
  const underscore_count = (u.match(/_/g) || []).length;
  const slash_count = (u.match(/\//g) || []).length;
  const double_slash_in_path = p.includes("//") ? 1 : 0;
  const at_symbol_count = (u.match(/@/g) || []).length;
  const question_mark_count = (u.match(/\?/g) || []).length;
  const equal_count = (u.match(/=/g) || []).length;
  const ampersand_count = (u.match(/&/g) || []).length;
  const percent_count = (u.match(/%/g) || []).length;
  const is_https = parts.protocol === "https" ? 1 : 0;
  const is_ip = isIpAddress(h) ? 1 : 0;
  const has_non_standard_port = (parts.port && parts.port !== "80" && parts.port !== "443") ? 1 : 0;

  const domainParts = h.split(".").filter(Boolean);
  const subdomain_count = Math.max(0, domainParts.length - 2);
  const subdomain_length = domainParts.length > 2 ? domainParts.slice(0, domainParts.length - 2).join(".").length : 0;
  const tld_length = domainParts.length > 0 ? domainParts[domainParts.length - 1].length : 0;
  const is_punycode = h.includes("xn--") ? 1 : 0;

  const digit_count = (u.match(/\d/g) || []).length;
  const digit_count_domain = (h.match(/\d/g) || []).length;
  const percentage_numeric_chars = url_length > 0 ? parseFloat((digit_count / url_length).toFixed(4)) : 0;
  const percentage_numeric_chars_domain = hostname_length > 0 ? parseFloat((digit_count_domain / hostname_length).toFixed(4)) : 0;

  const url_entropy = calcShannonEntropy(u);
  const domain_entropy = calcShannonEntropy(h);

  const lowerPath = p.toLowerCase();
  const suspicious_file_extension = SUSPICIOUS_EXTENSIONS.some(ext => lowerPath.endsWith(ext)) ? 1 : 0;

  const uLower = u.toLowerCase();
  const hLower = h.toLowerCase();
  let kwCount = 0;
  let kwInDomain = 0;
  let kwInPath = 0;

  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (uLower.includes(kw)) kwCount++;
    if (hLower.includes(kw)) kwInDomain++;
    if (lowerPath.includes(kw)) kwInPath++;
  }

  const raw34: { key: string; name: string; value: number; category: FeatureRecord["category"]; safeRange: string; status: FeatureRecord["status"]; description: string }[] = [
    { key: "url_length", name: "URL Length", value: url_length, category: "structural", safeRange: "< 75 chars", status: url_length > 120 ? "critical" : url_length > 75 ? "elevated" : "normal", description: "Excessive length often obfuscates destination." },
    { key: "hostname_length", name: "Hostname Length", value: hostname_length, category: "domain", safeRange: "< 30 chars", status: hostname_length > 40 ? "critical" : hostname_length > 30 ? "elevated" : "normal", description: "Length of domain name component." },
    { key: "path_length", name: "Path Length", value: path_length, category: "structural", safeRange: "< 50 chars", status: path_length > 80 ? "critical" : path_length > 50 ? "elevated" : "normal", description: "Length of path segment." },
    { key: "query_length", name: "Query Length", value: query_length, category: "structural", safeRange: "< 40 chars", status: query_length > 90 ? "critical" : query_length > 40 ? "elevated" : "normal", description: "Length of query parameters." },
    { key: "dot_count", name: "Dot Count", value: dot_count, category: "lexical", safeRange: "<= 3", status: dot_count > 5 ? "critical" : dot_count > 3 ? "elevated" : "normal", description: "High dot counts often indicate subdomain chaining." },
    { key: "dot_count_domain", name: "Domain Dot Count", value: dot_count_domain, category: "domain", safeRange: "<= 2", status: dot_count_domain > 3 ? "critical" : dot_count_domain > 2 ? "elevated" : "normal", description: "Number of dot separators in hostname." },
    { key: "hyphen_count", name: "Hyphen Count", value: hyphen_count, category: "lexical", safeRange: "<= 2", status: hyphen_count > 4 ? "critical" : hyphen_count > 2 ? "elevated" : "normal", description: "Hyphens frequently appear in typosquatted domains." },
    { key: "hyphen_count_domain", name: "Domain Hyphen Count", value: hyphen_count_domain, category: "domain", safeRange: "0", status: hyphen_count_domain > 2 ? "critical" : hyphen_count_domain > 0 ? "elevated" : "normal", description: "Hyphens in hostname brand spoofing." },
    { key: "has_hyphen_in_domain", name: "Has Hyphen in Domain", value: has_hyphen_in_domain, category: "domain", safeRange: "0", status: has_hyphen_in_domain === 1 ? "elevated" : "normal", description: "Presence of hyphens in hostname." },
    { key: "underscore_count", name: "Underscore Count", value: underscore_count, category: "lexical", safeRange: "0", status: underscore_count > 2 ? "critical" : underscore_count > 0 ? "elevated" : "normal", description: "Underscores in URL tokens." },
    { key: "slash_count", name: "Slash Count", value: slash_count, category: "structural", safeRange: "<= 5", status: slash_count > 7 ? "critical" : slash_count > 5 ? "elevated" : "normal", description: "Number of directory path slashes." },
    { key: "double_slash_in_path", name: "Double Slash in Path", value: double_slash_in_path, category: "structural", safeRange: "0", status: double_slash_in_path === 1 ? "critical" : "normal", description: "Open redirect technique indicator." },
    { key: "at_symbol_count", name: "At Symbol (@) Count", value: at_symbol_count, category: "lexical", safeRange: "0", status: at_symbol_count > 0 ? "critical" : "normal", description: "Userinfo auth spoofing in URL." },
    { key: "question_mark_count", name: "Question Mark Count", value: question_mark_count, category: "lexical", safeRange: "<= 1", status: question_mark_count > 1 ? "critical" : "normal", description: "Query parameter delimiters." },
    { key: "equal_count", name: "Equal Sign Count", value: equal_count, category: "lexical", safeRange: "<= 3", status: equal_count > 4 ? "elevated" : "normal", description: "Parameter assignments in query string." },
    { key: "ampersand_count", name: "Ampersand Count", value: ampersand_count, category: "lexical", safeRange: "<= 3", status: ampersand_count > 4 ? "elevated" : "normal", description: "Multiple parameter concatenations." },
    { key: "percent_count", name: "Percent (%) Count", value: percent_count, category: "lexical", safeRange: "<= 2", status: percent_count > 4 ? "critical" : percent_count > 1 ? "elevated" : "normal", description: "URL percent-encoding / obfuscation." },
    { key: "is_https", name: "HTTPS Protocol", value: is_https, category: "domain", safeRange: "1", status: is_https === 0 ? "critical" : "normal", description: "Whether secure TLS encryption is active." },
    { key: "is_ip_address", name: "Raw IP Hostname", value: is_ip, category: "domain", safeRange: "0", status: is_ip === 1 ? "critical" : "normal", description: "Host is direct IPv4 address bypass." },
    { key: "has_non_standard_port", name: "Non-Standard Port", value: has_non_standard_port, category: "domain", safeRange: "0", status: has_non_standard_port === 1 ? "critical" : "normal", description: "Port other than standard 80 or 443." },
    { key: "subdomain_count", name: "Subdomain Count", value: subdomain_count, category: "domain", safeRange: "<= 1", status: subdomain_count > 2 ? "critical" : subdomain_count > 1 ? "elevated" : "normal", description: "Excessive subdomains suggest deceptive naming." },
    { key: "subdomain_length", name: "Subdomain Length", value: subdomain_length, category: "domain", safeRange: "< 15", status: subdomain_length > 25 ? "critical" : subdomain_length > 15 ? "elevated" : "normal", description: "Cumulative length of subdomains." },
    { key: "tld_length", name: "TLD Length", value: tld_length, category: "domain", safeRange: "2 - 4", status: tld_length > 5 ? "elevated" : "normal", description: "Top-level domain extension length." },
    { key: "is_punycode", name: "Punycode (IDN)", value: is_punycode, category: "domain", safeRange: "0", status: is_punycode === 1 ? "critical" : "normal", description: "Internationalized domain homograph attack flag." },
    { key: "digit_count", name: "Digit Count in URL", value: digit_count, category: "lexical", safeRange: "< 8", status: digit_count > 15 ? "critical" : digit_count > 7 ? "elevated" : "normal", description: "Absolute count of numeric characters." },
    { key: "digit_count_domain", name: "Digit Count in Domain", value: digit_count_domain, category: "domain", safeRange: "0", status: digit_count_domain > 4 ? "critical" : digit_count_domain > 0 ? "elevated" : "normal", description: "Numeric digits inside hostname." },
    { key: "percentage_numeric_chars", name: "Numeric Ratio (URL)", value: percentage_numeric_chars, category: "lexical", safeRange: "< 0.15", status: percentage_numeric_chars > 0.25 ? "critical" : percentage_numeric_chars > 0.15 ? "elevated" : "normal", description: "Ratio of numeric characters to total length." },
    { key: "percentage_numeric_chars_domain", name: "Numeric Ratio (Domain)", value: percentage_numeric_chars_domain, category: "domain", safeRange: "0", status: percentage_numeric_chars_domain > 0.2 ? "critical" : percentage_numeric_chars_domain > 0 ? "elevated" : "normal", description: "Ratio of numbers inside the hostname." },
    { key: "url_entropy", name: "Shannon Entropy (URL)", value: url_entropy, category: "heuristic", safeRange: "3.2 - 4.3", status: url_entropy > 4.6 ? "critical" : url_entropy > 4.2 ? "elevated" : "normal", description: "Information randomness / algorithmic generation." },
    { key: "domain_entropy", name: "Shannon Entropy (Domain)", value: domain_entropy, category: "heuristic", safeRange: "2.5 - 3.8", status: domain_entropy > 4.0 ? "critical" : domain_entropy > 3.6 ? "elevated" : "normal", description: "Randomness of hostname characters." },
    { key: "suspicious_file_extension", name: "Suspicious Extension", value: suspicious_file_extension, category: "heuristic", safeRange: "0", status: suspicious_file_extension === 1 ? "critical" : "normal", description: "Executables or macro-enabled downloads." },
    { key: "suspicious_keyword_count", name: "Suspicious Keywords", value: kwCount, category: "heuristic", safeRange: "0", status: kwCount >= 3 ? "critical" : kwCount > 0 ? "elevated" : "normal", description: "Count of targeted social engineering words." },
    { key: "suspicious_keyword_in_domain", name: "Keywords in Domain", value: kwInDomain, category: "heuristic", safeRange: "0", status: kwInDomain > 1 ? "critical" : kwInDomain > 0 ? "elevated" : "normal", description: "Phishing target keywords in hostname." },
    { key: "suspicious_keyword_in_path", name: "Keywords in Path", value: kwInPath, category: "heuristic", safeRange: "0", status: kwInPath > 2 ? "critical" : kwInPath > 0 ? "elevated" : "normal", description: "Phishing keywords located in URI path." },
  ];

  return raw34;
}

/**
 * Real-time summary analysis for URL as user types.
 */
export function analyzeLiveUrl(rawUrl: string) {
  const parts = parseUrlParts(rawUrl);
  const entropy = calcShannonEntropy(parts.normalized);
  const isHttps = parts.protocol === "https";
  const isIp = isIpAddress(parts.hostname);
  
  const detectedKeywords: string[] = [];
  const lower = parts.normalized.toLowerCase();
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (lower.includes(kw) && !detectedKeywords.includes(kw)) {
      detectedKeywords.push(kw);
    }
  }

  // TLD and SLD
  const domainParts = parts.hostname.split(".").filter(Boolean);
  const tld = domainParts.length > 1 ? "." + domainParts[domainParts.length - 1] : "";
  const sld = domainParts.length > 1 ? domainParts[domainParts.length - 2] : parts.hostname;

  const length = parts.normalized.length;
  const digitCount = (parts.normalized.match(/\d/g) || []).length;
  const digitRatio = length > 0 ? Math.round((digitCount / length) * 100) : 0;

  // Immediate heuristic risk estimation
  let quickRisk = 10;
  if (!isHttps) quickRisk += 25;
  if (isIp) quickRisk += 45;
  if (detectedKeywords.length > 0) quickRisk += Math.min(30, detectedKeywords.length * 12);
  if (entropy > 4.4) quickRisk += 15;
  if (tld === ".xyz" || tld === ".top" || tld === ".tk" || tld === ".cc") quickRisk += 20;
  quickRisk = Math.min(98, Math.max(5, quickRisk));

  return {
    normalized: parts.normalized,
    protocol: parts.protocol || "http",
    hostname: parts.hostname,
    sld,
    tld,
    isHttps,
    isIp,
    entropy,
    detectedKeywords,
    length,
    digitRatio,
    quickRisk,
  };
}

/**
 * Real-time summary analysis for Message as user types.
 */
export function analyzeLiveMessage(text: string) {
  const trimmed = text.trim();
  const words = trimmed ? trimmed.split(/\s+/).length : 0;
  const chars = text.length;

  const URGENCY_TRIGGERS = [
    { label: "Urgent Action Required", pattern: /\b(urgent|immediately|immediate action|act now|hurry|asap)\b/i },
    { label: "Account Suspension", pattern: /\b(suspend|suspended|terminated|deactivated|locked out|blocked)\b/i },
    { label: "Fee / Refund Coercion", pattern: /\b(refund|concession|penalty|fine|due today|overdue|claim prize)\b/i },
    { label: "Credential Demand", pattern: /\b(verify password|confirm otp|enter pin|share credentials|login now)\b/i },
    { label: "Authority Impersonation", pattern: /\b(dean|registrar|hod|counselor|warden|director|proctor)\b/i },
  ];

  const triggersFound: string[] = [];
  for (const t of URGENCY_TRIGGERS) {
    if (t.pattern.test(text)) {
      triggersFound.push(t.label);
    }
  }

  // URL extraction regex
  const urlRegex = /(https?:\/\/[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:com|org|edu|net|xyz|top|site|in)\/[^\s]*)/gi;
  const extractedUrls = (text.match(urlRegex) || []).map(u => u.trim());

  let urgencyScore = 15;
  if (triggersFound.length > 0) urgencyScore += triggersFound.length * 20;
  if (extractedUrls.length > 0) urgencyScore += 25;
  urgencyScore = Math.min(95, urgencyScore);

  return {
    words,
    chars,
    triggersFound,
    extractedUrls,
    urgencyScore,
  };
}

/**
 * Real-time summary analysis for QR payloads.
 */
export function analyzeLiveQr(payload: string) {
  const p = payload.trim();
  let type: "URL" | "WIFI" | "UPI" | "VCARD" | "TEXT" = "TEXT";
  let details = "Plain text content";
  let riskBadge = "Neutral";

  if (p.startsWith("http://") || p.startsWith("https://") || p.includes(".xyz/") || p.includes(".org/")) {
    type = "URL";
    details = `Web link: ${p}`;
    riskBadge = p.startsWith("https://") ? "Medium (Review URL)" : "High (Insecure HTTP)";
  } else if (p.startsWith("WIFI:")) {
    type = "WIFI";
    const ssidMatch = p.match(/S:([^;]+);/);
    const passMatch = p.match(/P:([^;]+);/);
    details = `Wi-Fi Network SSID: "${ssidMatch ? ssidMatch[1] : "Unknown"}", Password: ${passMatch ? "Present" : "Open"}`;
    riskBadge = "Rogue Access Point Warning";
  } else if (p.startsWith("upi://pay")) {
    type = "UPI";
    const paMatch = p.match(/pa=([^&]+)/);
    const amMatch = p.match(/am=([^&]+)/);
    details = `Direct UPI Payee: ${paMatch ? paMatch[1] : "Unknown"}, Amount: ${amMatch ? "₹" + amMatch[1] : "Variable"}`;
    riskBadge = "Direct Financial Transaction";
  } else if (p.includes("BEGIN:VCARD")) {
    type = "VCARD";
    details = "Contact Card Profile Import";
    riskBadge = "Low Risk Profile";
  }

  return {
    type,
    details,
    riskBadge,
    length: p.length,
  };
}

/**
 * Real-time summary analysis for Office documents.
 */
export function analyzeLiveDocument(fileName: string, details: string) {
  const lower = fileName.toLowerCase().trim();
  const isMacroEnabled = lower.endsWith(".xlsm") || lower.endsWith(".docm") || lower.endsWith(".pptm");
  const isLegacy = lower.endsWith(".xls") || lower.endsWith(".doc");
  const isOpenXml = lower.endsWith(".xlsx") || lower.endsWith(".docx");

  const combined = (fileName + " " + details).toLowerCase();
  const vbaStreamsDetected = combined.includes("vbaproject") || combined.includes("autoopen") || combined.includes("workbook_open") || isMacroEnabled;
  const ddeDetected = combined.includes("dde") || combined.includes("powershell") || combined.includes("cmd.exe");

  let riskRating = "SAFE";
  if (ddeDetected || (vbaStreamsDetected && (combined.includes("powershell") || combined.includes("paste")))) {
    riskRating = "CRITICAL";
  } else if (vbaStreamsDetected || isMacroEnabled) {
    riskRating = "HIGH RISK";
  } else if (isLegacy) {
    riskRating = "SUSPICIOUS (Legacy Binary)";
  }

  return {
    extension: lower.slice(lower.lastIndexOf(".")),
    isMacroEnabled,
    isOpenXml,
    vbaStreamsDetected,
    ddeDetected,
    riskRating,
  };
}

/**
 * Real-time summary analysis for Cyberbullying.
 */
export function analyzeLiveCyberbullying(text: string) {
  const lower = text.toLowerCase();
  const categories: string[] = [];

  if (/\b(freak|worthless|loser|ugly|disgusting|pathetic|kill yourself|die)\b/i.test(lower)) {
    categories.push("Severe Hostility & Insults");
  }
  if (/\b(hostel|room|block|know where you live|watch your back|after lab|follow you)\b/i.test(lower)) {
    categories.push("Doxxing & Physical Intimidation");
  }
  if (/\b(nobody wants you|exclude|kick out|laughing at you|everyone hates)\b/i.test(lower)) {
    categories.push("Social Isolation & Exclusion");
  }

  const hostilityScore = Math.min(95, categories.length * 35 + (lower.length > 10 ? 10 : 0));

  return {
    categories,
    hostilityScore: categories.length > 0 ? hostilityScore : 5,
    severity: categories.length >= 2 ? "CRITICAL" : categories.length === 1 ? "HIGH" : "LOW",
  };
}
