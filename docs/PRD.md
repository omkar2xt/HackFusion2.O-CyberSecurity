**SIGNALSAFE CAMPUS**

**PRODUCT REQUIREMENTS DOCUMENT**

HackFusion 2.0 • 24-hour hackathon prototype • Version 1.0

## Document control

| Field | Value |

| --- | --- |

| Product | SignalSafe Campus |

| Document | Product Requirements Document (PRD) |

| Version / status | 1.0 / Proposed baseline for hackathon implementation |

| Primary users | Students, faculty, campus IT/security administrators |

| Delivery constraint | 24-hour hackathon prototype |

| Source alignment | HACKFUSION 2.0 Cybersecurity Problem Statement: SignalSafe Campus (uploaded problem statement, page 8) |

## 1. Product overview

SignalSafe Campus is a campus-focused cybersecurity platform that helps users recognize, assess, prevent and report digital threats. It accepts user-submitted URLs, suspicious messages and QR-code destinations, provides explainable risk assessments and routes incidents to authorized campus personnel for investigation.

The product is delivered through a shared backend and multiple user-facing channels: a web dashboard, a Chrome browser extension, a mobile-friendly web/PWA experience, and a WhatsApp reporting integration where official platform access and credentials are available.

## 2. Problem statement

Students, faculty and administrative staff encounter phishing, fraudulent websites, malicious links, QR-code scams, payment fraud, cyberbullying and impersonation. Users may not recognize suspicious content, may not know how to report it, and may fail to preserve useful evidence. SignalSafe Campus provides a consistent analysis and incident-reporting workflow.

## 3. Product goals and non-goals

## 3.1 Goals

- Allow a user to submit a URL, message text or QR-derived URL for analysis.

- Return a risk level, verdict, indicators and actionable safety recommendations.

- Make it easy to submit a suspicious item as a campus incident.

- Provide authorized administrators with an incident queue, evidence view and status workflow.

- Offer consistent functionality across the web dashboard, browser extension and mobile experience.

- Use a single detection service and common data model so all clients behave consistently.

- Protect reports and personal information through authentication, authorization, validation and audit logging.

## 3.2 Non-goals for the 24-hour prototype

- Guaranteed detection of every phishing, payment-fraud, cyberbullying or impersonation case.

- Reading or monitoring private WhatsApp conversations in the background.

- Automatically blocking websites at the operating-system or network level.

- A production-grade native iOS and Android application.

- Autonomous incident remediation or contacting alleged attackers.

- Claiming that a heuristic warning proves a URL is malicious.

## 4. Target users and permissions

| Role | Primary capabilities | Restrictions |

| --- | --- | --- |

| Student / faculty | Scan submitted content; submit and view own reports; receive guidance. | Cannot view other users’ private reports or administer cases. |

| Campus security admin | View authorized incident queue; triage, assign, update status; record investigation notes. | Access limited to assigned/authorized campus scope; actions audited. |

| Platform administrator | Manage roles, configuration and integration settings. | Privileged actions require strong protection and audit records. |

## 5. Scope and feature requirements

## 5.1 Core features — must have

| ID | Requirement | Acceptance criteria |

| --- | --- | --- |

| FR-01 URL scan | User submits a URL for analysis. | API validates and normalizes input; returns scan ID, verdict, risk score/level, indicators and recommendations. |

| FR-02 Message analysis | User submits suspicious message text. | System extracts URLs and applies supported indicators; output clearly states what was and was not analyzed. |

| FR-03 Explainable result | Show why a result was flagged. | Every finding includes an indicator, evidence/source category and confidence or limitation where applicable. |

| FR-04 QR workflow | Decode QR content and analyze the destination URL. | QR flow submits decoded text/URL to the same URL analysis service; no automatic navigation. |

| FR-05 Incident submission | User converts a scan or manual submission into an incident. | Incident receives unique ID, timestamp, submitter, status and linked evidence. |

| FR-06 Admin triage | Authorized admin reviews and updates incidents. | Admin can set severity/status, add investigation notes and record resolution; each change is audited. |

| FR-07 Shared clients | Extension, web and mobile clients use the common API. | Same input produces consistent schema and verdict semantics across clients. |

| FR-08 Access control | Protect private incident data. | Server enforces role and ownership checks on every protected operation. |

## 5.2 Should-have features

- Chrome extension popup with current-tab URL scan and explicit user-triggered reporting.

- Threat-intelligence lookup against an approved feed/API, subject to availability and rate limits.

- Dashboard metrics: report volume, severity distribution, open/resolved cases and common indicators.

- User-facing report status and safe-action guidance.

- Evidence attachment support with file-type, size and content validation.

## 5.3 Could-have / post-hackathon

- Official WhatsApp Business Platform webhook for user-submitted messages or URLs.

- Native Android/iOS app; initially use a responsive PWA to demonstrate mobile workflows.

- Machine-learning classifier trained and evaluated on a labeled dataset.

- Additional incident categories such as payment fraud, impersonation and cyberbullying, each with tailored triage workflows.

## 6. User journeys

## 6.1 Scan a suspicious link

1. User opens SignalSafe in the web app or browser extension.

1. User submits/picks a URL; the client sends it to POST /api/v1/scan/url.

1. Backend validates the input, applies deterministic checks and optional threat-intelligence lookups.

1. Backend returns a structured result with risk level, indicators and recommendations.

1. Client displays the result and offers an explicit option to submit an incident.

## 6.2 Report and investigate an incident

1. Authenticated user submits a suspicious item and optional context/evidence.

1. Backend creates an incident and links the scan result where available.

1. Authorized campus admin sees the incident in the queue.

1. Admin reviews evidence, sets severity/status, adds notes and records actions.

1. User sees permitted status updates; all privileged changes are audit logged.

## 7. Risk model and result semantics

Use a transparent, versioned scoring policy. The initial score may combine deterministic indicators and threat-intelligence matches. Do not present an uncalibrated score as a probability.

| Output | Meaning |

| --- | --- |

| MALICIOUS / confirmed match | A trusted threat-intelligence source or verified test indicator matched. Include source and timestamp. |

| SUSPICIOUS | One or more heuristic indicators warrant caution; not proof of maliciousness. |

| LOW RISK / no known indicators | No supported indicators were found. This is not a guarantee of safety. |

| UNKNOWN / unavailable | Insufficient data, unsupported input, or external lookup unavailable. |

If a numeric score is shown, document the scoring version and explain the contributing indicators. Distinguish feed-confirmed matches from heuristic flags in both UI and API.

## 8. Non-functional requirements

| Area | Requirement |

| --- | --- |

| Security | HTTPS in deployment; server-side authorization; least privilege; secret management; input validation; safe error handling. |

| Privacy | Explicit submission; data minimization; avoid collecting full private conversations; define retention and deletion policy. |

| Performance | For the hackathon demo, aim for a typical rule-based URL scan response within 2 seconds, excluding external feed latency. |

| Reliability | Gracefully handle unavailable threat-intelligence providers; return UNKNOWN/degraded status rather than silently failing. |

| Usability | Risk reasons and next steps understandable to non-technical campus users. |

| Auditability | Record admin actions and security-relevant events without logging passwords, tokens or unnecessary sensitive content. |

| Compatibility | Modern Chromium browser for extension demo; responsive mobile browser experience. |

## 9. Success metrics

- Detection quality measured on a held-out labeled dataset using precision, recall, F1 and false-positive rate.

- Percentage of scans returning a structured, explainable result.

- Incident submission success rate and time to create a report.

- Admin triage completion time in the demo workflow.

- Authorization test pass rate, including attempts to access another user’s incident.

- End-to-end success: browser extension or mobile/web client → shared API → stored incident → admin dashboard.

## 10. 24-hour delivery priorities

| Priority | Deliverable | Owner |

| --- | --- | --- |

| P0 | API contract, backend, URL detection, shared database and auth/authorization | Developer 1 |

| P0 | Chrome extension: current URL scan, result display, report action | Developer 2 |

| P0 | Web dashboard: scan UI, incident submission, admin queue and status updates | Developer 3 |

| P1 | Mobile-responsive PWA, QR decode and reporting flow | Developer 4 |

| P2 | WhatsApp official reporting integration if credentials and setup permit | Developer 4 |

Integration rule: Developer 1 publishes OpenAPI documentation and mock responses within the first 2–3 hours. Other developers build against the agreed contract rather than waiting for the complete backend.

## 11. Assumptions, dependencies and risks

| Item | Assumption / mitigation |

| --- | --- |

| Threat intelligence | Provider access, API keys, quotas and terms may constrain live lookups. Keep rule-based checks functional without external services. |

| Datasets | The organizer-listed datasets may not cover every incident category. Use labeled public data only for supported tasks and clearly marked synthetic examples for demos. |

| WhatsApp | Use an official, permitted integration. Do not scrape WhatsApp Web or read private chats in the background. |

| QR scanning | Decode locally and analyze the destination; do not automatically open it. |

| URL safety | Do not blindly fetch arbitrary submitted URLs from the backend. If redirect inspection is implemented, use an isolated, restricted fetcher with SSRF protections. |

| False positives | Show evidence and uncertainty; provide a reporting/feedback path. |

| Scope | Prioritize a complete URL-to-incident-to-admin workflow over unfinished breadth. |

## 12. Definition of done

- All P0 workflows operate against the same backend and database.

- A labeled test set has been run and basic metrics are reported honestly.

- A user can submit a URL, receive an explainable result and create an incident.

- An authorized admin can investigate and update that incident.

- A user cannot read or modify another user’s private incident.

- The extension and responsive web experience demonstrate the same scan semantics.

- No private secrets are committed to the repository; demo data is synthetic or approved.

## 13. Source alignment and interpretation

The uploaded HACKFUSION 2.0 problem statement (page 8) calls for analysis of suspicious messages, URLs, QR codes and reported incidents; understandable risk alerts and safety recommendations; and a secure reporting mechanism for authorized campus personnel. It also emphasizes usability, privacy, accessibility and rapid response. It explicitly notes that the listed datasets do not cover all SignalSafe features and that cyberbullying, payment fraud and campus-specific incidents need additional suitable data or carefully designed synthetic examples.
