**SIGNALSAFE CAMPUS**

**SYSTEM DESIGN & GITHUB REPOSITORY STRUCTURE**

System Design & GitHub Repository Blueprint • Version 1.0

## Document control

| Field | Value |

| --- | --- |

| Product | SignalSafe Campus |

| Document purpose | Detailed implementation design and repository blueprint |

| Version | 1.0 — proposed baseline |

| Delivery target | 24-hour hackathon prototype with extensible architecture |

| Team | 4 developers |

| Architecture | Modular monolith backend, shared API, multiple clients, shared PostgreSQL |

## 1. Design principles

- One authoritative backend and detection pipeline; clients must not implement separate verdict logic.

- Modular monolith for the hackathon: simple to deploy, but separated into clear domain modules.

- API-first parallel development: publish OpenAPI schemas and mock responses early.

- Security decisions are server-side. Never trust client-supplied roles, risk scores, verdicts or incident ownership.

- Privacy by design: explicit user submission, minimum data collection and no background reading of private chats.

- Degrade safely: if a threat-intelligence provider is unavailable, return a clearly labeled partial/unknown result.

## 2. System context and architecture

SignalSafe Campus accepts user-submitted suspicious URLs, message text and QR-decoded content through a browser extension, web dashboard, mobile-responsive PWA and (if available) an official WhatsApp Business integration. All channels call the same FastAPI backend. The backend validates the caller and input, runs the shared analysis pipeline, persists scan and incident records, and exposes authorized results to the user or campus administrator.

CHROME EXT.     WEB DASHBOARD     MOBILE PWA     WHATSAPP CLOUD API      |                |                |                 |      +----------------+----------------+-----------------+                               |                          HTTPS / REST                               |                        FASTAPI BACKEND        +----------------------+----------------------+        |                      |                      |    Auth & RBAC          Detection Service       Incident Service                               |                  +------------+------------+                  |                         |            Rule Engine              Threat Intel Adapters                  |                         |                  +------------+------------+                               |                     SUPABASE POSTGRESQL                scans / incidents / evidence / audit

## 3. Component-level design

| Component | Design responsibilities | Owner |

| --- | --- | --- |

| API gateway / routes | Versioned REST routes, request validation, response models, authentication dependency, rate limiting hooks and request IDs. | Dev 1 |

| Authentication & RBAC | Validate Supabase access tokens; derive user identity and role server-side; enforce user ownership and campus-admin scope. | Dev 1 |

| Detection engine | Normalize input, extract indicators, run deterministic checks, call threat-intelligence adapters, score and explain findings. | Dev 1 |

| Incident service | Create reports, link scans, enforce permissions, manage status/severity/assignment and audit changes. | Dev 1 |

| Browser extension | Manifest V3 popup, current-tab URL scan, warning/result UI and explicit incident reporting. | Dev 2 |

| Web dashboard | Student/faculty scan and reporting UI; admin queue, incident detail, triage and metrics. | Dev 3 |

| Mobile PWA | Responsive mobile scan/report experience; QR decode locally; submit decoded content to API. | Dev 4 |

| WhatsApp adapter | Official inbound webhook, signature/token verification, message parsing and reply using shared service. | Dev 4; optional |

## 4. Core request flows

## 4.1 URL scan flow

1. User explicitly submits a URL from the browser extension, web app or mobile PWA.

1. Client sends POST /api/v1/scan/url with the URL and a valid access token when authentication is required.

1. Backend validates payload size and URL syntax; unsupported schemes are rejected.

1. Detection service normalizes the URL and extracts supported features such as hostname structure, punycode, IP-literal host, unusual port and suspicious encoding.

1. Optional threat-intelligence adapters query approved providers with timeouts and caching.

1. Scoring policy produces a verdict, risk level, indicators, recommendations and scoring-policy version.

1. Backend persists the scan metadata and returns the canonical response schema.

1. Client displays the evidence and offers an explicit report action; scanning alone does not automatically create an incident.

## 4.2 Incident reporting and response flow

1. Authenticated user submits an incident, optionally referencing a scan_id and attaching approved evidence.

1. Backend verifies ownership of the referenced scan and validates evidence metadata.

1. Incident is created with SUBMITTED status, severity default and unique ID.

1. Authorized campus admin views the scoped incident queue and reviews evidence.

1. Admin changes status/severity/assignment and adds investigation notes.

1. Every privileged state change is recorded in audit_logs.

1. Reporter sees only the fields and updates permitted by policy.

## 4.3 QR workflow

Decode the QR code on the client device where practical. Treat decoded content as untrusted input. If it contains a URL, send it through the same URL scan service. Never automatically open the decoded destination. Reject or clearly label non-URL payloads.

## 4.4 WhatsApp workflow

Use the official WhatsApp Business Platform/Cloud API only. The webhook receives user-submitted content, verifies the webhook request, applies size/type limits, calls the shared scan/report service and replies with the result. WhatsApp integration is optional and must not block the core release if credentials or setup are unavailable. Do not scrape WhatsApp Web or monitor private conversations.

## 5. Detection design

| Stage | Implementation guidance | Output |

| --- | --- | --- |

| Input validation | Type, length, scheme and parser validation; reject malformed or unsupported content. | Validated input |

| Normalization | Parse hostname and URL components safely; retain original only where justified. | Normalized representation |

| Feature extraction | Documented heuristic features: hostname length/labels, punycode, IP host, suspicious encoding, unusual port and deceptive patterns. | Indicator candidates |

| Threat intelligence | Provider adapter interface, timeout, cache, source timestamp and provider error handling. | External match/no-match/unavailable |

| Scoring | Versioned policy; distinguish confirmed feed match from heuristic warning; no uncalibrated probability claims. | Verdict and risk level |

| Explanation | Return each indicator, evidence category and user-safe recommendation. | Explainable result |

| Persistence | Store minimum necessary metadata and scoring version; raw message content only when justified by explicit report. | Scan record |

Initial verdict semantics: MALICIOUS/CONFIRMED MATCH only for a trusted source or verified test indicator; SUSPICIOUS for heuristic signals; LOW RISK / NO KNOWN INDICATORS does not guarantee safety; UNKNOWN when evidence is insufficient or a required provider is unavailable.

Do not fetch arbitrary user URLs from the primary API process. Redirect expansion or page inspection introduces SSRF and malware-exposure risk. If later required, isolate it in a restricted worker with egress controls, DNS/IP validation, redirect limits, timeouts and no access to internal networks or cloud metadata.

## 6. API design and shared contracts

| Method / route | Purpose | Authorization |

| --- | --- | --- |

| POST /api/v1/scan/url | Analyze a URL. | Public rate-limited or authenticated per chosen policy; no privileged data. |

| POST /api/v1/scan/message | Analyze submitted message text and extract URLs. | Authenticated or rate-limited; explicit submission. |

| POST /api/v1/scan/qr | Analyze decoded QR content. | Authenticated or rate-limited. |

| POST /api/v1/incidents | Create an incident. | Authenticated user; server assigns reporter. |

| GET /api/v1/incidents | List incidents visible to caller. | Own reports for user; scoped queue for admin. |

| GET /api/v1/incidents/{id} | Incident detail. | Owner or authorized campus admin. |

| PATCH /api/v1/incidents/{id} | Update status, severity or assignment. | Admin-only fields enforced server-side. |

| GET /api/v1/dashboard/stats | Aggregated campus metrics. | Authorized admin. |

| GET /api/v1/health | Service health. | No secrets or internal diagnostics. |

## 6.1 Canonical URL scan response

{   "scan_id": "uuid",   "verdict": "SUSPICIOUS",   "risk_level": "HIGH",   "risk_score": 78,   "scoring_version": "v1",   "indicators": [     {       "code": "LOOKALIKE_HOST",       "label": "Possible lookalike domain",       "evidence_type": "heuristic",       "detail": "The hostname resembles a known brand"     }   ],   "recommendations": [     "Do not enter credentials",     "Open the institution website using a saved bookmark"   ],   "checked_at": "2026-10-30T10:00:00Z" }

The example is a schema illustration, not a real scan result. Define exact enums and Pydantic models in shared/api-contracts before frontend integration. Clients must not calculate or override the authoritative verdict.

## 7. Data model

| Table | Important fields | Rules |

| --- | --- | --- |

| profiles | id (auth user FK), display_name, role, campus_id, created_at | Role changes are privileged; clients cannot self-assign admin. |

| scans | id, submitted_by, input_type, input_fingerprint, verdict, risk_score, scoring_version, indicators JSONB, created_at | Minimize raw input storage; store only what is needed. |

| incidents | id, created_by, scan_id nullable, category, severity, status, summary, description, assigned_to, campus_id, timestamps | Server assigns created_by/campus_id; validate scan ownership. |

| incident_evidence | id, incident_id, evidence_type, storage_path/reference, metadata JSONB, created_at | Private storage; validate size/type and authorize retrieval. |

| incident_notes | id, incident_id, author_id, note, created_at | Only authorized case participants/admins can read. |

| audit_logs | id, actor_id, action, resource_type, resource_id, metadata JSONB, created_at | Append-only application behavior; exclude secrets. |

Recommended incident status lifecycle: SUBMITTED → TRIAGED → INVESTIGATING → RESOLVED or CLOSED. Severity (LOW/MEDIUM/HIGH/CRITICAL) is independent of status. Include campus_id from the beginning if the design may support multiple institutions.

## 8. Security controls

- HTTPS for all deployed traffic; validate Supabase JWTs server-side.

- Enforce authorization on every incident read, update, evidence download and admin action. UUIDs do not replace access checks.

- Keep Supabase service-role keys, threat-intelligence keys and WhatsApp tokens on the backend only.

- Apply rate limits, request-size limits, strict schemas and safe error responses.

- Use least-privilege database access and Row Level Security where suitable; backend checks remain authoritative.

- Escape or sanitize user-submitted content before rendering; do not render arbitrary HTML from messages.

- Validate file uploads by size, extension and content; store in private object storage.

- Log security-relevant actions but never passwords, bearer tokens, API keys or unnecessary personal content.

- Make data collection explicit; no background browser-history collection or private chat surveillance.

## 9. GitHub monorepo structure

Use one repository so shared API contracts, documentation and integration changes are visible to the entire team. Each developer owns a top-level module and works on a feature branch.

signalsafe-campus/ ├── README.md ├── LICENSE ├── .gitignore ├── .env.example ├── docker-compose.yml                 # optional local development ├── docs/ │   ├── PRD.md │   ├── SYSTEM_ARCHITECTURE.md │   ├── SYSTEM_DESIGN.md │   ├── API_CONTRACT.md │   ├── DATABASE_SCHEMA.md │   ├── SECURITY_AND_PRIVACY.md │   └── demo/ │ ├── shared/ │   └── api-contracts/ │       ├── openapi.yaml │       ├── schemas/ │       └── examples/ │ ├── backend/                            # Developer 1 │   ├── app/ │   │   ├── main.py │   │   ├── core/                       # config, logging, errors │   │   ├── api/v1/                     # route handlers │   │   ├── auth/                       # JWT validation, RBAC │   │   ├── detection/                  # rules, parser, scoring │   │   ├── threat_intel/               # provider adapters │   │   ├── incidents/                  # case workflow │   │   ├── audit/ │   │   └── persistence/                # repositories/models │   ├── tests/ │   ├── requirements.txt │   └── Dockerfile │ ├── browser-extension/                  # Developer 2 │   ├── manifest.json │   ├── src/ │   │   ├── background/ │   │   ├── popup/ │   │   ├── content/ │   │   ├── options/ │   │   └── services/api.ts │   ├── public/ │   └── package.json │ ├── web-dashboard/                      # Developer 3 │   ├── src/ │   │   ├── app/ │   │   ├── components/ │   │   ├── features/ │   │   │   ├── scanner/ │   │   │   ├── incidents/ │   │   │   └── admin/ │   │   ├── lib/ │   │   └── services/api.ts │   ├── public/ │   └── package.json │ ├── mobile-pwa/                         # Developer 4 │   ├── src/ │   │   ├── app/ │   │   ├── components/ │   │   ├── features/ │   │   │   ├── qr-scanner/ │   │   │   ├── url-scan/ │   │   │   └── reporting/ │   │   ├── lib/ │   │   └── services/api.ts │   └── package.json │ ├── integrations/ │   └── whatsapp-cloud-api/             # Developer 4; optional │       ├── webhook/ │       ├── services/ │       └── README.md │ ├── supabase/ │   ├── migrations/ │   ├── seed.sql │   └── config.toml │ └── scripts/     ├── dev/     ├── test/     └── seed-demo-data.py

The WhatsApp integration is separated from mobile-pwa because it is a server-side webhook adapter, not a mobile client. It must call shared backend services and must not duplicate detection logic.

## 10. Repository governance and collaboration

| Practice | Rule |

| --- | --- |

| Branches | main = stable demo/release; develop = integration; feature/<owner>-<module> = work branches. |

| Pull requests | All changes go through PRs into develop; at least one teammate reviews API/schema/security changes. |

| Ownership | Use CODEOWNERS for backend, extension, dashboard, mobile and shared contracts. |

| Contracts | Changes to OpenAPI or shared schemas require notifying all client owners. |

| Commits | Use concise conventional prefixes where practical: feat, fix, docs, test, refactor, chore. |

| Secrets | Commit only .env.example with placeholder names; add real .env files and keys to .gitignore. |

| CI | Run backend tests/lint and frontend typecheck/lint/build on pull requests if setup time allows. |

| Integration | Merge small, working increments frequently; avoid one large final-day merge. |

## 11. Four-developer ownership matrix

| Developer | Primary ownership | Must publish early | Must not own |

| --- | --- | --- | --- |

| 1 — Backend/security | backend/, supabase/, shared API contract | OpenAPI draft, mock JSON, auth and DB schema | Frontend UI implementation |

| 2 — Browser extension | browser-extension/ | Extension scaffold, API client and mock scan flow | Separate phishing scoring logic |

| 3 — Web dashboard | web-dashboard/ | Page scaffold, role views and API client | Direct database writes bypassing backend |

| 4 — Mobile/WhatsApp | mobile-pwa/, integrations/whatsapp-cloud-api/ | QR/report flow and API client; WhatsApp feasibility check | Separate detection engine or unofficial WhatsApp scraping |

## 12. Build sequence and integration gates

| Timebox | Milestone | Exit gate |

| --- | --- | --- |

| 0–2 h | Repository, branch policy, database model and API contract agreed. | OpenAPI draft and example responses committed. |

| 2–5 h | Backend skeleton and client scaffolds; mock API available. | All clients can render mock scan results. |

| 5–10 h | URL detection and extension/web scan workflow. | A URL scan reaches backend and returns structured evidence. |

| 10–15 h | Incident creation and admin workflow. | A report created from a scan appears in admin queue. |

| 15–19 h | PWA QR flow and cross-client integration. | At least browser and web/PWA use the same live API. |

| 19–22 h | Authorization, regression and failure-mode tests. | Cross-user incident access is denied; degraded provider behavior is clear. |

| 22–24 h | Demo rehearsal and stabilization. | Repeatable end-to-end demo; no risky unmerged changes. |

## 13. Test plan and release gates

- Detection evaluation: use labeled benign/phishing samples; report precision, recall, F1 and false-positive rate. Keep train/test separation if ML is used.

- API validation: malformed URLs, unsupported schemes, oversized message bodies, missing/expired tokens and provider timeout.

- Authorization: Student A cannot read or modify Student B’s incident; non-admin cannot change admin-only fields.

- Integration: same URL scanned from extension and PWA returns consistent verdict semantics.

- Incident lifecycle: submit → triage → investigate → resolve; each admin change creates an audit record.

- Privacy: no background chat reading, no broad browser-history collection and no secrets in logs or repository.

## 14. Deployment and environment configuration

| Variable | Scope | Notes |

| --- | --- | --- |

| SUPABASE_URL | Client/backend as required | Project URL; configure per environment. |

| SUPABASE_ANON_KEY | Client | Public client key; RLS and server authorization still required. |

| SUPABASE_SERVICE_ROLE_KEY | Backend only | Privileged secret; never expose in extension or web bundle. |

| THREAT_INTEL_API_KEY | Backend only | Optional provider secret. |

| WHATSAPP_ACCESS_TOKEN | Webhook backend only | Optional official integration secret. |

| WHATSAPP_VERIFY_TOKEN | Webhook backend only | Webhook verification configuration; keep secret. |

| API_BASE_URL | Clients | Environment-specific backend URL. |

Use separate local/development and demo configuration. Never commit real keys. Configure CORS narrowly for known deployed origins; browser-extension origins must be explicitly handled if required.

## 15. Risks and mitigations

| Risk | Mitigation |

| --- | --- |

| Backend becomes a bottleneck | Publish mock API and OpenAPI early; freeze core schemas by hour 3. |

| Four interfaces exceed time | Prioritize extension + web dashboard + mobile-responsive PWA; WhatsApp is optional. |

| False positives undermine trust | Show exact indicators, source category and uncertainty; evaluate on labeled data. |

| Threat-intel service unavailable | Timeout, cache and return UNKNOWN/partial status; core rules remain available. |

| SSRF from URL fetching | Do not fetch arbitrary URLs in primary API; isolate any later fetcher. |

| Cross-user data exposure | Server-side ownership checks, scoped admin access and negative authorization tests. |

| WhatsApp access unavailable | Demonstrate manual share/report flow; do not use unofficial scraping. |

## 16. Definition of integrated prototype

- A user scans a suspicious URL in the browser extension or web/PWA.

- The shared backend returns an explainable verdict with documented limitations.

- The user explicitly submits an incident based on the result.

- The incident is persisted and appears in the authorized admin queue.

- An admin updates status and records a note; the action appears in the audit trail.

- An unauthorized user cannot access the incident.

- The demo clearly labels any simulated threat-intelligence or WhatsApp behavior.

## 17. Design decisions to confirm

- Confirm whether the mobile deliverable is a PWA for the hackathon or a native app; recommended: PWA first.

- Confirm whether WhatsApp Business API credentials and webhook setup are available; otherwise keep it optional.

- Confirm one-campus or multi-campus data scoping; include campus_id if multi-campus may be needed.

- Confirm which threat-intelligence source is approved and accessible.

- Agree on exact API enums, error format, pagination and auth requirements before client implementation.

## 18. Relationship to companion documents

This document is the implementation-level design companion to the SignalSafe Campus PRD and System Architecture Document. The PRD defines product requirements and acceptance criteria; the architecture document defines the logical system structure; this document expands component behavior, data/API contracts, security controls, repository layout and team integration practices.
