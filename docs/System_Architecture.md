**SIGNALSAFE CAMPUS**

**SYSTEM ARCHITECTURE DOCUMENT**

HackFusion 2.0 • 24-hour hackathon prototype • Version 1.0

## Document control

| Field | Value |

| --- | --- |

| Product | SignalSafe Campus |

| Document | System Architecture Document (SAD) |

| Version / status | 1.0 / Proposed hackathon architecture |

| Architecture style | Modular monolith backend + multiple clients + shared PostgreSQL |

| Primary stack | Next.js, Chrome MV3, responsive PWA, FastAPI, Supabase PostgreSQL/Auth |

## 1. Architecture objectives

- Provide one authoritative detection and incident-management backend for every client.

- Separate user interfaces from security decisions and persistence.

- Support parallel development by four developers through stable API contracts.

- Keep threat analysis explainable, auditable and safe to operate.

- Deliver a feasible prototype within 24 hours while allowing later expansion.

## 2. High-level logical architecture

Client channels call a versioned HTTPS API. The API authenticates the caller, validates input, invokes the shared detection service, persists scan/incident records and returns a consistent response. Administrators use the web dashboard to investigate incidents. External threat-intelligence providers are optional dependencies; the system must remain useful when they are unavailable.

[Chrome Extension]       [Web Dashboard]       [Mobile PWA]       [WhatsApp Cloud API]        |                       |                    |                      |        +-----------------------+--------------------+----------------------+                                        |                                 HTTPS / REST API                                        |                               [FastAPI Application]                                        |              +-------------------------+-------------------------+              |                         |                         |       [Auth & RBAC]             [Detection Service]       [Incident Service]                                        |                          +-------------+-------------+                          |                           |                  [Rule/Heuristic Engine]     [Threat Intel Adapters]                          |                           |                          +-------------+-------------+                                        |                              [Supabase PostgreSQL]                                        |                               [Audit/Event Records]

The diagram is logical rather than a deployment topology. For the hackathon, the FastAPI application can be a single deployable service with internally separated modules.

## 3. Component responsibilities

| Component | Responsibilities | Owner |

| --- | --- | --- |

| Chrome extension | Read current tab URL only with required permissions; explicit scan/report actions; render verdict and indicators. | Developer 2 |

| Web dashboard | Student scan/report screens; admin queue, case detail, status and metrics. | Developer 3 |

| Mobile PWA | Responsive scan/report UX; QR decoding in client; user status view. | Developer 4 |

| WhatsApp adapter | Receive user-submitted content via official webhook; validate webhook; call shared scan/report services; reply with result. | Developer 4 |

| FastAPI API layer | Versioned routes, schema validation, auth dependency, rate limiting hooks, response serialization. | Developer 1 |

| Detection service | Normalize inputs, apply rules, call threat-intelligence adapters, create evidence-backed verdict. | Developer 1 |

| Incident service | Create/read/update incidents; enforce ownership and admin scope; record transitions and notes. | Developer 1 |

| Supabase | PostgreSQL persistence and authentication identity; row-level security where appropriate. | Developer 1 |

## 4. Suggested backend module layout

backend/   app/     main.py     core/                 # settings, logging, errors     api/v1/               # route handlers     schemas/              # Pydantic request/response models     auth/                 # token validation, role dependencies     detection/       normalizer.py       url_rules.py       message_parser.py       scoring.py       service.py     threat_intel/       base.py       providers/     incidents/       service.py       permissions.py     persistence/       models.py       repositories.py     audit/       service.py   tests/   requirements.txt

## 5. Data architecture

Use a single Supabase PostgreSQL project. The following is a proposed minimal logical schema; names can be adjusted before migrations, but the team must agree on them before parallel implementation.

| Table | Key fields | Purpose |

| --- | --- | --- |

| profiles | id (auth user FK), display_name, role, campus_id, created_at | Application role and campus context. |

| scans | id, submitted_by, input_type, input_fingerprint, verdict, risk_score, scoring_version, indicators JSONB, created_at | Analysis history; avoid storing more raw content than needed. |

| incidents | id, created_by, scan_id nullable, category, severity, status, summary, description, assigned_to, created_at, updated_at | Report and investigation lifecycle. |

| incident_evidence | id, incident_id, evidence_type, storage_path/reference, metadata JSONB, created_at | Evidence metadata and controlled object references. |

| incident_notes | id, incident_id, author_id, note, created_at | Investigation notes with access controls. |

| audit_logs | id, actor_id, action, resource_type, resource_id, metadata JSONB, created_at | Record privileged actions and relevant access events. |

Recommended incident statuses: SUBMITTED → TRIAGED → INVESTIGATING → RESOLVED or CLOSED. Severity and status are separate fields. Define campus_id/tenant scope if multiple institutions are supported.

## 6. API contract

| Method and path | Request (summary) | Response (summary) |

| --- | --- | --- |

| POST /api/v1/scan/url | { url } | scan_id, verdict, risk_level, risk_score, indicators[], recommendations[], checked_at |

| POST /api/v1/scan/message | { message_text } | scan_id, extracted_urls[], findings[], verdict, recommendations[] |

| POST /api/v1/scan/qr | { decoded_content } | scan result for decoded URL/content; reject unsupported payloads safely |

| POST /api/v1/incidents | { scan_id?, category, summary, description?, evidence_refs? } | incident_id, status, created_at |

| GET /api/v1/incidents | Filters: status, severity, mine/page | Only records caller is authorized to view |

| GET /api/v1/incidents/{id} | Path incident ID | Incident plus permitted evidence and notes |

| PATCH /api/v1/incidents/{id} | Allowed status/severity/assignment fields | Updated incident; admin authorization required |

| GET /api/v1/dashboard/stats | Time range/filter | Aggregated metrics limited to authorized admin scope |

| GET /api/v1/health | None | Service health; no secrets or internal details |

Publish the exact Pydantic schemas and OpenAPI spec before client implementation. Use consistent error envelopes, UTC timestamps, pagination and request IDs. Do not let clients set trusted verdicts, scores, roles or incident ownership.

## 7. Detection pipeline

1. Input validation: enforce length/type limits; parse URLs using a standards-aware parser; reject malformed schemes and unsupported content.

1. Normalization: canonicalize hostname/URL carefully while retaining the original submitted value where retention is justified.

1. Feature extraction: inspect hostname structure, punycode/lookalike patterns, IP-literal hosts, suspicious encoding, unusual ports and other documented heuristics.

1. Threat-intelligence lookup: query approved sources through adapters; apply timeouts, caching and provider error handling.

1. Scoring: combine supported signals using a versioned policy; keep feed-confirmed matches distinct from heuristic indicators.

1. Result generation: return verdict, risk level, evidence indicators, recommendations, checked_at and limitations.

1. Persistence: store minimum necessary scan metadata; link scan to incident only when user submits a report.

Security guardrail: do not fetch arbitrary user-submitted URLs from the main API server. Redirect expansion or page inspection creates SSRF and malware exposure risks. If added later, run it in an isolated egress-restricted worker with DNS/IP validation, redirect limits, timeouts and no access to internal networks or cloud metadata endpoints.

## 8. Authentication and authorization

- Use Supabase Auth for identity. Clients send a short-lived access token over HTTPS; backend validates it and derives the user identity.

- Roles are assigned server-side and stored in a protected profile/role table. Never trust a role sent by the client.

- Student/faculty users can create incidents and read only their own reports unless campus policy explicitly allows otherwise.

- Campus admins can access incidents only within their authorized campus scope and can perform triage/update actions.

- Every incident lookup/update checks ownership or admin scope server-side; unpredictable IDs are not an authorization control.

- Use least-privilege database credentials. Keep service-role keys exclusively on the server; never ship them in browser extension or frontend bundles.

- Apply rate limits to scan and report endpoints; protect admin actions and webhook endpoints.

## 9. Privacy, evidence and operational security

- Make submission explicit. Do not monitor private browser activity or messaging conversations in the background.

- Browser extension permissions should be minimal; request access only for the feature being used. Explain when the current URL is sent for analysis.

- For WhatsApp, use the official WhatsApp Business Platform/Cloud API where available. Do not scrape WhatsApp Web or automate private-account sessions.

- Avoid storing full message content unless necessary for an incident and clearly disclosed. Offer redaction/minimization where practical.

- Validate uploads by size, type and content; store outside executable paths; restrict access with signed/authorized retrieval.

- Do not place credentials, tokens or private evidence in logs. Define retention and deletion policy before real campus deployment.

- Use synthetic incident examples for the hackathon demo; do not label real people or domains as malicious without evidence.

## 10. Client integration contracts

| Client | Minimum integration | Notes |

| --- | --- | --- |

| Browser extension | POST /scan/url; POST /incidents; optional auth token flow | Use Manifest V3; no broad history collection; show result before navigation only if extension design and permissions support it. |

| Web dashboard | All scan and incident endpoints; admin stats and updates | Primary admin experience and integration reference client. |

| Mobile PWA | POST /scan/url; POST /scan/message; POST /scan/qr; incident endpoints | QR decode can occur on device; send decoded content to shared API. |

| WhatsApp | Verified inbound webhook → shared service → reply | Only if official API setup, business verification/configuration and credentials are ready. Treat as optional integration. |

## 11. Deployment architecture

Hackathon deployment proposal: deploy Next.js dashboard and FastAPI separately; use Supabase hosted PostgreSQL/Auth; package the Chrome extension for local installation or developer-mode demo; host the PWA as the responsive web app; configure WhatsApp webhook only if approved credentials and a reachable HTTPS endpoint are available.

| Environment variable | Where used | Handling |

| --- | --- | --- |

| DATABASE_URL / Supabase server config | Backend | Server-side only; secret store. |

| SUPABASE_URL | Clients/backend as required | Public project URL; not a secret by itself. |

| SUPABASE_ANON_KEY | Client | Public client key; enforce RLS and backend authorization. |

| SUPABASE_SERVICE_ROLE_KEY | Backend only | Highly privileged secret; never expose to clients. |

| THREAT_INTEL_API_KEY | Backend only | Secret store; optional provider. |

| WHATSAPP_ACCESS_TOKEN / VERIFY_TOKEN | Backend webhook | Secret store; optional integration. |

## 12. Four-developer ownership and integration

| Developer | Owns | Integration contract |

| --- | --- | --- |

| 1 — Backend/security | FastAPI, detection engine, database migrations, auth/RBAC, incident APIs, OpenAPI spec | Publishes stable schemas, mock server/responses and API documentation early. |

| 2 — Browser extension | Manifest V3, popup, current URL scan, result and report UX | Consumes published scan and incident endpoints; no independent verdict logic. |

| 3 — Web dashboard | Next.js student/admin screens, incident queue, case detail, analytics | Consumes same APIs; does not directly bypass backend authorization. |

| 4 — Mobile/WhatsApp | PWA/mobile UI, QR decode, mobile reporting, optional WhatsApp webhook | Uses same scan/report contracts; WhatsApp remains optional and official-API based. |

## 13. 24-hour integration plan

| Window | Integration milestone | Exit condition |

| --- | --- | --- |

| 0–2 hours | Agree schema, endpoint names, response types, roles and repo structure. | OpenAPI draft and shared sample JSON committed. |

| 2–6 hours | Backend mock/API skeleton; clients scaffold independently. | All clients can call mock endpoints. |

| 6–12 hours | Detection and primary UI workflows. | URL scan works end-to-end in at least one client. |

| 12–17 hours | Incident lifecycle and admin queue. | Submitted report appears in admin dashboard. |

| 17–21 hours | Connect extension and mobile/PWA; optional WhatsApp. | At least two client channels use the same live API. |

| 21–24 hours | Security tests, regression, demo rehearsal. | Demonstrate scan → report → triage → resolution. |

## 14. Test strategy

| Test category | Minimum checks |

| --- | --- |

| Detection | Known phishing and benign labeled samples; precision/recall; false-positive review; provider unavailable behavior. |

| API | Schema validation, malformed URLs, oversized inputs, rate limits, error responses. |

| Authorization | Student A cannot read/update Student B’s incident; non-admin cannot change severity/assignment/status. |

| Injection and uploads | SQL/HTML payload handling; upload size/type validation; no unsafe rendering of submitted content. |

| Integration | Extension and PWA scan the same URL and display same verdict; incident created from scan appears in admin queue. |

| Privacy | No background chat/browser surveillance; no tokens or secrets in logs; explicit consent for submitted content. |

## 15. Key architecture decisions

| Decision | Rationale |

| --- | --- |

| One shared backend | Avoids duplicated detection logic and inconsistent verdicts. |

| Modular monolith for prototype | Lower operational complexity than microservices; modules can be separated later if needed. |

| PWA before native apps | Provides a mobile-ready experience within the hackathon timebox. |

| WhatsApp official integration only | Avoids fragile scraping and unauthorized access to private conversations. |

| Rules + optional threat intelligence first | Explainable, testable baseline; ML can be added only with evaluation evidence. |

| Backend is authoritative | Clients cannot choose risk scores, roles, incident ownership or trusted status. |

## 16. Open decisions before implementation

- Which threat-intelligence provider(s) are available and permitted for the event?

- Will the organizers provide API test infrastructure or should the team create its own controlled test set?

- Will campus admins be scoped to one institution or multiple campuses?

- Which evidence types and retention duration are acceptable for the demo?

- Are WhatsApp Business credentials and webhook hosting available during the hackathon?

- Will mobile delivery be PWA-only for the event, with native apps deferred?

## 17. Reference

Primary source: HACKFUSION 2.0 – 24Hours National Level Hackathon, Problem Statements, Cybersecurity theme, “SignalSafe Campus: Recognize, Resist and Report Digital Threats,” page 8 of the organizer PDF. The architecture choices, API contracts, role model and delivery priorities in this document are proposed implementation decisions for the team, not requirements explicitly prescribed by the organizer.
