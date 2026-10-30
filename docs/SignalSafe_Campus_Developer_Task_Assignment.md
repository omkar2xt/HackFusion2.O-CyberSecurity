**SIGNALSAFE CAMPUS**

**DEVELOPER TASK ASSIGNMENT DOCUMENT**

Feature ownership • Deliverables • Dependencies • Acceptance criteria • 24-hour plan

## 1. Purpose and working agreement

This document divides SignalSafe Campus into four independently owned workstreams for a four-developer hackathon team. Each developer owns the implementation and testing of their module, but all modules must use one shared backend, one common API contract and one agreed data model.

Product scope is based on the SignalSafe Campus problem statement in HACKFUSION 2.0 (uploaded organizer PDF, page 8), together with the team's chosen delivery direction: web dashboard, Chrome browser extension, mobile-friendly PWA and an optional official WhatsApp reporting integration.

- Do not create separate phishing detection engines in client applications. The backend is the single source of truth for verdicts and risk scores.

- Do not start integration against guessed endpoints. Developer 1 publishes the API contract and mock responses early.

- All features must be demonstrable. A smaller complete workflow is better than multiple unfinished interfaces.

- WhatsApp is conditional on official API access and credentials; do not scrape WhatsApp Web or read private chats in the background.

- Mobile deliverable for the 24-hour event is a responsive PWA unless the team explicitly agrees otherwise.

## 2. Team overview

| Developer | Role | Primary ownership | Priority |

| --- | --- | --- | --- |

| Developer 1 | Backend & Cybersecurity Engine | FastAPI, detection, threat-intelligence adapters, authentication/RBAC, database and incident APIs | P0 — critical dependency |

| Developer 2 | Browser Extension | Chrome Manifest V3 extension, current-tab URL scan, warnings and reporting | P0 |

| Developer 3 | Web Dashboard | Student/faculty interface, admin incident queue, case management and analytics | P0 |

| Developer 4 | Mobile & Messaging | Mobile PWA, QR scanning, mobile reporting and optional WhatsApp Cloud API adapter | P1/P2 |

## 3. Developer 1 — Backend & Cybersecurity Engine

Mission: deliver the shared security service that all clients use. This developer owns the backend, authoritative detection decisions, identity/authorization checks and persistence.

## 3.1 Features to build

| ID | Feature | Implementation tasks | Priority |

| --- | --- | --- | --- |

| BE-01 | FastAPI service foundation | Create app entry point, configuration, versioned routes, Pydantic schemas, CORS policy, health endpoint and consistent error responses. | P0 |

| BE-02 | URL analysis engine | Validate URL and scheme; parse hostname; normalize safely; extract documented indicators such as punycode, IP-literal host, unusual port, suspicious encoding and deceptive hostname patterns. | P0 |

| BE-03 | Explainable risk result | Return verdict, risk level, indicators, recommendations, timestamp and scoring-policy version. Keep confirmed feed matches separate from heuristic warnings. | P0 |

| BE-04 | Message analysis | Accept explicitly submitted text, extract URLs and analyze supported indicators. State clearly when only extracted URLs were analyzed. | P1 |

| BE-05 | Threat-intelligence adapter | Create provider interface; integrate an approved feed/API if credentials exist; implement timeout, caching and provider-unavailable handling. | P1 |

| BE-06 | Authentication and RBAC | Validate Supabase JWT; derive user ID and role server-side; enforce student ownership and campus-admin permissions. | P0 |

| BE-07 | Incident APIs | Create/list/read/update incidents; validate scan ownership; support status, severity, assignment and notes with role checks. | P0 |

| BE-08 | Database and migrations | Create profiles, scans, incidents, evidence metadata, notes and audit logs; define indexes, constraints and RLS policy as appropriate. | P0 |

| BE-09 | Audit logging | Record admin status/severity/assignment changes and relevant security events; never log secrets or bearer tokens. | P1 |

| BE-10 | API documentation and mocks | Publish OpenAPI specification, sample request/response JSON and mock endpoints by hour 2–3. | P0 |

## 3.2 Backend endpoints to publish

| Method / endpoint | Expected behavior |

| --- | --- |

| POST /api/v1/scan/url | Analyze URL and return canonical scan result. |

| POST /api/v1/scan/message | Analyze submitted message text and extracted URLs. |

| POST /api/v1/scan/qr | Analyze decoded QR payload; URL payloads use the same URL scanner. |

| POST /api/v1/incidents | Create incident; reporter identity is derived from auth token. |

| GET /api/v1/incidents | Return only incidents caller is authorized to view; support pagination/filters. |

| GET /api/v1/incidents/{id} | Return incident detail after ownership/admin-scope check. |

| PATCH /api/v1/incidents/{id} | Admin-only updates for status, severity, assignment and permitted fields. |

| GET /api/v1/dashboard/stats | Return authorized admin aggregates. |

| GET /api/v1/health | Return basic service health without exposing secrets. |

## 3.3 Required deliverables

- Backend runs locally and has a documented start command.

- OpenAPI spec and mock responses committed early.

- URL scanner returns explainable results for a small labeled test set.

- Database migrations and seed/demo data are committed.

- Auth and role checks are implemented server-side.

- At least one end-to-end incident can be created, listed by an admin and updated.

- README documents environment variables and setup; real secrets are not committed.

## 3.4 Acceptance criteria

- Malformed URLs and unsupported schemes are rejected safely.

- Every scan response follows the shared schema.

- An external provider outage does not crash the scanner; result is marked partial/unknown as appropriate.

- Student A cannot read or modify Student B's incident.

- A non-admin cannot perform admin-only incident updates.

- Admin actions create audit records.

- Detection claims are supported by indicators; no claim of guaranteed phishing detection.

## 3.5 Explicitly out of scope

- Building browser, mobile or dashboard user interfaces.

- Fetching arbitrary submitted URLs from the primary API server. Any future redirect inspection must use an isolated, restricted worker.

- Building a full ML research pipeline during the 24-hour event unless the core rules-based engine is complete.

## 4. Developer 2 — Chrome Browser Extension

Mission: provide a lightweight browser-side entry point for users to inspect the current website and submit suspicious URLs. The extension displays backend results; it does not make authoritative risk decisions.

## 4.1 Features to build

| ID | Feature | Implementation tasks | Priority |

| --- | --- | --- | --- |

| EX-01 | Manifest V3 setup | Create manifest, service worker/background entry, popup UI, icons and build scripts. | P0 |

| EX-02 | Current-tab URL capture | Read the active tab URL only when the user invokes the scan action; request minimal permissions. | P0 |

| EX-03 | Scan action | Send URL to POST /api/v1/scan/url and handle loading, success, validation and network-error states. | P0 |

| EX-04 | Risk result UI | Show verdict, risk level, indicators and recommendations from backend response. | P0 |

| EX-05 | Safety warning | Display a clear caution state for suspicious/confirmed results; do not claim a low-risk result guarantees safety. | P0 |

| EX-06 | Report action | Allow explicit submission to POST /api/v1/incidents, linking scan_id and user-provided context. | P0 |

| EX-07 | Authentication handoff | Use an agreed secure login/token approach; do not hardcode tokens or privileged keys in extension files. | P1 |

| EX-08 | Settings/help | Show backend connection status, privacy explanation and basic help. | P2 |

## 4.2 Suggested extension screens

- Idle popup: current domain, Scan this page action and short privacy note.

- Scanning state: progress indicator and cancel/close behavior.

- Result state: verdict, risk level, evidence indicators, recommended action and Report this site.

- Error state: backend unavailable, unsupported URL or rate limit; offer retry without inventing a verdict.

- Report state: optional user context, confirmation and incident reference.

## 4.3 Required deliverables

- Loadable Chrome Manifest V3 extension in developer mode.

- Popup scans the current tab URL through the shared backend.

- Result view uses API response rather than local duplicate scoring.

- User can submit a report linked to the scan.

- Minimal permissions are documented; no browser history collection or background surveillance.

- Setup instructions and demo steps are in browser-extension/README.md.

## 4.4 Acceptance criteria

- Extension loads without manifest/runtime errors.

- Clicking Scan sends the active URL to the correct API endpoint.

- Backend verdict and indicators render correctly.

- Network failure is shown as an error/unknown state, not as safe.

- Report action creates an incident and displays its reference.

- Extension does not automatically open submitted links or transmit browsing data without an explicit scan action.

## 4.5 Explicitly out of scope

- Implementing phishing classification independently in JavaScript.

- Reading all tabs, browsing history or page content by default.

- Blocking all navigation at browser level for the hackathon prototype.

## 5. Developer 3 — Web Dashboard

Mission: build the primary user and campus-admin portal. This is the central visual interface for scanning, reporting, triaging and demonstrating the incident-response lifecycle.

## 5.1 Features to build

| ID | Feature | Implementation tasks | Priority |

| --- | --- | --- | --- |

| WD-01 | Application shell | Create Next.js app, navigation, responsive layout, loading/error states and API client. | P0 |

| WD-02 | Authentication UI | Login/logout and role-aware navigation using agreed Supabase Auth flow. | P0 |

| WD-03 | Student/faculty scanner | Form to submit URL and optionally message text; display backend verdict, score/level, indicators and recommendations. | P0 |

| WD-04 | Incident submission | Create report from a scan or manual report; collect category and concise context; show incident reference. | P0 |

| WD-05 | My reports | List current user's incidents and show permitted status/detail information. | P1 |

| WD-06 | Admin dashboard | Display incident counts, severity distribution, open/resolved counts and recent cases using API aggregates. | P0 |

| WD-07 | Incident queue | Filter/search authorized incidents by status and severity; paginate results. | P0 |

| WD-08 | Incident detail | Show submitted content/evidence metadata, linked scan indicators, timeline and investigation notes as permitted. | P0 |

| WD-09 | Case management | Allow admin to update status, severity, assignment and notes through authorized API calls. | P0 |

| WD-10 | Audit visibility | Show permitted action history/timeline for the case; no direct database bypass. | P1 |

## 5.2 Suggested pages

| Route (suggested) | Purpose |

| --- | --- |

| /login | Authentication |

| /scan | Student/faculty URL and message scanner |

| /report | Manual suspicious-activity report |

| /my-reports | Reporter’s own incidents |

| /admin | Admin overview and metrics |

| /admin/incidents | Incident queue and filters |

| /admin/incidents/[id] | Incident detail, evidence, notes and status controls |

## 5.3 Required deliverables

- Responsive web app with login and role-aware navigation.

- Working URL scan UI connected to backend.

- Incident creation and reporter confirmation.

- Admin queue and case detail connected to real API data.

- Admin status/severity update flow.

- Useful empty, loading, validation and error states.

- Setup and demo instructions in web-dashboard/README.md.

## 5.4 Acceptance criteria

- Scan results display the backend's exact verdict and evidence.

- Student/faculty users cannot see admin-only routes or data; backend still enforces access.

- Admin can find a submitted incident and move it through the defined lifecycle.

- Updates are reflected after refresh and recorded by backend audit logging.

- Dashboard metrics are derived from backend data, not hardcoded demo numbers.

- Mobile viewport remains usable even if native mobile functionality is owned by Developer 4.

## 5.5 Explicitly out of scope

- Writing directly to Supabase tables from the UI if that bypasses the agreed backend authorization model.

- Creating a second detection engine or independently changing verdict semantics.

- Building the Chrome extension or WhatsApp webhook.

## 6. Developer 4 — Mobile PWA, QR and WhatsApp Integration

Mission: deliver a phone-friendly reporting channel and QR workflow. WhatsApp is an optional adapter that must use official platform interfaces and the same backend services.

## 6.1 Mobile PWA features

| ID | Feature | Implementation tasks | Priority |

| --- | --- | --- | --- |

| MO-01 | PWA foundation | Create responsive installable web experience or agreed mobile client; configure manifest/icons if supported. | P1 |

| MO-02 | Mobile URL scan | Allow paste/share of a URL and submit it to POST /api/v1/scan/url. | P1 |

| MO-03 | QR scanner | Use device camera permission to decode QR locally; show decoded destination before analysis/navigation. | P1 |

| MO-04 | QR analysis | Submit decoded URL/content to POST /api/v1/scan/qr or common URL endpoint as agreed. | P1 |

| MO-05 | Message submission | Allow user to paste suspicious message text and send to POST /api/v1/scan/message. | P1 |

| MO-06 | Incident reporting | Submit suspicious item with category and optional context; display incident reference. | P1 |

| MO-07 | Report status | Allow authenticated reporter to view their own report status through authorized API. | P2 |

| MO-08 | Mobile UX/privacy | Permission explanation, camera denial fallback, accessible controls and explicit submit actions. | P1 |

## 6.2 WhatsApp integration — conditional

| ID | Feature | Implementation tasks | Priority |

| --- | --- | --- | --- |

| WA-01 | Feasibility check | Confirm official WhatsApp Business Platform/Cloud API access, credentials, webhook URL and account setup early. | P2 |

| WA-02 | Webhook verification | Implement official webhook verification and validate inbound requests per provider guidance. | P2 |

| WA-03 | Inbound submission | Accept user-submitted text/URL, enforce limits and call shared backend scan/report services. | P2 |

| WA-04 | Reply | Send concise verdict, evidence summary and safe next step through official API. | P2 |

| WA-05 | Privacy and abuse controls | Do not ingest private conversations; process only messages users intentionally send to the bot; rate-limit and avoid echoing sensitive content. | P2 |

## 6.3 Required deliverables

- Responsive mobile experience that can scan/paste a URL and submit a report.

- QR decoding works on a supported device or a clearly documented fallback accepts an uploaded QR image.

- Decoded QR destination is displayed before the user chooses to analyze it; never auto-open it.

- Message text can be explicitly submitted for analysis if backend endpoint is ready.

- WhatsApp adapter is delivered only if official access and setup are available; otherwise provide a documented feasibility result and demo the manual share-to-PWA flow.

- Setup and privacy notes are documented in mobile-pwa/README.md and integrations/whatsapp-cloud-api/README.md.

## 6.4 Acceptance criteria

- Mobile scan calls the same backend and displays the canonical result.

- QR destination is decoded and sent to the shared analysis pipeline.

- Camera permission denial does not break manual URL submission.

- User can create an incident and see its reference.

- WhatsApp integration, if enabled, verifies inbound webhook and never scrapes WhatsApp Web.

- Secrets remain server-side and no private chats are monitored.

## 6.5 Explicitly out of scope

- Building separate mobile phishing rules or risk scoring.

- Native iOS and Android apps in parallel during the 24-hour event unless the team deliberately drops other P1 work.

- Unofficial WhatsApp browser automation or background conversation access.

## 7. Shared integration contract — mandatory for all developers

## 7.1 Canonical scan response

{   "scan_id": "uuid",   "verdict": "SUSPICIOUS",   "risk_level": "HIGH",   "risk_score": 78,   "scoring_version": "v1",   "indicators": [     {       "code": "LOOKALIKE_HOST",       "label": "Possible lookalike domain",       "evidence_type": "heuristic",       "detail": "Evidence explanation"     }   ],   "recommendations": ["Do not enter credentials"],   "checked_at": "2026-10-30T10:00:00Z" }

Illustrative schema only. Developer 1 owns the final OpenAPI/Pydantic definition. All clients must use exact enum values and must handle UNKNOWN, provider unavailable, validation errors and rate limiting.

## 7.2 Shared rules

- All clients use the same API base URL per environment.

- All API timestamps use ISO 8601 UTC.

- Backend derives submitter identity and role from verified authentication; clients never submit trusted owner/role fields.

- Clients display evidence returned by backend and do not invent threat findings.

- All incident access and updates are authorized server-side.

- Use a shared API client or generated types where practical; keep contract changes coordinated through shared/api-contracts/openapi.yaml.

## 8. Repository ownership

| Path | Owner | Review / dependency |

| --- | --- | --- |

| backend/** and supabase/** | Developer 1 | API/schema changes must be announced to all client developers. |

| browser-extension/** | Developer 2 | Consumes backend API contract. |

| web-dashboard/** | Developer 3 | Consumes backend API; admin UI depends on incident endpoints. |

| mobile-pwa/** | Developer 4 | Consumes scan/report APIs. |

| integrations/whatsapp-cloud-api/** | Developer 4 | Optional; calls shared backend service. |

| shared/api-contracts/** | Developer 1 maintains; all review | Any breaking change requires client-owner acknowledgement. |

| docs/** | All; coordinator maintains | Keep setup, API and demo steps current. |

## 9. 24-hour execution schedule

| Time | Dev 1 — Backend | Dev 2 — Extension | Dev 3 — Dashboard | Dev 4 — Mobile/WhatsApp |

| --- | --- | --- | --- | --- |

| 0–2 h | Agree schema, OpenAPI, mock response, repo setup | Scaffold extension; connect mock | Scaffold app and role pages | Scaffold PWA; verify QR library/device support; check WhatsApp access |

| 2–6 h | API skeleton, auth and URL rules | Popup and scan request | Scanner UI and login | Mobile scan/report shell |

| 6–10 h | Detection response and persistence | Result and warning UI | Display real scan response | QR decode and scan |

| 10–15 h | Incident create/list/update APIs | Report action | Admin queue and case detail | Incident reporting |

| 15–19 h | RBAC, audit and integration support | End-to-end extension tests | Status updates and dashboard metrics | PWA integration; WhatsApp only if ready |

| 19–22 h | Authorization and API regression | Fix extension defects | Fix dashboard defects | Fix mobile defects |

| 22–24 h | Release stabilization | Demo rehearsal | Demo rehearsal | Demo rehearsal |

## 10. Team lead / coordinator responsibilities

- Create the GitHub repository, branches, issue labels and project board.

- Confirm the final feature cut and ensure P0 work is not displaced by optional integrations.

- Hold a short contract review at hour 2–3 and an integration checkpoint around hours 10, 15 and 20.

- Require small pull requests and review cross-module changes promptly.

- Maintain a single demo script and seed data set.

- Freeze non-critical features during the final 2–3 hours; prioritize a stable end-to-end flow.

## 11. Final demo acceptance checklist

- Browser extension scans a test URL and displays backend-generated evidence.

- Student submits a report from the scan.

- Report is visible in the authorized admin dashboard.

- Admin updates status/severity and adds an investigation note.

- Reporter can view the allowed status update.

- Another student cannot access the report by changing its ID.

- Mobile PWA scans a URL and demonstrates QR decode/report flow, or documents a device limitation with a working fallback.

- WhatsApp is either shown through an official working integration or clearly marked as a future/optional integration.

- All demo URLs, incidents and user identities are synthetic test data.

## 12. Definition of completion

A developer’s module is complete when its assigned P0/P1 acceptance criteria pass, its code is merged into the integration branch, setup instructions are documented, it uses the agreed shared API contract, and it can be demonstrated without relying on another developer’s local machine. Optional features must be clearly labeled rather than represented as complete.

## 13. Companion documents

Use this assignment document alongside the SignalSafe Campus PRD, System Architecture Document, and System Design & GitHub Repository Structure document. If a conflict appears, the team should resolve it explicitly and update the shared requirements/API contract rather than silently implementing different assumptions.
