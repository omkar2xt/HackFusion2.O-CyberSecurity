**SIGNALSAFE CAMPUS**

Technology Stack & Implementation Guide

A shared technical baseline for the browser extension, web dashboard, mobile PWA, backend detection engine and campus incident workflow.

| Project | SignalSafe Campus |

| --- | --- |

| Document | Technology Stack |

| Purpose | Team implementation reference |

## 1. Product Overview

SignalSafe Campus is a multi-channel campus cybersecurity platform. It helps students and staff submit suspicious URLs, messages and QR destinations for assessment; understand the evidence behind a risk result; and report incidents to authorized campus personnel.

The product is organized around one backend and one shared detection engine. The browser extension, web dashboard and mobile PWA are separate clients that consume the same versioned API.

## 2. Recommended Technology Stack

| Layer | Technology | Purpose |

| --- | --- | --- |

| Web dashboard | Next.js (App Router), React, TypeScript | Student/faculty scanning and reporting; admin incident queue and analytics. |

| UI styling | Tailwind CSS, Lucide React | Responsive interface, consistent components and iconography. |

| Browser extension | Chrome Extension Manifest V3, TypeScript/JavaScript, HTML/CSS | Explicit user-initiated current-tab URL checks and reporting. |

| Mobile experience | React-based Progressive Web App (PWA) | Mobile-first reporting, URL checks and QR scanning without a separate native app for the initial release. |

| Backend API | Python 3.12+, FastAPI, Pydantic | Versioned REST API, validation, authentication checks and orchestration. |

| Database | Supabase PostgreSQL | Profiles, scans, incidents, evidence, notes and audit records. |

| Authentication | Supabase Auth | User sign-in and identity; application roles enforced by backend policies. |

| Detection engine | Python URL parsing, deterministic rules and threat-intelligence adapters | Explainable indicators, risk scoring and recommendations. |

| QR scanning | html5-qrcode (or equivalent browser-compatible library) | Decode QR content locally; show the destination before analysis. |

| Threat intelligence | Google Safe Browsing API and/or OpenPhish feed, subject to access and terms | Known malicious URL signals; external matches must be distinguished from heuristic findings. |

| Optional ML | Scikit-learn | Only add a trained classifier if suitable data, evaluation and time are available. |

| WhatsApp integration | Official WhatsApp Business Cloud API | Optional inbound reporting workflow; no WhatsApp Web scraping or private-chat monitoring. |

| Deployment | Vercel for Next.js; Render or Railway for FastAPI | Separate frontend and API deployments; configure production secrets securely. |

| Testing | Pytest, Postman, Playwright | Backend tests, API verification and end-to-end UI checks. |

| Source control | Git and GitHub monorepo | Shared contracts, feature branches, pull requests and integration. |

## 3. System Architecture

High-level request flow:

1. User submits a URL, message, QR destination or incident through a client.

1. The client sends the submission to the FastAPI backend over HTTPS.

1. The backend validates and normalizes input, authenticates the user and applies rate limits.

1. The detection engine evaluates deterministic indicators and, where configured, threat-intelligence results.

1. The API returns a structured verdict, risk level, score, evidence and recommended next steps.

1. If the user files an incident, the incident workflow stores it and exposes it only to authorized campus roles.

The backend is the source of truth for detection and authorization. Do not duplicate risk-scoring logic inside the extension, dashboard or PWA.

## 4. Core API Contract

| Method | Endpoint | Purpose |

| --- | --- | --- |

| POST | /api/v1/scan/url | Analyze a submitted URL. |

| POST | /api/v1/scan/message | Analyze user-submitted message text. |

| POST | /api/v1/scan/qr | Analyze decoded QR content/destination. |

| POST | /api/v1/incidents | Create an incident report. |

| GET | /api/v1/incidents | List incidents permitted for the current user/role. |

| GET | /api/v1/incidents/{id} | Read an incident after authorization checks. |

| PATCH | /api/v1/incidents/{id} | Update allowed incident fields/status. |

| GET | /api/v1/dashboard/stats | Return role-scoped dashboard metrics. |

| GET | /api/v1/health | Health check for deployment monitoring. |

## 5. Standard Scan Response

Use one consistent response shape across URL, message and QR analysis. Example fields:

- scan_id — unique identifier for the scan.

- verdict — for example, MALICIOUS, SUSPICIOUS, LOW_RISK or UNKNOWN.

- risk_level and risk_score — severity representation, with the scoring scale documented.

- scoring_version — version of the rules/model used.

- indicators — structured evidence with a code, label, evidence type and explanation.

- recommendations — clear actions the user should take.

- checked_at — timestamp of the analysis.

A LOW_RISK result is not a guarantee that content is safe. Use UNKNOWN when evidence is insufficient or a required provider is unavailable. Separate confirmed threat-intelligence matches from heuristic signals in both the API and user interface.

## 6. Database and Core Entities

- profiles: authenticated user profile, display name, role and campus identifier.

- scans: submitter, input type, privacy-preserving fingerprint where appropriate, verdict, score, scoring version, indicators and timestamp.

- incidents: creator, related scan, category, severity, status, summary, description, assignee, campus and timestamps.

- incident_evidence: evidence references and metadata linked to an incident.

- incident_notes: authorized internal case notes.

- audit_logs: security-relevant actions, actor, target and timestamp.

Suggested incident lifecycle: SUBMITTED → TRIAGED → INVESTIGATING → RESOLVED or CLOSED. Severity and workflow status are separate fields.

## 7. Four-Developer Ownership

**Developer 1 — Backend & Detection: **FastAPI, Supabase schema, authentication/RBAC, URL/message/QR analysis, scoring, incident APIs, audit logs, tests and OpenAPI contract.

**Developer 2 — Browser Extension: **Manifest V3 extension, popup and result UI, explicit current-tab URL scan, report action, API integration and extension testing.

**Developer 3 — Web Dashboard: **Next.js dashboard, student/faculty scan and report flows, admin incident queue, case details, role-aware navigation and analytics.

**Developer 4 — Mobile & Integration: **Responsive PWA, mobile URL/message reporting, QR camera flow and optional official WhatsApp Business webhook.

## 8. GitHub Monorepo Structure

signalsafe-campus/ ├── README.md ├── .gitignore ├── .env.example ├── docs/ │   ├── PRD.md │   ├── SYSTEM_ARCHITECTURE.md │   ├── SYSTEM_DESIGN.md │   ├── API_CONTRACT.md │   ├── DATABASE_SCHEMA.md │   └── SECURITY_AND_PRIVACY.md ├── shared/api-contracts/ │   ├── openapi.yaml │   ├── schemas/ │   └── examples/ ├── backend/ │   ├── app/{main.py,core/,api/v1/,schemas/,auth/,detection/, │   │        threat_intel/,incidents/,persistence/,audit/} │   ├── tests/ │   ├── requirements.txt │   └── Dockerfile ├── browser-extension/ │   ├── manifest.json │   ├── src/{background/,popup/,content/,options/,services/} │   └── package.json ├── web-dashboard/ │   ├── src/{app/,components/,features/,lib/,services/} │   └── package.json ├── mobile-pwa/ │   ├── src/{app/,components/,features/qr-scanner/, │   │        features/url-scan/,features/reporting/,lib/,services/} │   └── package.json ├── integrations/whatsapp-cloud-api/ ├── supabase/{migrations/,seed.sql,config.toml} └── scripts/{dev/,test/,seed-demo-data.py}

## 9. Git Workflow and Integration Rules

- Keep main deployable; use develop as the shared integration branch.

- Create feature branches using feature/<developer>-<module>.

- Open pull requests into develop; review API, database and security changes before merging.

- Developer 1 publishes the initial OpenAPI contract and mock responses early so other developers can work in parallel.

- Each client consumes the shared API; do not create separate databases or independent detection implementations.

- Commit .env.example only. Never commit .env files, API keys, Supabase service-role keys or WhatsApp tokens.

- Integrate and test small increments throughout the build rather than merging everything at the end.

## 10. Security, Privacy and Safety Requirements

- Analyze only content explicitly submitted by the user; do not silently inspect private messages, browsing history or unrelated files.

- Request the minimum browser-extension permissions. Trigger scans only after an explicit user action.

- For QR codes, decode locally and display the destination before the user proceeds to analysis or navigation.

- Never fetch arbitrary user-submitted URLs from the primary API process. If page inspection is required, use an isolated, egress-restricted analysis service with SSRF protections.

- Validate and normalize inputs; apply authentication, authorization, rate limits and request-size limits.

- Enforce role and campus scope on the server for every incident read or update. Hiding UI controls is not authorization.

- Keep secrets server-side. Use HTTPS and avoid storing raw submitted content longer than the product requires.

- Minimize sensitive data in logs; provide a clear retention policy and audit privileged actions.

- Present evidence and uncertainty. Do not claim that a heuristic result proves a URL is malicious or safe.

- Use only the official WhatsApp Business Cloud API if that integration is implemented; obtain required user consent and follow platform policies.

## 11. Suggested Build Priorities

**P0 — Required: **Backend scan API and shared response schema; URL analysis; authentication and basic roles; dashboard scan/report flow; browser extension explicit URL scan; incident submission and admin queue; deployment and end-to-end demo.

**P1 — High value: **Message analysis; mobile PWA; QR decoding and destination preview; evidence-rich explanations; incident assignment and audit trail.

**P2 — Optional: **WhatsApp Business Cloud API; additional threat-intelligence providers; ML classifier after evaluation; advanced analytics and notifications.

## 12. Definition of Done

- All clients use the same documented API contract.

- A user can submit a URL and receive a structured, explainable result.

- A user can submit an incident and see its permitted status.

- An authorized campus operator can triage and update an incident.

- Server-side authorization prevents cross-user and cross-campus data access.

- Secrets are not exposed in source control or browser bundles.

- Core flows have automated or repeatable tests.

- The deployed demo clearly communicates limitations and does not overstate detection certainty.

## 13. Implementation Notes

This document defines a recommended implementation baseline, not a claim that every provider or service has already been configured. Confirm API access, pricing, rate limits, data licensing and platform terms before integrating third-party threat-intelligence or messaging services. Keep the first working demo small, secure and integrated; add optional channels only after the core scan-to-report workflow works.
