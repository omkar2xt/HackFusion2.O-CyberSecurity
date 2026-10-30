# SignalSafe Campus — Security and Privacy Requirements

**Version:** 1.0  
**Status:** Proposed security baseline for the hackathon prototype

## 1. Purpose and scope

This document defines the minimum security and privacy controls for SignalSafe Campus across the FastAPI backend, Supabase database, web dashboard, Chrome extension, mobile PWA and optional WhatsApp Business integration.

The platform processes user-submitted suspicious URLs, message text, QR-decoded content and incident reports. These inputs must be treated as untrusted and potentially sensitive.

## 2. Security principles

1. **Explicit submission:** Analyze only content the user deliberately submits or selects.
2. **Least privilege:** Each client, user role and service receives only the permissions it needs.
3. **Backend authority:** Authentication, authorization, verdicts, risk scores, ownership and workflow decisions are enforced server-side.
4. **Data minimization:** Collect and retain only information required to provide the service and investigate a submitted incident.
5. **Explainability:** Present evidence and uncertainty; do not overstate detection certainty.
6. **Safe failure:** Provider outages and incomplete evidence must not be interpreted as proof that content is safe.
7. **Auditability:** Record privileged actions without recording secrets or unnecessary personal content.

## 3. Authentication and authorization

- Use Supabase Auth for identity.
- Validate access tokens in the FastAPI backend on protected operations.
- Derive user ID, role and campus scope from trusted server-side records.
- Never trust client-supplied role, reporter ID, campus ID, incident owner, verdict or risk score.
- Enforce ownership or authorized campus scope on every incident read, update, note access and evidence retrieval.
- A student/faculty user must not access another user's private incident unless an explicit campus policy permits it.
- Campus administrators must be restricted to their authorized campus scope.
- Platform-administrator privileges must be explicitly granted and audited.
- Unpredictable UUIDs do not replace authorization checks.
- Apply rate limits to scan, report, login-sensitive and webhook endpoints.

## 4. Browser extension privacy and security

- Use Chrome Extension Manifest V3.
- Request the minimum permissions needed for the implemented features.
- Read the active tab URL only when the user explicitly invokes the scan action.
- Explain that the URL is sent to the SignalSafe backend for analysis.
- Do not collect browsing history, scan all tabs or monitor browser activity in the background.
- Do not automatically open submitted links.
- Do not embed Supabase service-role keys, threat-intelligence secrets or other privileged credentials in extension files.
- Show network failures as errors or unknown results, never as safe results.

## 5. URL and QR-code safety

- Treat submitted URLs and decoded QR content as untrusted input.
- Validate URL syntax, length and supported schemes.
- Parse and normalize hostnames safely.
- Do not automatically navigate to a decoded QR destination.
- Display the decoded destination to the user before analysis or navigation.
- Do not fetch arbitrary user-submitted URLs from the primary FastAPI process. This can expose the service to server-side request forgery (SSRF), internal network access and malware.
- If redirect expansion or page inspection is added later, run it in an isolated worker with:
  - strict egress restrictions;
  - DNS and resolved-IP validation;
  - blocking of loopback, private, link-local and cloud-metadata ranges;
  - redirect-count limits;
  - connection and read timeouts;
  - response-size limits;
  - no access to internal services or credentials.
- Treat non-URL QR payloads as untrusted and label or reject unsupported content.

## 6. Message analysis and user-submitted content

- Analyze only message text explicitly pasted or submitted by the user.
- Do not read private WhatsApp conversations or other private messages in the background.
- Clearly explain whether the service analyzed message text, extracted URLs or both.
- Limit request size and validate content types.
- Escape submitted content before rendering it in the dashboard or extension.
- Never render arbitrary submitted HTML or execute scripts from user content.
- Avoid retaining full message text unless it is necessary for a user-submitted incident and the retention is disclosed.
- Where practical, support redaction and store only necessary evidence.

## 7. Threat-intelligence and detection integrity

- Use only approved threat-intelligence sources and follow their access terms, rate limits and data-handling requirements.
- Keep API keys on the backend in a secret manager or protected deployment environment.
- Apply timeouts, caching and controlled retries to external providers.
- A provider outage must not crash the scanner.
- Distinguish trusted-source matches from heuristic indicators in API responses and UI.
- A heuristic warning is not proof of maliciousness.
- `LOW_RISK` means no supported indicators were found; it does not guarantee safety.
- Use `UNKNOWN` or a clearly marked degraded result when evidence is insufficient or a required lookup is unavailable.
- Version the scoring policy and explain contributing indicators.
- Do not present an uncalibrated risk score as a statistical probability.
- Test detection against labeled benign and malicious examples and review false positives.

## 8. Database, secrets and deployment

- Use HTTPS for all deployed client-to-server traffic.
- Keep `SUPABASE_SERVICE_ROLE_KEY`, database credentials, threat-intelligence keys and WhatsApp access tokens server-side only.
- Never commit `.env` files, tokens, passwords, private keys or production credentials.
- Commit only a sanitized `.env.example`.
- Use least-privilege database access and RLS policies where appropriate.
- Keep public client keys separate from privileged service credentials.
- Apply strict request schemas, input-size limits and safe error handling.
- Restrict database, storage and administrative access to authorized services and users.
- Configure CORS for known production origins rather than allowing arbitrary origins.
- Keep dependencies updated and avoid unnecessary packages.

## 9. Incident evidence and file uploads

- Evidence is private by default.
- Validate file size, extension and actual content; do not trust the filename or browser-provided MIME type alone.
- Store uploaded evidence in private object storage, not executable or publicly served application directories.
- Authorize every evidence download or preview.
- Use short-lived signed access where appropriate.
- Avoid exposing evidence URLs in public logs or analytics.
- Define allowed evidence types and maximum size before enabling uploads.
- Use synthetic examples for public hackathon demonstrations.

## 10. Logging and audit

Log security-relevant events such as:

- Authentication and authorization failures where appropriate.
- Incident creation.
- Incident status, severity and assignment changes.
- Administrative actions.
- Threat-intelligence provider failures.
- Rate-limit events and suspicious API usage.

Do not log:

- Passwords or authentication secrets.
- Bearer tokens, API keys or session cookies.
- Supabase service-role credentials.
- Full private message content unless a narrowly justified, disclosed requirement exists.
- Unnecessary personal data or private evidence.

Audit records should identify the actor, action, resource and timestamp, with minimal safe metadata. Treat audit logs as append-only at the application level.

## 11. WhatsApp integration

- Use the official WhatsApp Business Platform/Cloud API only.
- Implement a verified webhook and validate inbound requests according to the provider's current requirements.
- Store access tokens and verification secrets on the backend.
- Apply message size/type limits and rate limiting.
- Process only content the user deliberately sends to the official reporting channel.
- Do not scrape WhatsApp Web, automate private-account sessions or monitor private conversations.
- Keep this integration optional; it must not block the core scan-to-incident workflow.
- Confirm business setup, permissions, user notice, provider terms and data handling before enabling it.

## 12. Privacy, retention and user transparency

Before real campus deployment, document:

- What data is collected for scans and incidents.
- Whether raw URLs or message text are stored.
- Who can view reports, evidence and internal investigation notes.
- How long scans, reports, evidence and audit records are retained.
- How users can request correction or deletion where applicable.
- Which third-party providers receive submitted data.
- Whether data is processed outside the institution's region.
- How users are informed about the purpose and limits of analysis.

Collect only what is necessary. Avoid using real personal reports in hackathon demos; use synthetic or explicitly approved data.

## 13. Minimum security test checklist

- [ ] Malformed URLs and unsupported schemes are rejected.
- [ ] Oversized requests are rejected safely.
- [ ] A student cannot read or modify another student's incident.
- [ ] A non-admin cannot perform admin-only updates.
- [ ] An administrator cannot access incidents outside their campus scope.
- [ ] Client-supplied roles, ownership and risk scores are ignored or rejected.
- [ ] Evidence retrieval checks authorization.
- [ ] HTML/script content is displayed safely as text.
- [ ] Provider outage returns a partial/unknown state without crashing the service.
- [ ] Rate limits are applied to relevant endpoints.
- [ ] No secrets or bearer tokens appear in logs or client bundles.
- [ ] The extension performs no background browsing-history collection.
- [ ] QR destinations are not opened automatically.
- [ ] WhatsApp integration, if enabled, uses the official API and verified webhook.
- [ ] Demo data is synthetic or approved.

## 14. Prototype limitations

SignalSafe Campus is a hackathon prototype, not a guarantee of protection against all phishing, fraud, cyberbullying or impersonation. Detection quality depends on supported indicators, available threat-intelligence sources and the quality of test data.

A result must communicate its evidence and limitations. Production deployment requires a formal security review, privacy/retention policy, operational monitoring, incident-response ownership and validation against the institution's applicable policies and legal requirements.
