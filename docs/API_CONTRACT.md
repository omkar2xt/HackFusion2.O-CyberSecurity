# SignalSafe Campus — API Contract

**Version:** 1.0  
**Status:** Proposed hackathon baseline  
**Base path:** `/api/v1`  
**Transport:** HTTPS in deployed environments  
**Backend:** FastAPI

## 1. Purpose

This document defines the shared REST API used by the SignalSafe Campus web dashboard, Chrome extension, mobile PWA and optional WhatsApp Business integration.

The backend is authoritative for authentication, authorization, detection verdicts, risk scores, incident ownership and workflow transitions. Clients must not independently calculate or override these values.

## 2. API conventions

- Request and response bodies use JSON unless an endpoint explicitly documents another content type.
- Timestamps use UTC ISO 8601 format.
- Resource identifiers use UUIDs.
- All deployed traffic must use HTTPS.
- The backend validates all request data and returns consistent error responses.
- Clients must handle loading, validation, unauthorized, rate-limit, provider-unavailable and server-error states.
- Pagination and filtering must be applied server-side for list endpoints.
- Exact Pydantic models and OpenAPI definitions in the FastAPI application are the implementation source of truth.

### Authentication

Authenticated requests send a Supabase access token:

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

The backend validates the token and derives the user identity and role. A client must never submit a trusted `role`, `created_by`, `submitted_by`, `campus_id` or incident ownership value as an authority.

Scan endpoints may be configured as authenticated or public-rate-limited for the prototype. Incident creation and private incident access require authentication.

## 3. Common response conventions

### Scan response

All scan endpoints return the same core scan-result structure where applicable:

```json
{
  "scan_id": "uuid",
  "verdict": "SUSPICIOUS",
  "risk_level": "HIGH",
  "risk_score": 78,
  "scoring_version": "v1",
  "indicators": [
    {
      "code": "LOOKALIKE_HOST",
      "label": "Possible lookalike domain",
      "evidence_type": "heuristic",
      "detail": "The hostname resembles a known brand."
    }
  ],
  "recommendations": [
    "Do not enter credentials.",
    "Open the institution website using a saved bookmark."
  ],
  "checked_at": "2026-10-30T10:00:00Z"
}
```

This is an illustrative contract example, not a real scan result.

### Verdict semantics

| Verdict | Meaning |
|---|---|
| `MALICIOUS` | A trusted threat-intelligence source or verified test indicator matched. Include source and timestamp where available. |
| `SUSPICIOUS` | One or more heuristic indicators warrant caution; this is not proof of maliciousness. |
| `LOW_RISK` | No supported indicators were found. This is not a guarantee of safety. |
| `UNKNOWN` | Evidence is insufficient, input is unsupported, or a required external lookup is unavailable. |

### Suggested enums

- `risk_level`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `UNKNOWN`
- `evidence_type`: `heuristic`, `threat_intelligence`, `user_report`, `other`
- `incident_status`: `SUBMITTED`, `TRIAGED`, `INVESTIGATING`, `RESOLVED`, `CLOSED`
- `incident_severity`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

Severity and workflow status are independent.

### Error response

Use a consistent envelope:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The submitted URL is invalid.",
    "request_id": "request-id"
  }
}
```

Do not expose stack traces, secrets, provider credentials or internal diagnostics in client-facing errors.

## 4. Endpoints

### 4.1 `POST /api/v1/scan/url`

Analyze a user-submitted URL.

**Request**

```json
{
  "url": "https://example.com/login"
}
```

**Success:** `200 OK` with the canonical scan response.

**Validation and behavior**
- Accept only supported URL schemes, normally `http` and `https`.
- Reject malformed URLs, unsupported schemes and oversized input.
- Parse and normalize the hostname safely.
- Return explainable indicators and recommendations.
- Do not automatically open or visit the submitted URL.
- Do not fetch arbitrary submitted URLs from the primary API process.

### 4.2 `POST /api/v1/scan/message`

Analyze explicitly submitted message text and any URLs extracted from it.

**Request**

```json
{
  "message_text": "Your account will be suspended. Verify at https://example.com"
}
```

**Response**

Return a scan identifier, extracted URL findings, indicators, verdict, recommendations and limitations. The response must make clear whether the message itself was analyzed or only URLs extracted from it.

### 4.3 `POST /api/v1/scan/qr`

Analyze decoded QR content. QR decoding should normally happen on the client device.

**Request**

```json
{
  "decoded_content": "https://example.com/payment"
}
```

**Behavior**
- Treat decoded content as untrusted input.
- If it is a URL, route it through the same URL analysis service.
- Clearly label or reject unsupported non-URL payloads.
- Never automatically navigate to the decoded destination.

### 4.4 `POST /api/v1/incidents`

Create an incident report.

**Request**

```json
{
  "scan_id": "optional-scan-uuid",
  "category": "PHISHING",
  "summary": "Suspicious account verification message",
  "description": "I received this message and believe it may be fraudulent.",
  "evidence_refs": []
}
```

**Success:** `201 Created`

```json
{
  "incident_id": "uuid",
  "status": "SUBMITTED",
  "created_at": "2026-10-30T10:15:00Z"
}
```

**Rules**
- Require an authenticated reporter.
- Derive reporter identity and campus scope server-side.
- If `scan_id` is supplied, verify that the caller is permitted to reference it.
- Validate evidence references and ownership.
- Do not accept client-supplied ownership or privileged workflow fields.

### 4.5 `GET /api/v1/incidents`

List incidents visible to the caller.

Suggested query parameters:

| Parameter | Purpose |
|---|---|
| `status` | Filter by incident status |
| `severity` | Filter by severity |
| `mine` | Restrict to the caller's own reports where applicable |
| `page` | Page number |
| `page_size` | Number of records per page |

Students/faculty receive only their permitted reports. Campus administrators receive only incidents within their authorized campus scope.

### 4.6 `GET /api/v1/incidents/{id}`

Return incident details after an ownership or campus-admin authorization check. Include only evidence, notes and history the caller is permitted to view.

### 4.7 `PATCH /api/v1/incidents/{id}`

Update permitted incident fields. Intended for authorized campus administrators.

**Illustrative request**

```json
{
  "status": "INVESTIGATING",
  "severity": "HIGH",
  "assigned_to": "authorized-user-uuid",
  "note": "Initial review started."
}
```

The backend must validate allowed state transitions, assignment scope and permissions. Every privileged update must create an audit record.

### 4.8 `GET /api/v1/dashboard/stats`

Return aggregated metrics for an authorized administrator, scoped to their campus permissions.

Possible metrics include report volume, severity distribution, open/resolved counts and recent cases. Metrics must come from stored records, not hardcoded client values.

### 4.9 `GET /api/v1/health`

Return basic service health. Do not expose secrets, environment variables or internal infrastructure details.

## 5. Status codes

| Status | Use |
|---|---|
| `200` | Successful read or scan |
| `201` | Resource created |
| `400` | Invalid request semantics |
| `401` | Missing or invalid authentication |
| `403` | Authenticated but not authorized |
| `404` | Resource not found or not visible to caller |
| `422` | Request schema/validation failure |
| `429` | Rate limit exceeded |
| `500` | Unexpected server error |
| `503` | Required dependency unavailable, where appropriate |

## 6. Security requirements for API consumers

- Do not store privileged API keys or Supabase service-role keys in frontend bundles or extension code.
- Do not trust client-supplied risk scores, verdicts, roles, ownership or campus identifiers.
- Render submitted content as text; do not execute or render arbitrary HTML.
- Do not automatically open scanned URLs or QR destinations.
- Use the same API contract in every client.
- Treat `UNKNOWN` or provider-unavailable results as inconclusive, not safe.

## 7. Integration checklist

- [ ] Developer 1 publishes the OpenAPI specification and sample responses early.
- [ ] All clients use the same endpoint names and response semantics.
- [ ] Authentication and role checks are enforced server-side.
- [ ] List endpoints implement server-side authorization and pagination.
- [ ] Error responses are consistent and safe.
- [ ] Scan results include evidence and scoring-policy version.
- [ ] Incident updates are audited.
- [ ] API tests cover malformed input, authorization failures and provider outages.
