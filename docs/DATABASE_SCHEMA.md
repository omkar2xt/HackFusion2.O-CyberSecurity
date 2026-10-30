# SignalSafe Campus — Database Schema

**Version:** 1.0  
**Status:** Proposed logical schema  
**Database:** Supabase PostgreSQL

## 1. Purpose

This document describes the proposed relational data model for SignalSafe Campus. It supports user profiles, scan history, incident reporting, evidence metadata, investigation notes and audit records.

The schema is a logical baseline. Confirm exact SQL types, constraints, indexes, foreign-key actions and Row Level Security (RLS) policies in migration files before implementation.

## 2. Design principles

- Use one Supabase PostgreSQL project for the prototype.
- Use Supabase Auth as the identity provider.
- Store application roles in a protected profile/role record; users cannot self-assign privileged roles.
- Derive reporter identity and campus scope on the server.
- Minimize retained raw message and URL content.
- Enforce authorization on every protected read and write.
- Keep audit records free of passwords, bearer tokens and API secrets.

## 3. Entity overview

```text
auth.users
    |
    | 1:1
    v
profiles

profiles 1 --- many scans
profiles 1 --- many incidents (created_by)
scans    1 --- 0..many incidents (scan_id, nullable)
incidents 1 --- many incident_evidence
incidents 1 --- many incident_notes
profiles 1 --- many incident_notes (author_id)
profiles 1 --- many audit_logs (actor_id)
```

`campus_id` provides a scope boundary if the deployment supports multiple institutions or campuses.

## 4. Tables

### 4.1 `profiles`

Application profile associated with a Supabase Auth user.

| Column | Suggested type | Rules / purpose |
|---|---|---|
| `id` | `uuid` | Primary key; references `auth.users(id)` |
| `display_name` | `text` | User-facing display name |
| `role` | `text` or enum | Protected application role |
| `campus_id` | `uuid` or `text` | Campus/tenant scope |
| `created_at` | `timestamptz` | Creation timestamp |

Suggested roles: `STUDENT`, `FACULTY`, `CAMPUS_ADMIN`, `PLATFORM_ADMIN`.

Role assignment and changes are privileged operations. Do not allow users to update their own role through ordinary profile editing.

### 4.2 `scans`

Stores scan metadata and the explainable result.

| Column | Suggested type | Rules / purpose |
|---|---|---|
| `id` | `uuid` | Primary key; returned as `scan_id` |
| `submitted_by` | `uuid` | Nullable only if anonymous scans are explicitly supported |
| `input_type` | `text` or enum | For example `URL`, `MESSAGE`, `QR` |
| `input_fingerprint` | `text` | Optional privacy-preserving correlation/deduplication value |
| `verdict` | `text` or enum | `MALICIOUS`, `SUSPICIOUS`, `LOW_RISK`, `UNKNOWN` |
| `risk_score` | `integer` | Score under documented scoring policy |
| `scoring_version` | `text` | Version of rules/model used |
| `indicators` | `jsonb` | Structured evidence indicators |
| `created_at` | `timestamptz` | Scan timestamp |

Avoid storing complete raw message content unless it is necessary for a user-submitted incident and the retention is disclosed. If raw input is retained, define access controls and deletion/retention rules.

### 4.3 `incidents`

Stores user-submitted reports and their investigation lifecycle.

| Column | Suggested type | Rules / purpose |
|---|---|---|
| `id` | `uuid` | Primary key |
| `created_by` | `uuid` | Server-assigned reporter; references `profiles.id` |
| `scan_id` | `uuid` | Nullable reference to `scans.id` |
| `category` | `text` or enum | Incident category |
| `severity` | `text` or enum | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `status` | `text` or enum | Workflow status |
| `summary` | `text` | Short incident description |
| `description` | `text` | Optional context |
| `assigned_to` | `uuid` | Nullable authorized investigator |
| `campus_id` | `uuid` or `text` | Server-assigned campus scope |
| `created_at` | `timestamptz` | Creation timestamp |
| `updated_at` | `timestamptz` | Last update timestamp |

Suggested status lifecycle:

`SUBMITTED → TRIAGED → INVESTIGATING → RESOLVED` or `CLOSED`.

Severity and status are separate attributes. Validate allowed transitions in the backend.

### 4.4 `incident_evidence`

Stores references and metadata for evidence associated with an incident.

| Column | Suggested type | Rules / purpose |
|---|---|---|
| `id` | `uuid` | Primary key |
| `incident_id` | `uuid` | References `incidents.id` |
| `evidence_type` | `text` | Evidence category |
| `storage_path` or `reference` | `text` | Private object-storage path or controlled reference |
| `metadata` | `jsonb` | Limited metadata; avoid unnecessary sensitive content |
| `created_at` | `timestamptz` | Upload/reference timestamp |

Evidence must be private by default. Validate file size, extension and actual content. Authorize every evidence retrieval.

### 4.5 `incident_notes`

Stores investigation notes.

| Column | Suggested type | Rules / purpose |
|---|---|---|
| `id` | `uuid` | Primary key |
| `incident_id` | `uuid` | References `incidents.id` |
| `author_id` | `uuid` | References `profiles.id` |
| `note` | `text` | Note content |
| `created_at` | `timestamptz` | Creation timestamp |

Only authorized case participants and administrators within the permitted scope may read notes. Decide whether notes are append-only; do not silently expose internal notes to reporters.

### 4.6 `audit_logs`

Records privileged actions and security-relevant events.

| Column | Suggested type | Rules / purpose |
|---|---|---|
| `id` | `uuid` | Primary key |
| `actor_id` | `uuid` | Nullable for system-originated events |
| `action` | `text` | Action name |
| `resource_type` | `text` | For example `incident` |
| `resource_id` | `uuid` or `text` | Target identifier |
| `metadata` | `jsonb` | Minimal, non-secret event metadata |
| `created_at` | `timestamptz` | Event timestamp |

Treat audit logs as append-only at the application level. Never store passwords, bearer tokens, API keys or unnecessary submitted personal content.

## 5. Relationships and constraints

Recommended baseline constraints:

- `profiles.id` references `auth.users.id`.
- `scans.submitted_by` references `profiles.id` when authenticated.
- `incidents.created_by` references `profiles.id` and is assigned by the server.
- `incidents.scan_id` references `scans.id` and may be null.
- `incidents.assigned_to` references `profiles.id` and must be validated as an authorized assignee.
- `incident_evidence.incident_id` references `incidents.id`.
- `incident_notes.incident_id` references `incidents.id`.
- `incident_notes.author_id` references `profiles.id`.
- `audit_logs.actor_id` references `profiles.id` where applicable.

Choose `ON DELETE` behavior deliberately. For security and auditability, avoid cascading deletion that unintentionally erases investigation history.

## 6. Indexing recommendations

Consider indexes on:

- `scans(submitted_by, created_at)`
- `scans(verdict, created_at)`
- `incidents(created_by, created_at)`
- `incidents(campus_id, status, severity, created_at)`
- `incidents(assigned_to, status)`
- `incident_evidence(incident_id)`
- `incident_notes(incident_id, created_at)`
- `audit_logs(resource_type, resource_id, created_at)`
- `audit_logs(actor_id, created_at)`

Validate index choices against actual query patterns and dataset size.

## 7. Row Level Security and authorization

Enable RLS on tables exposed through Supabase APIs. Policies must reflect the intended role and campus boundaries.

Minimum authorization expectations:

- A student/faculty user can create a report and read only their own reports unless campus policy explicitly permits broader access.
- A campus administrator can read and manage incidents only within their authorized campus scope.
- A platform administrator has explicitly granted platform-level permissions.
- Users cannot self-promote by updating `profiles.role`.
- Every incident lookup, update, note access and evidence retrieval is checked server-side.
- UUIDs are identifiers, not authorization controls.

The backend remains authoritative even when RLS is enabled. Do not rely solely on hidden frontend controls.

## 8. Migration and seed-data plan

Suggested migration order:

1. Create/confirm profile role and campus fields.
2. Create `scans`.
3. Create `incidents`.
4. Create `incident_evidence`.
5. Create `incident_notes`.
6. Create `audit_logs`.
7. Add indexes, constraints, updated-at triggers and RLS policies.
8. Add synthetic seed data for the demo.

Use migrations committed to `supabase/migrations/`. Keep demo records clearly synthetic and never seed real personal reports into a public demo environment.

## 9. Open schema decisions

Confirm these with the team before final migrations:

- Whether unauthenticated URL scans are permitted.
- Exact role names and whether faculty can view only their own reports.
- Whether campus administrators can see all incidents in one campus or only assigned cases.
- Evidence file types, maximum size, storage provider and retention.
- Whether raw submitted URLs/messages are retained, redacted or represented only by fingerprints and indicators.
- Whether incident notes are internal-only or whether a separate reporter-visible update model is needed.
- Exact category enums and status-transition rules.
