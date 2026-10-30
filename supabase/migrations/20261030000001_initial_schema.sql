-- ==============================================================================
-- SignalSafe Campus — Initial Database Schema Draft
-- Migration: 20261030000001_initial_schema.sql
-- Description: Core schema for profiles, scans, incidents, evidence, notes, and audit logs.
-- 
-- IMPORTANT:
-- This is a migration draft prepared for Milestone 1 review.
-- Do NOT execute directly on live database until approved.
-- ==============================================================================

-- 1. Enable Required Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. Create Enums / Domains
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('STUDENT', 'FACULTY', 'CAMPUS_ADMIN', 'PLATFORM_ADMIN');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE scan_input_type AS ENUM ('URL', 'MESSAGE', 'QR');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE scan_verdict AS ENUM ('MALICIOUS', 'SUSPICIOUS', 'LOW_RISK', 'UNKNOWN');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE scan_risk_level AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE incident_category AS ENUM ('PHISHING', 'MALWARE', 'CREDENTIAL_HARVESTING', 'IMPERSONATION', 'SCAM', 'OTHER');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE incident_severity AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE incident_status AS ENUM ('SUBMITTED', 'TRIAGED', 'INVESTIGATING', 'RESOLVED', 'CLOSED');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE evidence_type AS ENUM ('heuristic', 'threat_intelligence', 'user_report', 'screenshot', 'raw_header', 'other');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ==============================================================================
-- 3. Profiles Table
-- Linked 1:1 with auth.users. Stores application roles and campus tenancy.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    display_name TEXT,
    role user_role NOT NULL DEFAULT 'STUDENT',
    campus_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==============================================================================
-- 4. Scans Table
-- Stores scan submissions, metadata, explainable indicators, and recommendations.
-- Resolves discrepancy by including risk_level and recommendations per API contract.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submitted_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    input_type scan_input_type NOT NULL,
    input_fingerprint TEXT,
    verdict scan_verdict NOT NULL,
    risk_level scan_risk_level NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    scoring_version TEXT NOT NULL DEFAULT 'v1',
    indicators JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==============================================================================
-- 5. Incidents Table
-- Stores user reports and administrative triage lifecycle.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_by UUID NOT NULL REFERENCES public.profiles(id) ON DELETE RESTRICT,
    scan_id UUID REFERENCES public.scans(id) ON DELETE SET NULL,
    category incident_category NOT NULL,
    severity incident_severity NOT NULL DEFAULT 'MEDIUM',
    status incident_status NOT NULL DEFAULT 'SUBMITTED',
    summary TEXT NOT NULL,
    description TEXT,
    assigned_to UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    campus_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==============================================================================
-- 6. Incident Evidence Table
-- References and metadata for evidence attached to an incident.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.incident_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
    evidence_type evidence_type NOT NULL,
    storage_path TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==============================================================================
-- 7. Incident Notes Table
-- Case management notes entered by investigators or system logs.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.incident_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
    author_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE RESTRICT,
    note TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==============================================================================
-- 8. Audit Logs Table
-- Append-only record of privileged state changes and sensitive operations.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==============================================================================
-- 9. Indexes for Performance & Scoped Lookups
-- ==============================================================================
CREATE INDEX IF NOT EXISTS idx_profiles_campus_role ON public.profiles(campus_id, role);

CREATE INDEX IF NOT EXISTS idx_scans_submitted_by_created_at ON public.scans(submitted_by, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict_created_at ON public.scans(verdict, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_fingerprint ON public.scans(input_fingerprint);

CREATE INDEX IF NOT EXISTS idx_incidents_created_by_created_at ON public.incidents(created_by, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_campus_status_severity ON public.incidents(campus_id, status, severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_to_status ON public.incidents(assigned_to, status);
CREATE INDEX IF NOT EXISTS idx_incidents_scan_id ON public.incidents(scan_id);

CREATE INDEX IF NOT EXISTS idx_incident_evidence_incident_id ON public.incident_evidence(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_notes_incident_id_created_at ON public.incident_notes(incident_id, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON public.audit_logs(resource_type, resource_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON public.audit_logs(actor_id, created_at DESC);

-- ==============================================================================
-- 10. Helper Functions for Role & Tenancy Checks (SECURITY DEFINER)
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.current_user_role()
RETURNS user_role
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT role FROM public.profiles WHERE id = (SELECT auth.uid());
$$;

CREATE OR REPLACE FUNCTION public.current_user_campus_id()
RETURNS UUID
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT campus_id FROM public.profiles WHERE id = (SELECT auth.uid());
$$;

-- Function: Prevent role escalation on profile update
CREATE OR REPLACE FUNCTION public.check_profile_update_privileges()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    caller_role user_role;
BEGIN
    -- Only enforce restrictions on client application roles (authenticated / anon)
    IF auth.role() IN ('authenticated', 'anon') THEN
        -- If role or campus_id is changed, caller MUST be PLATFORM_ADMIN
        IF (NEW.role IS DISTINCT FROM OLD.role) OR (NEW.campus_id IS DISTINCT FROM OLD.campus_id) THEN
            caller_role := (SELECT public.current_user_role());
            IF caller_role IS NULL OR caller_role != 'PLATFORM_ADMIN' THEN
                RAISE EXCEPTION 'Unauthorized: Users cannot modify their own role or campus tenancy.';
            END IF;
        END IF;
    END IF;

    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_protect_profile_update ON public.profiles;
CREATE TRIGGER trg_protect_profile_update
BEFORE UPDATE ON public.profiles
FOR EACH ROW
EXECUTE FUNCTION public.check_profile_update_privileges();

-- Trigger: Automatically create profile on auth.users insert
-- CRITICAL REQUIREMENT: Default to STUDENT, ignore client-supplied metadata role.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    INSERT INTO public.profiles (
        id,
        display_name,
        role,
        campus_id,
        created_at,
        updated_at
    )
    VALUES (
        NEW.id,
        COALESCE(
            NEW.raw_user_meta_data->>'full_name',
            NEW.raw_user_meta_data->>'display_name',
            NEW.raw_user_meta_data->>'name',
            SPLIT_PART(NEW.email, '@', 1)
        ),
        'STUDENT'::user_role, -- Forcibly default to STUDENT regardless of user metadata
        NULL, -- Tenancy cannot be assigned via client signup metadata; must be server-provisioned
        now(),
        now()
    )
    ON CONFLICT (id) DO NOTHING;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION public.handle_new_user();

-- Updated_at trigger for incidents
CREATE OR REPLACE FUNCTION public.update_incident_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_incidents_updated_at ON public.incidents;
CREATE TRIGGER trg_incidents_updated_at
BEFORE UPDATE ON public.incidents
FOR EACH ROW
EXECUTE FUNCTION public.update_incident_timestamp();

-- Function & Trigger: Prevent unauthorized modification of created_by or campus_id on incidents
CREATE OR REPLACE FUNCTION public.check_incident_update_privileges()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    -- Prevent changing created_by or campus_id on UPDATE for any application user
    IF auth.role() IN ('authenticated', 'anon') THEN
        IF (NEW.created_by IS DISTINCT FROM OLD.created_by) THEN
            RAISE EXCEPTION 'Unauthorized: Incident reporter is immutable.';
        END IF;

        IF (NEW.campus_id IS DISTINCT FROM OLD.campus_id) THEN
            RAISE EXCEPTION 'Unauthorized: Incident campus tenancy is immutable through general incident updates.';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_protect_incident_update ON public.incidents;
CREATE TRIGGER trg_protect_incident_update
BEFORE UPDATE ON public.incidents
FOR EACH ROW
EXECUTE FUNCTION public.check_incident_update_privileges();

-- Trigger: Derive and enforce campus_id from authenticated reporter's profile
CREATE OR REPLACE FUNCTION public.handle_incident_campus_assignment()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    -- Server-side derivation: override any client-supplied campus_id with the reporter's trusted profile campus_id
    NEW.campus_id := (SELECT campus_id FROM public.profiles WHERE id = NEW.created_by);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_incidents_set_campus_id ON public.incidents;
CREATE TRIGGER trg_incidents_set_campus_id
BEFORE INSERT ON public.incidents
FOR EACH ROW
EXECUTE FUNCTION public.handle_incident_campus_assignment();

-- Function & Trigger: Guarantee append-only immutability for audit_logs
CREATE OR REPLACE FUNCTION public.prevent_audit_log_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RAISE EXCEPTION 'Security violation: audit_logs records are immutable and cannot be updated or deleted.';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON public.audit_logs;
CREATE TRIGGER trg_audit_logs_immutable
BEFORE UPDATE OR DELETE ON public.audit_logs
FOR EACH ROW
EXECUTE FUNCTION public.prevent_audit_log_modification();

-- ==============================================================================
-- 11. Row Level Security (RLS) Policies
-- ==============================================================================

-- Enable RLS on all tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- 11.1 Profiles Policies
DROP POLICY IF EXISTS "Profiles viewable by owner, campus admins, or platform admins" ON public.profiles;
CREATE POLICY "Profiles viewable by owner, campus admins, or platform admins"
ON public.profiles FOR SELECT
USING (
    (SELECT auth.uid()) = id
    OR (
        (SELECT public.current_user_role()) IN ('CAMPUS_ADMIN') 
        AND campus_id = (SELECT public.current_user_campus_id())
    )
    OR (SELECT public.current_user_role()) = 'PLATFORM_ADMIN'
);

DROP POLICY IF EXISTS "Users update own display name; platform admin manage profiles" ON public.profiles;
CREATE POLICY "Users update own display name; platform admin manage profiles"
ON public.profiles FOR UPDATE
USING (
    (SELECT auth.uid()) = id
    OR (SELECT public.current_user_role()) = 'PLATFORM_ADMIN'
)
WITH CHECK (
    (SELECT auth.uid()) = id
    OR (SELECT public.current_user_role()) = 'PLATFORM_ADMIN'
);

-- 11.2 Scans Policies
DROP POLICY IF EXISTS "Permit scan insertion with authenticated owner or anonymous NUL" ON public.scans;
DROP POLICY IF EXISTS "Permit scan insert with authenticated owner or anonymous NULL" ON public.scans;
DROP POLICY IF EXISTS "Authenticated users can insert scans" ON public.scans;
CREATE POLICY "Permit scan insert with authenticated owner or anonymous NULL"
ON public.scans FOR INSERT
WITH CHECK (
    submitted_by IS NULL 
    OR submitted_by = (SELECT auth.uid())
);

DROP POLICY IF EXISTS "Users view own scans; campus admins campus scans; admin all" ON public.scans;
CREATE POLICY "Users view own scans; campus admins campus scans; admin all"
ON public.scans FOR SELECT
USING (
    (submitted_by IS NOT NULL AND submitted_by = (SELECT auth.uid()))
    OR (
        (SELECT public.current_user_role()) = 'CAMPUS_ADMIN'
        AND submitted_by IN (
            SELECT p.id FROM public.profiles p WHERE p.campus_id = (SELECT public.current_user_campus_id())
        )
    )
    OR (SELECT public.current_user_role()) = 'PLATFORM_ADMIN'
);

-- 11.3 Incidents Policies
DROP POLICY IF EXISTS "Authenticated users can create incidents for themselves" ON public.incidents;
CREATE POLICY "Authenticated users can create incidents for themselves"
ON public.incidents FOR INSERT
WITH CHECK (
    created_by = (SELECT auth.uid())
    AND (
        campus_id IS NULL 
        OR campus_id = (SELECT public.current_user_campus_id())
    )
);

DROP POLICY IF EXISTS "Reporters, assigned investigators, and admins view incidents" ON public.incidents;
CREATE POLICY "Reporters, assigned investigators, and admins view incidents"
ON public.incidents FOR SELECT
USING (
    created_by = (SELECT auth.uid())
    OR assigned_to = (SELECT auth.uid())
    OR (
        (SELECT public.current_user_role()) = 'CAMPUS_ADMIN'
        AND campus_id = (SELECT public.current_user_campus_id())
    )
    OR (SELECT public.current_user_role()) = 'PLATFORM_ADMIN'
);

DROP POLICY IF EXISTS "Admins or assigned investigators update incidents in scope" ON public.incidents;
CREATE POLICY "Admins or assigned investigators update incidents in scope"
ON public.incidents FOR UPDATE
USING (
    (
        (SELECT public.current_user_role()) = 'CAMPUS_ADMIN'
        AND campus_id = (SELECT public.current_user_campus_id())
    )
    OR (SELECT public.current_user_role()) = 'PLATFORM_ADMIN'
    OR assigned_to = (SELECT auth.uid())
)
WITH CHECK (
    (
        (SELECT public.current_user_role()) = 'CAMPUS_ADMIN'
        AND campus_id = (SELECT public.current_user_campus_id())
    )
    OR (SELECT public.current_user_role()) = 'PLATFORM_ADMIN'
    OR assigned_to = (SELECT auth.uid())
);

-- 11.4 Incident Evidence Policies
DROP POLICY IF EXISTS "Reporters can add evidence to their own incidents" ON public.incident_evidence;
CREATE POLICY "Reporters can add evidence to their own incidents"
ON public.incident_evidence FOR INSERT
WITH CHECK (
    EXISTS (
        SELECT 1 FROM public.incidents i
        WHERE i.id = incident_id
        AND i.created_by = (SELECT auth.uid())
    )
);

DROP POLICY IF EXISTS "Reporters, assigned investigators, and admins view evidence" ON public.incident_evidence;
CREATE POLICY "Reporters, assigned investigators, and admins view evidence"
ON public.incident_evidence FOR SELECT
USING (
    EXISTS (
        SELECT 1 FROM public.incidents i
        WHERE i.id = incident_id
        AND (
            i.created_by = (SELECT auth.uid())
            OR i.assigned_to = (SELECT auth.uid())
            OR (
                (SELECT public.current_user_role()) = 'CAMPUS_ADMIN'
                AND i.campus_id = (SELECT public.current_user_campus_id())
            )
            OR (SELECT public.current_user_role()) = 'PLATFORM_ADMIN'
        )
    )
);

-- 11.5 Incident Notes Policies
DROP POLICY IF EXISTS "Authorized investigators and admins can create notes" ON public.incident_notes;
CREATE POLICY "Authorized investigators and admins can create notes"
ON public.incident_notes FOR INSERT
WITH CHECK (
    author_id = (SELECT auth.uid())
    AND (
        (SELECT public.current_user_role()) = 'PLATFORM_ADMIN'
        OR (
            (SELECT public.current_user_role()) = 'CAMPUS_ADMIN'
            AND EXISTS (
                SELECT 1 FROM public.incidents i
                WHERE i.id = incident_id
                AND i.campus_id = (SELECT public.current_user_campus_id())
            )
        )
        OR EXISTS (
            SELECT 1 FROM public.incidents i
            WHERE i.id = incident_id
            AND i.assigned_to = (SELECT auth.uid())
        )
    )
);

DROP POLICY IF EXISTS "Authorized investigators and admins can view notes" ON public.incident_notes;
CREATE POLICY "Authorized investigators and admins can view notes"
ON public.incident_notes FOR SELECT
USING (
    (SELECT public.current_user_role()) = 'PLATFORM_ADMIN'
    OR (
        (SELECT public.current_user_role()) = 'CAMPUS_ADMIN'
        AND EXISTS (
            SELECT 1 FROM public.incidents i
            WHERE i.id = incident_id
            AND i.campus_id = (SELECT public.current_user_campus_id())
        )
    )
    OR EXISTS (
        SELECT 1 FROM public.incidents i
        WHERE i.id = incident_id
        AND i.assigned_to = (SELECT auth.uid())
    )
);

-- 11.6 Audit Logs Policies (Append-only / Read-only for authorized staff)
DROP POLICY IF EXISTS "Admins can view audit logs within their scope" ON public.audit_logs;
CREATE POLICY "Admins can view audit logs within their scope"
ON public.audit_logs FOR SELECT
USING (
    (SELECT public.current_user_role()) = 'PLATFORM_ADMIN'
    OR (
        (SELECT public.current_user_role()) = 'CAMPUS_ADMIN'
        AND actor_id IN (
            SELECT p.id FROM public.profiles p WHERE p.campus_id = (SELECT public.current_user_campus_id())
        )
    )
);

-- Deny direct audit log insertion from client connections (server-side service role only)
DROP POLICY IF EXISTS "Deny client direct insert to audit logs" ON public.audit_logs;
CREATE POLICY "Deny client direct insert to audit logs"
ON public.audit_logs FOR INSERT
WITH CHECK (false);

-- ==============================================================================
-- 12. Least-Privilege Role Grants & Revokes
-- ==============================================================================
-- Ensure schema usage
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;

-- Revoke all table access from anon on sensitive private tables
REVOKE ALL ON TABLE public.profiles FROM anon;
REVOKE ALL ON TABLE public.incidents FROM anon;
REVOKE ALL ON TABLE public.incident_evidence FROM anon;
REVOKE ALL ON TABLE public.incident_notes FROM anon;
REVOKE ALL ON TABLE public.audit_logs FROM anon;

-- Permit anonymous users to ONLY insert scans (preserving anonymous scan submission)
REVOKE ALL ON TABLE public.scans FROM anon;
GRANT INSERT ON TABLE public.scans TO anon;

-- Authenticated users: application access governed by Row Level Security
GRANT SELECT, UPDATE ON TABLE public.profiles TO authenticated;
GRANT SELECT, INSERT ON TABLE public.scans TO authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.incidents TO authenticated;
GRANT SELECT, INSERT ON TABLE public.incident_evidence TO authenticated;
GRANT SELECT, INSERT ON TABLE public.incident_notes TO authenticated;
GRANT SELECT ON TABLE public.audit_logs TO authenticated;

-- Revoke insert, update, delete, truncate on audit_logs from authenticated (defense-in-depth)
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE public.audit_logs FROM authenticated;

-- Service role and internal administrators retain full maintenance privileges
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;
GRANT ALL ON ALL ROUTINES IN SCHEMA public TO service_role;

