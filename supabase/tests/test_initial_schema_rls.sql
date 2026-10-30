-- ==============================================================================
-- SignalSafe Campus — Pre-Staging Security Hardening & RLS Verification Suite
-- File: supabase/tests/test_initial_schema_rls.sql
-- 
-- Verifies the 10 pre-staging security hardening controls:
-- 1. Anonymous user can submit a permitted scan.
-- 2. Anonymous user cannot read private scan records.
-- 3. Anonymous user cannot read profiles or incidents.
-- 4. Authenticated users cannot directly insert audit logs.
-- 5. Ordinary application roles cannot alter incident created_by.
-- 6. Ordinary application roles cannot alter incident campus_id.
-- 7. Campus isolation remains intact.
-- 8. Assigned investigator access remains intact.
-- 9. Existing role escalation protections remain intact.
-- 10. Audit log immutability remains intact.
--
-- IMPORTANT:
-- Run this test script ONLY on an isolated, ephemeral local test database.
-- NEVER execute against the live Supabase project.
-- ==============================================================================

BEGIN;

-- Setup temporary table to aggregate test assertion results
CREATE TEMP TABLE IF NOT EXISTS temp_security_test_results (
    test_id INT PRIMARY KEY,
    test_name TEXT NOT NULL,
    status TEXT NOT NULL,
    details TEXT
);
TRUNCATE TABLE temp_security_test_results;
GRANT ALL ON temp_security_test_results TO PUBLIC;

DO $$
DECLARE
    -- Test Identifiers (UUIDs)
    v_campus_a UUID := '11111111-1111-1111-1111-111111111111';
    v_campus_b UUID := '22222222-2222-2222-2222-222222222222';
    v_student_a UUID := '00000000-0000-0000-0000-000000000001';
    v_student_b UUID := '00000000-0000-0000-0000-000000000002';
    v_admin_a UUID := '00000000-0000-0000-0000-000000000003';
    v_admin_b UUID := '00000000-0000-0000-0000-000000000004';
    v_investigator UUID := '00000000-0000-0000-0000-000000000005';
    v_platform_admin UUID := '00000000-0000-0000-0000-000000000006';
    v_attacker UUID := '99999999-9999-9999-9999-999999999999';

    v_incident_b UUID := '11111111-bbbb-bbbb-bbbb-111111111111';
    v_incident_a UUID := '11111111-aaaa-aaaa-aaaa-111111111111';
    v_audit_log_id UUID := 'aaaaaaaa-0000-0000-0000-aaaaaaaaaaaa';
    v_anon_scan_id UUID := '33333333-3333-3333-3333-333333333333';
    v_student_scan_id UUID := '44444444-4444-4444-4444-444444444444';

    cnt INT;
    err_occurred BOOLEAN;
    err_msg TEXT;
    v_update_blocked BOOLEAN := false;
    v_delete_blocked BOOLEAN := false;
BEGIN
    RAISE NOTICE '============================================================';
    RAISE NOTICE 'Starting Pre-Staging Security Hardening SQL Test Suite';
    RAISE NOTICE '============================================================';

    -- Reset any previous session state so setup operations run with unrestricted postgres / system privileges
    PERFORM set_config('role', 'postgres', true);
    PERFORM set_config('request.jwt.claim.role', '', true);
    PERFORM set_config('request.jwt.claim.sub', '', true);

    -- 0. Clean up previous test artifacts
    DELETE FROM public.incident_notes WHERE incident_id IN (v_incident_a, v_incident_b, '22222222-aaaa-aaaa-aaaa-222222222222');
    DELETE FROM public.incident_evidence WHERE incident_id IN (v_incident_a, v_incident_b, '22222222-aaaa-aaaa-aaaa-222222222222');
    DELETE FROM public.incidents WHERE id IN (v_incident_a, v_incident_b, '22222222-aaaa-aaaa-aaaa-222222222222');
    DELETE FROM public.scans WHERE id IN (v_anon_scan_id, v_student_scan_id);
    ALTER TABLE public.audit_logs DISABLE TRIGGER trg_audit_logs_immutable;
    DELETE FROM public.audit_logs WHERE id IN (v_audit_log_id, 'aaaaaaaa-0000-0000-0000-bbbbbbbbbbbb');
    ALTER TABLE public.audit_logs ENABLE TRIGGER trg_audit_logs_immutable;
    DELETE FROM auth.users WHERE id IN (v_student_a, v_student_b, v_admin_a, v_admin_b, v_investigator, v_platform_admin, v_attacker);

    -- 1. Setup Mock auth.users and profiles
    INSERT INTO auth.users (id, email, raw_user_meta_data) VALUES
    (v_student_a, 'student_a@campus-a.edu', '{"display_name": "Student A"}'::jsonb),
    (v_student_b, 'student_b@campus-b.edu', '{"display_name": "Student B"}'::jsonb),
    (v_admin_a, 'admin_a@campus-a.edu', '{"display_name": "Admin Campus A"}'::jsonb),
    (v_admin_b, 'admin_b@campus-b.edu', '{"display_name": "Admin Campus B"}'::jsonb),
    (v_investigator, 'investigator@campus-a.edu', '{"display_name": "Investigator"}'::jsonb),
    (v_platform_admin, 'platform_admin@signalsafe.org', '{"display_name": "Platform Admin"}'::jsonb);

    -- Provision authentic profiles (simulating backend service_role / administrative setup)
    UPDATE public.profiles SET campus_id = v_campus_a, role = 'STUDENT' WHERE id = v_student_a;
    UPDATE public.profiles SET campus_id = v_campus_b, role = 'STUDENT' WHERE id = v_student_b;
    UPDATE public.profiles SET campus_id = v_campus_a, role = 'CAMPUS_ADMIN' WHERE id = v_admin_a;
    UPDATE public.profiles SET campus_id = v_campus_b, role = 'CAMPUS_ADMIN' WHERE id = v_admin_b;
    UPDATE public.profiles SET campus_id = v_campus_a, role = 'FACULTY' WHERE id = v_investigator;
    UPDATE public.profiles SET campus_id = NULL, role = 'PLATFORM_ADMIN' WHERE id = v_platform_admin;

    -- Seed authentic incidents
    INSERT INTO public.incidents (id, created_by, category, severity, status, summary, campus_id, assigned_to)
    VALUES (v_incident_b, v_student_b, 'PHISHING', 'HIGH', 'INVESTIGATING', 'Student B incident on Campus B', v_campus_b, v_investigator);

    INSERT INTO public.incidents (id, created_by, category, severity, status, summary, campus_id)
    VALUES (v_incident_a, v_student_a, 'MALWARE', 'MEDIUM', 'SUBMITTED', 'Student A incident on Campus A', v_campus_a);

    INSERT INTO public.incident_evidence (id, incident_id, evidence_type, storage_path)
    VALUES ('eeeeeeee-1111-1111-1111-111111111111', v_incident_b, 'screenshot', 'evidence/screenshot1.png');

    INSERT INTO public.incident_notes (id, incident_id, author_id, note)
    VALUES ('bbbbbbbb-1111-1111-1111-111111111111', v_incident_b, v_admin_b, 'Initial note by Admin B');

    -- Seed authenticated scan record
    INSERT INTO public.scans (id, submitted_by, input_type, verdict, risk_level, risk_score)
    VALUES (v_student_scan_id, v_student_a, 'URL', 'LOW_RISK', 'LOW', 5);

    -- Seed audit log
    INSERT INTO public.audit_logs (id, actor_id, action, resource_type, resource_id, metadata)
    VALUES (v_audit_log_id, v_student_a, 'AUTH_LOGIN', 'user', '1', '{}'::jsonb);

    ----------------------------------------------------------------------------
    -- TEST 1: Anonymous user can submit a permitted scan.
    ----------------------------------------------------------------------------
    PERFORM set_config('role', 'anon', true);
    PERFORM set_config('request.jwt.claim.sub', '', true);
    PERFORM set_config('request.jwt.claim.role', 'anon', true);

    err_occurred := false;
    BEGIN
        INSERT INTO public.scans (id, submitted_by, input_type, verdict, risk_level, risk_score)
        VALUES (v_anon_scan_id, NULL, 'URL', 'MALICIOUS', 'HIGH', 85);
    EXCEPTION WHEN OTHERS THEN
        err_occurred := true;
        err_msg := SQLERRM;
    END;

    IF NOT err_occurred THEN
        INSERT INTO temp_security_test_results VALUES (1, 'Anonymous user can submit permitted scan', 'PASS', 'Anonymous user successfully inserted scan with submitted_by = NULL');
    ELSE
        INSERT INTO temp_security_test_results VALUES (1, 'Anonymous user can submit permitted scan', 'FAIL', format('Anonymous scan insertion blocked: %s', err_msg));
    END IF;

    ----------------------------------------------------------------------------
    -- TEST 2: Anonymous user cannot read private scan records.
    ----------------------------------------------------------------------------
    err_occurred := false;
    BEGIN
        SELECT count(*) INTO cnt FROM public.scans;
    EXCEPTION WHEN OTHERS THEN
        err_occurred := true;
        err_msg := SQLERRM;
    END;

    IF err_occurred THEN
        INSERT INTO temp_security_test_results VALUES (2, 'Anonymous user cannot read private scan records', 'PASS', format('Denied at table privilege layer: %s', err_msg));
    ELSIF cnt = 0 THEN
        INSERT INTO temp_security_test_results VALUES (2, 'Anonymous user cannot read private scan records', 'PASS', 'Zero scan records visible to anonymous role (RLS isolation)');
    ELSE
        INSERT INTO temp_security_test_results VALUES (2, 'Anonymous user cannot read private scan records', 'FAIL', format('Leak! Anonymous user read %s scans', cnt));
    END IF;

    ----------------------------------------------------------------------------
    -- TEST 3: Anonymous user cannot read profiles or incidents.
    ----------------------------------------------------------------------------
    DECLARE
        v_profiles_blocked BOOLEAN := false;
        v_incidents_blocked BOOLEAN := false;
    BEGIN
        BEGIN
            SELECT count(*) INTO cnt FROM public.profiles;
            IF cnt = 0 THEN v_profiles_blocked := true; END IF;
        EXCEPTION WHEN OTHERS THEN
            v_profiles_blocked := true;
        END;

        BEGIN
            SELECT count(*) INTO cnt FROM public.incidents;
            IF cnt = 0 THEN v_incidents_blocked := true; END IF;
        EXCEPTION WHEN OTHERS THEN
            v_incidents_blocked := true;
        END;

        IF v_profiles_blocked AND v_incidents_blocked THEN
            INSERT INTO temp_security_test_results VALUES (3, 'Anonymous user cannot read profiles or incidents', 'PASS', 'Access completely denied by least-privilege grant revocation');
        ELSE
            INSERT INTO temp_security_test_results VALUES (3, 'Anonymous user cannot read profiles or incidents', 'FAIL', format('ProfilesBlocked=%s, IncidentsBlocked=%s', v_profiles_blocked, v_incidents_blocked));
        END IF;
    END;

    ----------------------------------------------------------------------------
    -- TEST 4: Authenticated users cannot directly insert audit logs.
    ----------------------------------------------------------------------------
    PERFORM set_config('role', 'authenticated', true);
    PERFORM set_config('request.jwt.claim.sub', v_student_a::text, true);
    PERFORM set_config('request.jwt.claim.role', 'authenticated', true);

    err_occurred := false;
    BEGIN
        INSERT INTO public.audit_logs (id, actor_id, action, resource_type, resource_id, metadata)
        VALUES ('aaaaaaaa-0000-0000-0000-bbbbbbbbbbbb', v_student_a, 'FORGED_LOG', 'user', '1', '{}'::jsonb);
    EXCEPTION WHEN OTHERS THEN
        err_occurred := true;
        err_msg := SQLERRM;
    END;

    IF err_occurred THEN
        INSERT INTO temp_security_test_results VALUES (4, 'Authenticated users cannot directly insert audit logs', 'PASS', format('Direct insert denied: %s', err_msg));
    ELSE
        INSERT INTO temp_security_test_results VALUES (4, 'Authenticated users cannot directly insert audit logs', 'FAIL', 'Direct client insert succeeded on audit_logs!');
    END IF;

    ----------------------------------------------------------------------------
    -- TEST 5: Ordinary application roles cannot alter incident created_by.
    ----------------------------------------------------------------------------
    -- Switch to Admin A (has update privileges on Incident A in Campus A)
    PERFORM set_config('role', 'authenticated', true);
    PERFORM set_config('request.jwt.claim.role', 'authenticated', true);
    PERFORM set_config('request.jwt.claim.sub', v_admin_a::text, true);

    err_occurred := false;
    BEGIN
        UPDATE public.incidents SET created_by = v_student_b WHERE id = v_incident_a;
    EXCEPTION WHEN OTHERS THEN
        err_occurred := true;
        err_msg := SQLERRM;
    END;

    IF err_occurred THEN
        INSERT INTO temp_security_test_results VALUES (5, 'Application roles cannot alter incident created_by', 'PASS', format('Blocked by immutability trigger: %s', err_msg));
    ELSE
        INSERT INTO temp_security_test_results VALUES (5, 'Application roles cannot alter incident created_by', 'FAIL', 'Reporter reattribution succeeded!');
    END IF;

    ----------------------------------------------------------------------------
    -- TEST 6: Ordinary application roles cannot alter incident campus_id.
    ----------------------------------------------------------------------------
    PERFORM set_config('role', 'authenticated', true);
    PERFORM set_config('request.jwt.claim.role', 'authenticated', true);
    PERFORM set_config('request.jwt.claim.sub', v_admin_a::text, true);

    err_occurred := false;
    BEGIN
        UPDATE public.incidents SET campus_id = v_campus_b WHERE id = v_incident_a;
    EXCEPTION WHEN OTHERS THEN
        err_occurred := true;
        err_msg := SQLERRM;
    END;

    IF err_occurred THEN
        INSERT INTO temp_security_test_results VALUES (6, 'Application roles cannot alter incident campus_id', 'PASS', format('Blocked by tenancy immutability trigger: %s', err_msg));
    ELSE
        INSERT INTO temp_security_test_results VALUES (6, 'Application roles cannot alter incident campus_id', 'FAIL', 'Tenant hopping via incident update succeeded!');
    END IF;

    ----------------------------------------------------------------------------
    -- TEST 7: Campus isolation remains intact.
    ----------------------------------------------------------------------------
    -- Campus Admin A querying Campus B incidents
    PERFORM set_config('role', 'authenticated', true);
    PERFORM set_config('request.jwt.claim.role', 'authenticated', true);
    PERFORM set_config('request.jwt.claim.sub', v_admin_a::text, true);

    SELECT count(*) INTO cnt FROM public.incidents WHERE campus_id = v_campus_b;
    IF cnt = 0 THEN
        -- Also verify Student A cannot see Student B incident
        PERFORM set_config('request.jwt.claim.sub', v_student_a::text, true);
        SELECT count(*) INTO cnt FROM public.incidents WHERE id = v_incident_b;
        IF cnt = 0 THEN
            INSERT INTO temp_security_test_results VALUES (7, 'Campus isolation remains intact', 'PASS', 'Zero cross-campus or cross-student records visible under optimized RLS subqueries');
        ELSE
            INSERT INTO temp_security_test_results VALUES (7, 'Campus isolation remains intact', 'FAIL', 'Student A could read Student B incident');
        END IF;
    ELSE
        INSERT INTO temp_security_test_results VALUES (7, 'Campus isolation remains intact', 'FAIL', format('Admin A saw %s incidents from Campus B', cnt));
    END IF;

    ----------------------------------------------------------------------------
    -- TEST 8: Assigned investigator access remains intact.
    ----------------------------------------------------------------------------
    PERFORM set_config('role', 'authenticated', true);
    PERFORM set_config('request.jwt.claim.role', 'authenticated', true);
    PERFORM set_config('request.jwt.claim.sub', v_investigator::text, true);
    SELECT count(*) INTO cnt FROM public.incidents WHERE id = v_incident_b;
    IF cnt > 0 THEN
        -- Verify notes and evidence access
        IF EXISTS (SELECT 1 FROM public.incident_evidence WHERE incident_id = v_incident_b) 
           AND EXISTS (SELECT 1 FROM public.incident_notes WHERE incident_id = v_incident_b) THEN
            INSERT INTO temp_security_test_results VALUES (8, 'Assigned investigator access remains intact', 'PASS', 'Assigned investigator successfully accessed permitted incident, evidence, and notes');
        ELSE
            INSERT INTO temp_security_test_results VALUES (8, 'Assigned investigator access remains intact', 'FAIL', 'Investigator accessed incident but lacked evidence or notes access');
        END IF;
    ELSE
        INSERT INTO temp_security_test_results VALUES (8, 'Assigned investigator access remains intact', 'FAIL', 'Assigned investigator could not read incident');
    END IF;

    ----------------------------------------------------------------------------
    -- TEST 9: Existing role escalation protections remain intact.
    ----------------------------------------------------------------------------
    PERFORM set_config('role', 'authenticated', true);
    PERFORM set_config('request.jwt.claim.role', 'authenticated', true);
    PERFORM set_config('request.jwt.claim.sub', v_student_a::text, true);
    err_occurred := false;
    BEGIN
        UPDATE public.profiles SET role = 'CAMPUS_ADMIN' WHERE id = v_student_a;
    EXCEPTION WHEN OTHERS THEN
        err_occurred := true;
        err_msg := SQLERRM;
    END;

    IF err_occurred THEN
        -- Check signup metadata ignore
        PERFORM set_config('role', 'postgres', true);
        PERFORM set_config('request.jwt.claim.role', '', true);
        PERFORM set_config('request.jwt.claim.sub', '', true);
        INSERT INTO auth.users (id, email, raw_user_meta_data)
        VALUES (v_attacker, 'attacker@test.com', '{"role": "PLATFORM_ADMIN", "campus_id": "11111111-1111-1111-1111-111111111111"}'::jsonb);

        IF EXISTS (SELECT 1 FROM public.profiles WHERE id = v_attacker AND role = 'STUDENT' AND campus_id IS NULL) THEN
            INSERT INTO temp_security_test_results VALUES (9, 'Role escalation protections remain intact', 'PASS', 'Profile update blocked by trigger; signup metadata privileged role safely ignored');
        ELSE
            INSERT INTO temp_security_test_results VALUES (9, 'Role escalation protections remain intact', 'FAIL', 'Attacker assigned privileged role via metadata');
        END IF;
    ELSE
        INSERT INTO temp_security_test_results VALUES (9, 'Role escalation protections remain intact', 'FAIL', 'Student successfully updated own role');
    END IF;

    ----------------------------------------------------------------------------
    -- TEST 10: Audit log immutability remains intact.
    ----------------------------------------------------------------------------
    PERFORM set_config('role', 'authenticated', true);
    PERFORM set_config('request.jwt.claim.role', 'authenticated', true);
    PERFORM set_config('request.jwt.claim.sub', v_student_a::text, true);

    v_update_blocked := false;
    v_delete_blocked := false;

    -- 10a: Update blocked
    err_occurred := false;
    BEGIN
        UPDATE public.audit_logs SET action = 'TAMPERED' WHERE id = v_audit_log_id;
    EXCEPTION WHEN OTHERS THEN
        v_update_blocked := true;
    END;
    GET DIAGNOSTICS cnt = ROW_COUNT;
    IF cnt = 0 OR v_update_blocked THEN
        v_update_blocked := true;
    END IF;

    -- 10b: Delete blocked
    err_occurred := false;
    BEGIN
        DELETE FROM public.audit_logs WHERE id = v_audit_log_id;
    EXCEPTION WHEN OTHERS THEN
        v_delete_blocked := true;
    END;
    GET DIAGNOSTICS cnt = ROW_COUNT;
    IF cnt = 0 OR v_delete_blocked THEN
        v_delete_blocked := true;
    END IF;

    -- 10c: Verify under superuser that trigger enforces immutability
    PERFORM set_config('role', 'postgres', true);
    BEGIN
        UPDATE public.audit_logs SET action = 'TAMPERED' WHERE id = v_audit_log_id;
        v_update_blocked := false;
    EXCEPTION WHEN OTHERS THEN
        NULL; -- Expected trigger block
    END;

    IF v_update_blocked AND v_delete_blocked THEN
        INSERT INTO temp_security_test_results VALUES (10, 'Audit log immutability remains intact', 'PASS', 'Audit logs strictly immutable against updates and deletions across application and elevated roles');
    ELSE
        INSERT INTO temp_security_test_results VALUES (10, 'Audit log immutability remains intact', 'FAIL', format('UpdateBlocked=%s, DeleteBlocked=%s', v_update_blocked, v_delete_blocked));
    END IF;

END $$;

-- Display test results
SELECT test_id, test_name, status, details FROM temp_security_test_results ORDER BY test_id;

ROLLBACK;
