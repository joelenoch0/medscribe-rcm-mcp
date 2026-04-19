-- MedScribe RCM-FastMCP — Supabase Schema
-- Run this in the Supabase SQL Editor (free tier)
-- NO PHI is stored in any of these tables.

-- ── Consent Registry (42 CFR Part 2 + HIPAA) ─────────────────────────────
-- Stores hashed patient tokens and consent flags ONLY.
-- The patient_token is a one-way hash — never reverse-mappable to PHI.

CREATE TABLE IF NOT EXISTS consent_registry (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_token  TEXT NOT NULL,       -- hashed token, NOT PHI
    payer          TEXT,                -- optional payer scope
    consent_granted BOOLEAN NOT NULL DEFAULT FALSE,
    consent_type   TEXT DEFAULT 'general',  -- 'general' | 'sud_42cfr_part2'
    granted_at     TIMESTAMPTZ DEFAULT NOW(),
    expiry         TIMESTAMPTZ,         -- NULL = no expiry
    active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ DEFAULT NOW(),
    updated_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_consent_token  ON consent_registry(patient_token);
CREATE INDEX IF NOT EXISTS idx_consent_active ON consent_registry(active);

-- Row Level Security — only service role can write
ALTER TABLE consent_registry ENABLE ROW LEVEL SECURITY;

CREATE POLICY "anon_read_own_consent" ON consent_registry
    FOR SELECT USING (TRUE);  -- read allowed; token is already hashed

-- ── Audit Log (PHI-free event trail) ─────────────────────────────────────
-- HIPAA requires audit trails. All PHI is absent — only tool events logged.

CREATE TABLE IF NOT EXISTS audit_log (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool           TEXT NOT NULL,       -- tool name
    patient_token  TEXT,                -- hashed, NOT PHI
    payer          TEXT,
    trace_id       TEXT NOT NULL,       -- UUID from metadata lineage
    status         TEXT NOT NULL,       -- SUCCESS | BLOCKED:reason | FAIL:N_errors
    ts             TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_trace  ON audit_log(trace_id);
CREATE INDEX IF NOT EXISTS idx_audit_token  ON audit_log(patient_token);
CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(ts DESC);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_write" ON audit_log
    FOR INSERT WITH CHECK (TRUE);

-- ── Sample consent record for testing ────────────────────────────────────
-- Replace 'test_hashed_token_001' with actual hashed tokens in production.

INSERT INTO consent_registry (patient_token, consent_granted, consent_type, active)
VALUES ('test_hashed_token_001', TRUE, 'general', TRUE)
ON CONFLICT DO NOTHING;
