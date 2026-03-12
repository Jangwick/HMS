-- CT3 HICS Billing Workflow Migration
-- Run in Supabase SQL Editor before/after deployment (safe: IF NOT EXISTS)

ALTER TABLE IF EXISTS billing_records
    ADD COLUMN IF NOT EXISTS workflow_stage VARCHAR(80) DEFAULT 'AUTO_CAPTURE_CHARGES',
    ADD COLUMN IF NOT EXISTS has_valid_insurance BOOLEAN,
    ADD COLUMN IF NOT EXISTS claim_decision VARCHAR(30),
    ADD COLUMN IF NOT EXISTS claim_last_updated_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_billing_records_workflow_stage
    ON billing_records(workflow_stage);

CREATE INDEX IF NOT EXISTS idx_billing_records_claim_decision
    ON billing_records(claim_decision);
