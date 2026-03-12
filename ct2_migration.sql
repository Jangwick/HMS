-- =====================================================================
-- CT2 Phase 1-10 additions: encounters + result_inbox tables
-- Run in Supabase SQL editor (or psql)
-- =====================================================================

-- -------------------------------------------------------
-- 1. ENCOUNTERS  (EMR encounter record)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS encounters (
    id                  BIGSERIAL PRIMARY KEY,
    patient_id          BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    physician_id        BIGINT REFERENCES users(id) ON DELETE SET NULL,
    encounter_date      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    chief_complaint     TEXT,
    examination_notes   TEXT,
    diagnosis           TEXT,
    icd_code            VARCHAR(20),
    status              VARCHAR(40) NOT NULL DEFAULT 'Active'
                        CHECK (status IN ('Active','Awaiting Results','Ready for Discharge','Discharged')),
    discharged_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_encounters_patient   ON encounters(patient_id);
CREATE INDEX IF NOT EXISTS idx_encounters_physician ON encounters(physician_id);
CREATE INDEX IF NOT EXISTS idx_encounters_status    ON encounters(status);
CREATE INDEX IF NOT EXISTS idx_encounters_date      ON encounters(encounter_date DESC);

-- -------------------------------------------------------
-- 2. RESULT_INBOX  (verified results waiting physician ACK)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS result_inbox (
    id                  BIGSERIAL PRIMARY KEY,
    encounter_id        BIGINT REFERENCES encounters(id) ON DELETE SET NULL,
    patient_id          BIGINT REFERENCES patients(id) ON DELETE CASCADE,
    physician_id        BIGINT REFERENCES users(id) ON DELETE SET NULL,
    source_module       VARCHAR(30) NOT NULL,   -- 'Lab','Radiology','Surgery','Pharmacy'
    source_record_id    BIGINT,                  -- FK to lab_orders / radiology_orders / surgeries
    summary             TEXT,
    is_critical         BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged        BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_at     TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_result_inbox_physician   ON result_inbox(physician_id);
CREATE INDEX IF NOT EXISTS idx_result_inbox_encounter   ON result_inbox(encounter_id);
CREATE INDEX IF NOT EXISTS idx_result_inbox_critical    ON result_inbox(is_critical) WHERE is_critical = TRUE;
CREATE INDEX IF NOT EXISTS idx_result_inbox_unread      ON result_inbox(acknowledged)  WHERE acknowledged = FALSE;

-- -------------------------------------------------------
-- 3. EXTRA COLUMNS on existing tables
--    (run idempotently — IF NOT EXISTS for each column)
-- -------------------------------------------------------

-- lab_orders
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS barcode                VARCHAR(30);
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS specimen_collected_at  TIMESTAMPTZ;
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS specimen_registered_at TIMESTAMPTZ;
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS rejection_reason       TEXT;
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS result_value           TEXT;
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS result_unit            VARCHAR(30);
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS result_reference_range VARCHAR(80);
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS is_critical            BOOLEAN DEFAULT FALSE;
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS verified_by            BIGINT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS verified_at            TIMESTAMPTZ;

-- radiology_orders
ALTER TABLE radiology_orders ADD COLUMN IF NOT EXISTS scheduled_at          TIMESTAMPTZ;
ALTER TABLE radiology_orders ADD COLUMN IF NOT EXISTS imaging_completed_at  TIMESTAMPTZ;
ALTER TABLE radiology_orders ADD COLUMN IF NOT EXISTS findings              TEXT;
ALTER TABLE radiology_orders ADD COLUMN IF NOT EXISTS report_text           TEXT;
ALTER TABLE radiology_orders ADD COLUMN IF NOT EXISTS is_critical           BOOLEAN DEFAULT FALSE;
ALTER TABLE radiology_orders ADD COLUMN IF NOT EXISTS critical_findings     TEXT;
ALTER TABLE radiology_orders ADD COLUMN IF NOT EXISTS interpreter_id        BIGINT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE radiology_orders ADD COLUMN IF NOT EXISTS patient_prep_status   VARCHAR(20) DEFAULT 'Pending';

-- prescriptions
ALTER TABLE prescriptions ADD COLUMN IF NOT EXISTS safety_check_status VARCHAR(20);
ALTER TABLE prescriptions ADD COLUMN IF NOT EXISTS safety_flag_reason  TEXT;
ALTER TABLE prescriptions ADD COLUMN IF NOT EXISTS dispensed_at        TIMESTAMPTZ;
ALTER TABLE prescriptions ADD COLUMN IF NOT EXISTS dispensed_by        BIGINT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE prescriptions ADD COLUMN IF NOT EXISTS quantity            INT DEFAULT 1;

-- diet_plans
ALTER TABLE diet_plans ADD COLUMN IF NOT EXISTS approved_by  BIGINT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE diet_plans ADD COLUMN IF NOT EXISTS approved_at  TIMESTAMPTZ;

-- meal_tracking
ALTER TABLE meal_tracking ADD COLUMN IF NOT EXISTS delivery_status         VARCHAR(30) DEFAULT 'Pending';
ALTER TABLE meal_tracking ADD COLUMN IF NOT EXISTS delivered_at            TIMESTAMPTZ;
ALTER TABLE meal_tracking ADD COLUMN IF NOT EXISTS delivery_staff_id       BIGINT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE meal_tracking ADD COLUMN IF NOT EXISTS intake_percentage       INT CHECK (intake_percentage BETWEEN 0 AND 100);
ALTER TABLE meal_tracking ADD COLUMN IF NOT EXISTS intake_exception_reason TEXT;

-- surgeries
ALTER TABLE surgeries ADD COLUMN IF NOT EXISTS preop_cleared     BOOLEAN DEFAULT FALSE;
ALTER TABLE surgeries ADD COLUMN IF NOT EXISTS preop_notes       TEXT;
ALTER TABLE surgeries ADD COLUMN IF NOT EXISTS started_at        TIMESTAMPTZ;
ALTER TABLE surgeries ADD COLUMN IF NOT EXISTS ended_at          TIMESTAMPTZ;
ALTER TABLE surgeries ADD COLUMN IF NOT EXISTS intraop_notes     TEXT;
ALTER TABLE surgeries ADD COLUMN IF NOT EXISTS postop_status     VARCHAR(30);
ALTER TABLE surgeries ADD COLUMN IF NOT EXISTS recovery_location VARCHAR(80);

-- -------------------------------------------------------
-- RLS POLICIES  (match the "Allow all" pattern used by
--  every other table in this project)
-- -------------------------------------------------------
ALTER TABLE encounters   ENABLE ROW LEVEL SECURITY;
ALTER TABLE result_inbox ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Allow all on encounters"   ON encounters;
DROP POLICY IF EXISTS "Allow all on result_inbox" ON result_inbox;

CREATE POLICY "Allow all on encounters"   ON encounters   FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on result_inbox" ON result_inbox FOR ALL USING (true) WITH CHECK (true);

-- -------------------------------------------------------
-- Patch medical_records: add columns introduced in the
-- second CREATE TABLE definition (telehealth / documents)
-- -------------------------------------------------------
ALTER TABLE medical_records ADD COLUMN IF NOT EXISTS appointment_id  INTEGER REFERENCES appointments(id);
ALTER TABLE medical_records ADD COLUMN IF NOT EXISTS session_id      INTEGER REFERENCES telehealth_sessions(id);
ALTER TABLE medical_records ADD COLUMN IF NOT EXISTS record_type     VARCHAR(30) DEFAULT 'Outpatient';
ALTER TABLE medical_records ADD COLUMN IF NOT EXISTS prescription    TEXT;
ALTER TABLE medical_records ADD COLUMN IF NOT EXISTS follow_up_date  DATE;
ALTER TABLE medical_records ADD COLUMN IF NOT EXISTS recorded_by     INTEGER REFERENCES users(id);
-- Make diagnosis nullable so document uploads (no diagnosis) can be stored
ALTER TABLE medical_records ALTER COLUMN diagnosis DROP NOT NULL;

-- -------------------------------------------------------
-- Fix users.patient_id FK: change to ON DELETE SET NULL
-- so deleting a patient auto-nulls the portal account link
-- -------------------------------------------------------
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_patient_id_fkey;
ALTER TABLE users ADD CONSTRAINT users_patient_id_fkey
    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE SET NULL;

-- -------------------------------------------------------
-- Patch billing_records: add category column and fix status
-- -------------------------------------------------------
ALTER TABLE billing_records ADD COLUMN IF NOT EXISTS category VARCHAR(60) DEFAULT 'General';
ALTER TABLE billing_records ADD COLUMN IF NOT EXISTS appointment_id INTEGER REFERENCES appointments(id) ON DELETE SET NULL;

-- Add created_at to medical_records if missing (older DB instances)
ALTER TABLE medical_records ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();

-- Fix billing_records.patient_id FK to allow cascade deletion
ALTER TABLE billing_records DROP CONSTRAINT IF EXISTS billing_records_patient_id_fkey;
ALTER TABLE billing_records ADD CONSTRAINT billing_records_patient_id_fkey
    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE;
