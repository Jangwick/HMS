-- =============================================================================
-- HR2 Workflow Implementation Migration
-- Run this in Supabase SQL Editor to add all new columns for the HR2 workflow
-- =============================================================================

-- ----------------------------
-- TRAININGS: new fields
-- ----------------------------
ALTER TABLE IF EXISTS trainings ADD COLUMN IF NOT EXISTS location_type VARCHAR(50) DEFAULT 'On-site';
ALTER TABLE IF EXISTS trainings ADD COLUMN IF NOT EXISTS start_time TIME;
ALTER TABLE IF EXISTS trainings ADD COLUMN IF NOT EXISTS end_time TIME;
ALTER TABLE IF EXISTS trainings ADD COLUMN IF NOT EXISTS requirements_file_url TEXT;

-- ----------------------------
-- TRAINING_CERTIFICATIONS: new table
-- ----------------------------
CREATE TABLE IF NOT EXISTS training_certifications (
    id SERIAL PRIMARY KEY,
    training_id INTEGER REFERENCES trainings(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    issued_date DATE NOT NULL DEFAULT CURRENT_DATE,
    expiry_date DATE,
    created_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT unique_training_cert UNIQUE (training_id, user_id)
);

ALTER TABLE IF EXISTS training_certifications ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on training_certifications" ON training_certifications;
CREATE POLICY "Allow all on training_certifications" ON training_certifications FOR ALL USING (true) WITH CHECK (true);

-- ----------------------------
-- COMPETENCIES: category & license_required
-- ----------------------------
ALTER TABLE IF EXISTS competencies ADD COLUMN IF NOT EXISTS category VARCHAR(50) DEFAULT 'Technical';
ALTER TABLE IF EXISTS competencies ADD COLUMN IF NOT EXISTS license_required BOOLEAN DEFAULT FALSE;

-- ----------------------------
-- STAFF_COMPETENCIES: full workflow fields
-- ----------------------------
ALTER TABLE IF EXISTS staff_competencies ADD COLUMN IF NOT EXISTS assessment_type VARCHAR(50) DEFAULT 'Practical';
ALTER TABLE IF EXISTS staff_competencies ADD COLUMN IF NOT EXISTS supervisor_id INTEGER REFERENCES users(id);
ALTER TABLE IF EXISTS staff_competencies ADD COLUMN IF NOT EXISTS license_verified BOOLEAN DEFAULT FALSE;
ALTER TABLE IF EXISTS staff_competencies ADD COLUMN IF NOT EXISTS license_expiry DATE;
ALTER TABLE IF EXISTS staff_competencies ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Scheduled';
ALTER TABLE IF EXISTS staff_competencies ADD COLUMN IF NOT EXISTS score NUMERIC(5,2);
ALTER TABLE IF EXISTS staff_competencies ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE IF EXISTS staff_competencies ADD COLUMN IF NOT EXISTS corrective_action TEXT;
ALTER TABLE IF EXISTS staff_competencies ADD COLUMN IF NOT EXISTS evaluator_notes TEXT;
ALTER TABLE IF EXISTS staff_competencies ADD COLUMN IF NOT EXISTS evaluated_by INTEGER REFERENCES users(id);
ALTER TABLE IF EXISTS staff_competencies ADD COLUMN IF NOT EXISTS evaluated_at TIMESTAMP;

-- ----------------------------
-- SUCCESSION_PLANS: workflow fields
-- ----------------------------
ALTER TABLE IF EXISTS succession_plans ADD COLUMN IF NOT EXISTS is_critical BOOLEAN DEFAULT FALSE;
ALTER TABLE IF EXISTS succession_plans ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Pending Review';
ALTER TABLE IF EXISTS succession_plans ADD COLUMN IF NOT EXISTS review_notes TEXT;
ALTER TABLE IF EXISTS succession_plans ADD COLUMN IF NOT EXISTS reviewed_by INTEGER REFERENCES users(id);
ALTER TABLE IF EXISTS succession_plans ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP;
ALTER TABLE IF EXISTS succession_plans ADD COLUMN IF NOT EXISTS finalized_by INTEGER REFERENCES users(id);
ALTER TABLE IF EXISTS succession_plans ADD COLUMN IF NOT EXISTS finalized_at TIMESTAMP;

-- Done
SELECT 'HR2 workflow migration complete.' AS result;
