-- ============================================================================
-- CT3 HADS (Hospital Activity & Documentation System) Migration Script
-- ============================================================================
-- This script transforms CT3 from basic "Admin & Finance" 
-- into a full Hospital Activity & Documentation System (HADS)
--
-- Execute this script on your Supabase database after backing up existing data.
-- ============================================================================

-- ============================================================================
-- PHASE 1: PATIENT STATUS ENGINE
-- ============================================================================

-- Add new columns to patients table for status tracking
ALTER TABLE patients 
ADD COLUMN IF NOT EXISTS current_status VARCHAR(50) DEFAULT 'Registered',
ADD COLUMN IF NOT EXISTS status_updated_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS status_updated_by INTEGER,
ADD COLUMN IF NOT EXISTS admission_date DATE,
ADD COLUMN IF NOT EXISTS discharge_date DATE,
ADD COLUMN IF NOT EXISTS ward_id INTEGER,
ADD COLUMN IF NOT EXISTS bed_id INTEGER,
ADD COLUMN IF NOT EXISTS attending_doctor_id INTEGER;

-- Create patient_status_history table for audit trail
CREATE TABLE IF NOT EXISTS patient_status_history (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    old_status VARCHAR(50),
    new_status VARCHAR(50) NOT NULL,
    changed_by INTEGER NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT,
    location VARCHAR(200),
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_status_history_patient ON patient_status_history(patient_id);
CREATE INDEX IF NOT EXISTS idx_status_history_date ON patient_status_history(changed_at DESC);

-- ============================================================================
-- PHASE 2: ACTIVITY FEED
-- ============================================================================

-- Create hospital_activity_log table
CREATE TABLE IF NOT EXISTS hospital_activity_log (
    id SERIAL PRIMARY KEY,
    activity_type VARCHAR(100) NOT NULL,
    patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
    user_id INTEGER,
    description TEXT NOT NULL,
    metadata JSONB,
    ip_address VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activity_patient ON hospital_activity_log(patient_id);
CREATE INDEX IF NOT EXISTS idx_activity_type ON hospital_activity_log(activity_type);
CREATE INDEX IF NOT EXISTS idx_activity_date ON hospital_activity_log(created_at DESC);

-- ============================================================================
-- PHASE 5: DISCHARGE PLANNER
-- ============================================================================

-- Create discharge_plans table
CREATE TABLE IF NOT EXISTS discharge_plans (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    plan_status VARCHAR(50) DEFAULT 'Pending', -- Pending, Reviewing, Cleared
    billing_cleared BOOLEAN DEFAULT FALSE,
    billing_cleared_by INTEGER,
    billing_cleared_at TIMESTAMPTZ,
    labs_cleared BOOLEAN DEFAULT FALSE,
    labs_cleared_by INTEGER,
    labs_cleared_at TIMESTAMPTZ,
    clinical_summary_cleared BOOLEAN DEFAULT FALSE,
    clinical_summary_cleared_by INTEGER,
    clinical_summary_cleared_at TIMESTAMPTZ,
    fully_cleared BOOLEAN DEFAULT FALSE,
    discharge_summary TEXT,
    diagnosis TEXT,
    follow_up_date DATE,
    follow_up_instructions TEXT,
    activity_restrictions TEXT,
    diet_instructions TEXT,
    wound_care_instructions TEXT,
    medications_prescribed TEXT,
    created_by INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_discharge_plans_patient ON discharge_plans(patient_id);
CREATE INDEX IF NOT EXISTS idx_discharge_plans_status ON discharge_plans(plan_status);

-- ============================================================================
-- PHASE 6: TRANSFER MANAGEMENT
-- ============================================================================

-- Create patient_transfers table
CREATE TABLE IF NOT EXISTS patient_transfers (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    transfer_type VARCHAR(50) NOT NULL, -- Internal, External
    from_location VARCHAR(200),
    to_location VARCHAR(200) NOT NULL,
    destination_hospital VARCHAR(300),
    destination_department VARCHAR(200),
    reason TEXT NOT NULL,
    transport_mode VARCHAR(100),
    clinical_summary TEXT,
    status VARCHAR(50) DEFAULT 'Pending', -- Pending, Completed, Cancelled
    initiated_by INTEGER NOT NULL,
    completed_by INTEGER,
    initiated_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    cancellation_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_transfers_patient ON patient_transfers(patient_id);
CREATE INDEX IF NOT EXISTS idx_transfers_status ON patient_transfers(status);
CREATE INDEX IF NOT EXISTS idx_transfers_date ON patient_transfers(initiated_at DESC);

-- ============================================================================
-- PHASE 7: DOCUMENT VAULT
-- ============================================================================

-- Create patient_documents table
CREATE TABLE IF NOT EXISTS patient_documents (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    document_type VARCHAR(100) NOT NULL, -- Lab Result, Imaging, Prescription, Consent Form, etc.
    title VARCHAR(300) NOT NULL,
    description TEXT,
    file_url TEXT NOT NULL,
    file_size_kb INTEGER,
    mime_type VARCHAR(100),
    is_confidential BOOLEAN DEFAULT FALSE,
    uploaded_by INTEGER NOT NULL,
    uploaded_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_documents_patient ON patient_documents(patient_id);
CREATE INDEX IF NOT EXISTS idx_documents_type ON patient_documents(document_type);
CREATE INDEX IF NOT EXISTS idx_documents_date ON patient_documents(uploaded_at DESC);

-- ============================================================================
-- PHASE 8: BILLING ENHANCEMENT
-- ============================================================================

-- Create billing table if it doesn't exist
CREATE TABLE IF NOT EXISTS billing (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    total_amount DECIMAL(12, 2) NOT NULL DEFAULT 0,
    status VARCHAR(50) DEFAULT 'Unpaid',
    payment_method VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add new columns to billing table for enhanced billing
DO $$ 
BEGIN
    -- Add insurance_provider column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='billing' AND column_name='insurance_provider') THEN
        ALTER TABLE billing ADD COLUMN insurance_provider VARCHAR(200);
    END IF;
    
    -- Add insurance_policy_no column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='billing' AND column_name='insurance_policy_no') THEN
        ALTER TABLE billing ADD COLUMN insurance_policy_no VARCHAR(100);
    END IF;
    
    -- Add insurance_coverage column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='billing' AND column_name='insurance_coverage') THEN
        ALTER TABLE billing ADD COLUMN insurance_coverage DECIMAL(12, 2) DEFAULT 0;
    END IF;
    
    -- Add philhealth_coverage column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='billing' AND column_name='philhealth_coverage') THEN
        ALTER TABLE billing ADD COLUMN philhealth_coverage DECIMAL(12, 2) DEFAULT 0;
    END IF;
    
    -- Add senior_discount column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='billing' AND column_name='senior_discount') THEN
        ALTER TABLE billing ADD COLUMN senior_discount DECIMAL(12, 2) DEFAULT 0;
    END IF;
    
    -- Add pwd_discount column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='billing' AND column_name='pwd_discount') THEN
        ALTER TABLE billing ADD COLUMN pwd_discount DECIMAL(12, 2) DEFAULT 0;
    END IF;
    
    -- Add net_amount column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='billing' AND column_name='net_amount') THEN
        ALTER TABLE billing ADD COLUMN net_amount DECIMAL(12, 2);
    END IF;
END $$;

-- Create billing_line_items table for itemized billing
CREATE TABLE IF NOT EXISTS billing_line_items (
    id SERIAL PRIMARY KEY,
    bill_id INTEGER NOT NULL REFERENCES billing(id) ON DELETE CASCADE,
    description VARCHAR(500) NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    unit_price DECIMAL(12, 2) NOT NULL,
    discount DECIMAL(12, 2) DEFAULT 0,
    line_total DECIMAL(12, 2) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_line_items_bill ON billing_line_items(bill_id);

-- ============================================================================
-- DATA BACKFILL & CLEANUP
-- ============================================================================

-- Backfill existing patients with default status
UPDATE patients 
SET current_status = 'Registered',
    status_updated_at = NOW()
WHERE current_status IS NULL;

-- Backfill net_amount for existing bills
UPDATE billing
SET net_amount = total_amount
WHERE net_amount IS NULL;

-- ============================================================================
-- FUNCTIONS & TRIGGERS
-- ============================================================================

-- Function to auto-update discharge plan status
CREATE OR REPLACE FUNCTION update_discharge_plan_status()
RETURNS TRIGGER AS $$
BEGIN
    NEW.fully_cleared := (
        NEW.billing_cleared AND 
        NEW.labs_cleared AND 
        NEW.clinical_summary_cleared
    );
    
    IF NEW.fully_cleared THEN
        NEW.plan_status := 'Cleared';
    ELSIF NEW.billing_cleared OR NEW.labs_cleared OR NEW.clinical_summary_cleared THEN
        NEW.plan_status := 'Reviewing';
    ELSE
        NEW.plan_status := 'Pending';
    END IF;
    
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for discharge plan status updates
DROP TRIGGER IF EXISTS trigger_update_discharge_plan_status ON discharge_plans;
CREATE TRIGGER trigger_update_discharge_plan_status
    BEFORE INSERT OR UPDATE ON discharge_plans
    FOR EACH ROW
    EXECUTE FUNCTION update_discharge_plan_status();

-- Function to calculate billing line total
CREATE OR REPLACE FUNCTION calculate_line_total()
RETURNS TRIGGER AS $$
BEGIN
    NEW.line_total := (NEW.quantity * NEW.unit_price) - COALESCE(NEW.discount, 0);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for billing line item calculation
DROP TRIGGER IF EXISTS trigger_calculate_line_total ON billing_line_items;
CREATE TRIGGER trigger_calculate_line_total
    BEFORE INSERT OR UPDATE ON billing_line_items
    FOR EACH ROW
    EXECUTE FUNCTION calculate_line_total();

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================================

-- Enable RLS on new tables
ALTER TABLE patient_status_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE hospital_activity_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE discharge_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE patient_transfers ENABLE ROW LEVEL SECURITY;
ALTER TABLE patient_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_line_items ENABLE ROW LEVEL SECURITY;

-- Create policies for authenticated users
-- Note: Adjust these policies based on your specific security requirements

-- patient_status_history policies
CREATE POLICY "Users can view status history" ON patient_status_history FOR SELECT TO authenticated USING (true);
CREATE POLICY "Users can insert status history" ON patient_status_history FOR INSERT TO authenticated WITH CHECK (true);

-- hospital_activity_log policies
CREATE POLICY "Users can view activity log" ON hospital_activity_log FOR SELECT TO authenticated USING (true);
CREATE POLICY "Users can insert activity log" ON hospital_activity_log FOR INSERT TO authenticated WITH CHECK (true);

-- discharge_plans policies
CREATE POLICY "Users can view discharge plans" ON discharge_plans FOR SELECT TO authenticated USING (true);
CREATE POLICY "Users can insert discharge plans" ON discharge_plans FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Users can update discharge plans" ON discharge_plans FOR UPDATE TO authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Users can delete discharge plans" ON discharge_plans FOR DELETE TO authenticated USING (true);

-- patient_transfers policies
CREATE POLICY "Users can view transfers" ON patient_transfers FOR SELECT TO authenticated USING (true);
CREATE POLICY "Users can insert transfers" ON patient_transfers FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Users can update transfers" ON patient_transfers FOR UPDATE TO authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Users can delete transfers" ON patient_transfers FOR DELETE TO authenticated USING (true);

-- patient_documents policies
CREATE POLICY "Users can view documents" ON patient_documents FOR SELECT TO authenticated USING (true);
CREATE POLICY "Users can insert documents" ON patient_documents FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Users can update documents" ON patient_documents FOR UPDATE TO authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Users can delete documents" ON patient_documents FOR DELETE TO authenticated USING (true);

-- billing_line_items policies
CREATE POLICY "Users can view line items" ON billing_line_items FOR SELECT TO authenticated USING (true);
CREATE POLICY "Users can insert line items" ON billing_line_items FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Users can update line items" ON billing_line_items FOR UPDATE TO authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Users can delete line items" ON billing_line_items FOR DELETE TO authenticated USING (true);

-- ============================================================================
-- SAMPLE DATA (OPTIONAL - FOR TESTING)
-- ============================================================================

-- Insert sample hospital activity log entry
-- INSERT INTO hospital_activity_log (activity_type, description, metadata)
-- VALUES ('System', 'CT3 HADS migration completed', '{"version": "1.0", "migration_date": "2024-01-15"}');

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Verify new tables were created
-- SELECT table_name FROM information_schema.tables 
-- WHERE table_schema = 'public' 
-- AND table_name IN ('patient_status_history', 'hospital_activity_log', 'discharge_plans', 
--                    'patient_transfers', 'patient_documents', 'billing_line_items');

-- Verify new columns in patients table
-- SELECT column_name, data_type FROM information_schema.columns 
-- WHERE table_name = 'patients' 
-- AND column_name IN ('current_status', 'admission_date', 'ward_id');

-- Verify new columns in billing table
-- SELECT column_name, data_type FROM information_schema.columns 
-- WHERE table_name = 'billing' 
-- AND column_name IN ('insurance_provider', 'net_amount');

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================
-- CT3 HADS is now ready to use!
-- All routes in routes/core_transaction/ct3.py are now supported.
-- All templates in templates/subsystems/core_transaction/ct3/ can render data.
-- ============================================================================
