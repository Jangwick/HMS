-- =====================================================
-- Supabase Database Setup Script for HMS
-- Hospital Management System
-- =====================================================
-- Run this script in Supabase SQL Editor to create the users table
-- Go to: Supabase Dashboard > SQL Editor > New Query
-- =====================================================

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =====================================================
-- SINGLE USERS TABLE FOR ALL SUBSYSTEMS
-- =====================================================

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) NOT NULL,
    full_name VARCHAR(100),
    email VARCHAR(120) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    subsystem VARCHAR(20) NOT NULL,  -- hr1, hr2, ct1, ct2, log1, fin1, etc.
    department VARCHAR(50) NOT NULL,  -- HR, CORE_TRANSACTION, LOGISTICS, FINANCIALS
    role VARCHAR(50) DEFAULT 'Staff',
    password_created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    password_expires_at TIMESTAMP NOT NULL DEFAULT (NOW() + INTERVAL '90 days'),
    password_history JSONB DEFAULT '[]'::jsonb,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until TIMESTAMP,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    status VARCHAR(20) DEFAULT 'Pending', -- Pending, Active, Rejected
    avatar_url TEXT,
    
    CONSTRAINT unique_username UNIQUE (username),
    CONSTRAINT unique_email UNIQUE (email)
);

-- =====================================================
-- HR MODULE TABLES
-- =====================================================

-- HR1: Talent Acquisition
CREATE TABLE IF NOT EXISTS applicants (
    id SERIAL PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(120),
    phone VARCHAR(20),
    source VARCHAR(50), -- Walk-in, Referral, Agency
    vacancy_id INTEGER REFERENCES vacancies(id),
    status VARCHAR(50) DEFAULT 'Screening', -- Screening, Initial Interview, Final Interview, Offer, Handoff
    documents JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vacancies (
    id SERIAL PRIMARY KEY,
    position_name VARCHAR(100) NOT NULL,
    department VARCHAR(50),
    reason VARCHAR(100), -- Replacement, New position, New service
    requirements TEXT,
    qualifications TEXT,
    status VARCHAR(50) DEFAULT 'Open', -- Open, Filled, Closed
    approved_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS interviews (
    id SERIAL PRIMARY KEY,
    applicant_id INTEGER REFERENCES applicants(id) ON DELETE CASCADE,
    interviewer_id INTEGER REFERENCES users(id),
    interview_date TIMESTAMP NOT NULL,
    location VARCHAR(200),
    notes TEXT,
    status VARCHAR(50) DEFAULT 'Scheduled', -- Scheduled, Completed, Cancelled
    created_at TIMESTAMP DEFAULT NOW()
);

-- HR Table for Handoff/Onboarding
CREATE TABLE IF NOT EXISTS onboarding (
    id SERIAL PRIMARY KEY,
    applicant_id INTEGER REFERENCES applicants(id) ON DELETE CASCADE,
    position_id INTEGER REFERENCES vacancies(id),
    start_date DATE,
    status VARCHAR(50) DEFAULT 'Pending', -- Pending, In Progress, Completed
    created_at TIMESTAMP DEFAULT NOW()
);

-- HR2: Talent Development
CREATE TABLE IF NOT EXISTS competencies (
    id SERIAL PRIMARY KEY,
    role VARCHAR(100),
    skill_name VARCHAR(100) NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS staff_competencies (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    competency_id INTEGER REFERENCES competencies(id) ON DELETE CASCADE,
    assessment_date DATE DEFAULT CURRENT_DATE,
    level VARCHAR(50), -- Beginner, Intermediate, Expert
    assessor_id INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS trainings (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    type VARCHAR(100), -- Mandatory, Role-based
    schedule_date TIMESTAMP,
    description TEXT,
    location VARCHAR(200),
    trainer VARCHAR(100),
    target_department VARCHAR(100),
    max_participants INTEGER,
    materials_url TEXT,
    status VARCHAR(50) DEFAULT 'Scheduled'
);

CREATE TABLE IF NOT EXISTS training_participants (
    id SERIAL PRIMARY KEY,
    training_id INTEGER REFERENCES trainings(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    enrolled_at TIMESTAMP DEFAULT NOW(),
    attendance_status VARCHAR(50) DEFAULT 'Enrolled', -- Enrolled, Attended, Absent
    CONSTRAINT unique_training_participant UNIQUE (training_id, user_id)
);

-- HR2: Career & Succession
CREATE TABLE IF NOT EXISTS career_paths (
    id SERIAL PRIMARY KEY,
    path_name VARCHAR(100) NOT NULL,
    department VARCHAR(50),
    description TEXT,
    steps JSONB DEFAULT '[]'::jsonb, -- Array of {role: string, duration: string, requirements: string}
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS staff_career_paths (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    path_id INTEGER REFERENCES career_paths(id) ON DELETE CASCADE,
    current_step_index INTEGER DEFAULT 0,
    completed_requirements JSONB DEFAULT '[]'::jsonb,
    milestone_notes TEXT, -- New: Evidence/Reflection for current milestone
    requirement_evidence JSONB DEFAULT '{}'::jsonb, -- New: Map of requirement names to proof file URLs
    status VARCHAR(20) DEFAULT 'Active', -- Active, Completed, Paused
    started_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, path_id)
);

-- Safe injection
ALTER TABLE IF EXISTS staff_career_paths ADD COLUMN IF NOT EXISTS milestone_notes TEXT;

-- Ensure completed_requirements column exists if table already created
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='staff_career_paths' AND column_name='completed_requirements') THEN
        ALTER TABLE staff_career_paths ADD COLUMN completed_requirements JSONB DEFAULT '[]'::jsonb;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='staff_career_paths' AND column_name='requirement_evidence') THEN
        ALTER TABLE staff_career_paths ADD COLUMN requirement_evidence JSONB DEFAULT '{}'::jsonb;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS succession_plans (
    id SERIAL PRIMARY KEY,
    role_title VARCHAR(100) NOT NULL,
    incumbent_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    successor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    readiness_level VARCHAR(50), -- Ready Now, 1-2 Years, 3+ Years
    risk_of_vacancy VARCHAR(50), -- Low, Medium, High
    development_notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Ensure new columns exist in trainings table if it already exists
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='trainings' AND column_name='description') THEN
        ALTER TABLE trainings ADD COLUMN description TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='trainings' AND column_name='location') THEN
        ALTER TABLE trainings ADD COLUMN location VARCHAR(200);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='trainings' AND column_name='trainer') THEN
        ALTER TABLE trainings ADD COLUMN trainer VARCHAR(100);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='trainings' AND column_name='target_department') THEN
        ALTER TABLE trainings ADD COLUMN target_department VARCHAR(100);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='trainings' AND column_name='max_participants') THEN
        ALTER TABLE trainings ADD COLUMN max_participants INTEGER;
    END IF;
END $$;

-- HR3: Workforce Operations
CREATE TABLE IF NOT EXISTS attendance_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    clock_in TIMESTAMP,
    clock_out TIMESTAMP,
    status VARCHAR(50), -- On-time, Late, Absent
    remarks TEXT
);

CREATE TABLE IF NOT EXISTS leave_requests (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    leave_type VARCHAR(50), -- Sick, Vacation, Emergency
    start_date DATE,
    end_date DATE,
    status VARCHAR(50) DEFAULT 'Pending',
    remarks TEXT,
    approved_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- HR3: Staff Scheduling
CREATE TABLE IF NOT EXISTS staff_schedules (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    day_of_week VARCHAR(20), -- Monday, Tuesday, etc. or 'Daily'
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT unique_user_day UNIQUE (user_id, day_of_week)
);

ALTER TABLE IF EXISTS staff_schedules ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on staff_schedules" ON staff_schedules FOR ALL USING (true) WITH CHECK (true);

-- Ensure remarks column exists in leave_requests
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='leave_requests' AND column_name='remarks') THEN
        ALTER TABLE leave_requests ADD COLUMN remarks TEXT;
    END IF;
END $$;

-- HR4: Compensation & Analytics
CREATE TABLE IF NOT EXISTS salary_grades (
    id SERIAL PRIMARY KEY,
    grade_name VARCHAR(50) UNIQUE NOT NULL, -- Grade 1, Grade 2, etc.
    min_salary DECIMAL(12, 2) NOT NULL,
    max_salary DECIMAL(12, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compensation_records (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    base_salary DECIMAL(12, 2) NOT NULL,
    allowances DECIMAL(12, 2) DEFAULT 0.00,
    bonuses DECIMAL(12, 2) DEFAULT 0.00,
    deductions DECIMAL(12, 2) DEFAULT 0.00,
    effective_date DATE DEFAULT CURRENT_DATE,
    status VARCHAR(50) DEFAULT 'Active', -- Active, History
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS payroll_records (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    pay_period_start DATE NOT NULL,
    pay_period_end DATE NOT NULL,
    base_salary DECIMAL(12, 2) NOT NULL,
    gross_salary DECIMAL(12, 2) DEFAULT 0.00,
    bonuses DECIMAL(12, 2) DEFAULT 0.00,
    deductions DECIMAL(12, 2) DEFAULT 0.00,
    net_pay DECIMAL(12, 2) NOT NULL,
    status VARCHAR(50) DEFAULT 'Processed', -- Processed, Paid, Cancelled
    processed_date TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Ensure columns exist in compensation_records (Fix for PGRST204)
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='compensation_records' AND column_name='bonuses') THEN
        ALTER TABLE compensation_records ADD COLUMN bonuses DECIMAL(12, 2) DEFAULT 0.00;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='compensation_records' AND column_name='allowances') THEN
        ALTER TABLE compensation_records ADD COLUMN allowances DECIMAL(12, 2) DEFAULT 0.00;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='compensation_records' AND column_name='deductions') THEN
        ALTER TABLE compensation_records ADD COLUMN deductions DECIMAL(12, 2) DEFAULT 0.00;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='compensation_records' AND column_name='status') THEN
        ALTER TABLE compensation_records ADD COLUMN status VARCHAR(50) DEFAULT 'Active';
    END IF;
END $$;

-- =====================================================
-- HR4: BENEFITS & HMO TABLES
-- =====================================================

CREATE TABLE IF NOT EXISTS employee_benefits (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    benefit_type VARCHAR(100) NOT NULL,           -- 'HMO', 'Health Card', 'Rice Allowance', 'Uniform', 'Bonus', 'Other'
    provider VARCHAR(200),                         -- e.g. 'Maxicare', 'Medicard'
    coverage_amount DECIMAL(12,2) DEFAULT 0.00,
    start_date DATE DEFAULT CURRENT_DATE,
    end_date DATE,
    status VARCHAR(50) DEFAULT 'Active',           -- Active, Expired, Suspended
    notes TEXT,
    granted_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS benefit_claims (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    benefit_id INTEGER REFERENCES employee_benefits(id) ON DELETE SET NULL,
    claim_type VARCHAR(100) NOT NULL,              -- 'HMO Reimbursement', 'Benefit Availment', etc.
    amount DECIMAL(12,2) NOT NULL,
    description TEXT,
    status VARCHAR(50) DEFAULT 'Pending',          -- Pending, Approved, Rejected
    reviewed_by INTEGER REFERENCES users(id),
    reviewed_at TIMESTAMP,
    review_notes TEXT,
    submitted_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Fix: applicants.vacancy_id foreign key should allow vacancy deletion
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'applicants_vacancy_id_fkey' AND table_name = 'applicants'
    ) THEN
        ALTER TABLE applicants DROP CONSTRAINT applicants_vacancy_id_fkey;
    END IF;
    ALTER TABLE applicants ADD CONSTRAINT applicants_vacancy_id_fkey
        FOREIGN KEY (vacancy_id) REFERENCES vacancies(id) ON DELETE SET NULL;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Could not update applicants_vacancy_id_fkey: %', SQLERRM;
END $$;

-- Fix: onboarding.position_id foreign key should allow vacancy deletion
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'onboarding_position_id_fkey' AND table_name = 'onboarding'
    ) THEN
        ALTER TABLE onboarding DROP CONSTRAINT onboarding_position_id_fkey;
    END IF;
    ALTER TABLE onboarding ADD CONSTRAINT onboarding_position_id_fkey
        FOREIGN KEY (position_id) REFERENCES vacancies(id) ON DELETE SET NULL;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Could not update onboarding_position_id_fkey: %', SQLERRM;
END $$;

-- Safe column injections for employee_benefits (in case table was created without all columns)
ALTER TABLE IF EXISTS employee_benefits ADD COLUMN IF NOT EXISTS provider VARCHAR(200);
ALTER TABLE IF EXISTS employee_benefits ADD COLUMN IF NOT EXISTS coverage_amount DECIMAL(12,2) DEFAULT 0.00;
ALTER TABLE IF EXISTS employee_benefits ADD COLUMN IF NOT EXISTS start_date DATE DEFAULT CURRENT_DATE;
ALTER TABLE IF EXISTS employee_benefits ADD COLUMN IF NOT EXISTS end_date DATE;
ALTER TABLE IF EXISTS employee_benefits ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Active';
ALTER TABLE IF EXISTS employee_benefits ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE IF EXISTS employee_benefits ADD COLUMN IF NOT EXISTS granted_by INTEGER REFERENCES users(id);
ALTER TABLE IF EXISTS employee_benefits ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW();
ALTER TABLE IF EXISTS benefit_claims ADD COLUMN IF NOT EXISTS benefit_id INTEGER REFERENCES employee_benefits(id) ON DELETE SET NULL;
ALTER TABLE IF EXISTS benefit_claims ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE IF EXISTS benefit_claims ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Pending';
ALTER TABLE IF EXISTS benefit_claims ADD COLUMN IF NOT EXISTS reviewed_by INTEGER REFERENCES users(id);
ALTER TABLE IF EXISTS benefit_claims ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP;
ALTER TABLE IF EXISTS benefit_claims ADD COLUMN IF NOT EXISTS review_notes TEXT;
ALTER TABLE IF EXISTS benefit_claims ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMP DEFAULT NOW();

-- RLS: allow service role full access
ALTER TABLE IF EXISTS employee_benefits ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_employee_benefits" ON employee_benefits;
CREATE POLICY "service_role_employee_benefits" ON employee_benefits FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS benefit_claims ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_benefit_claims" ON benefit_claims;
CREATE POLICY "service_role_benefit_claims" ON benefit_claims FOR ALL USING (true) WITH CHECK (true);

-- =====================================================
-- CORE TRANSACTION TABLES
-- =====================================================

-- CT1: Patient Access
CREATE TABLE IF NOT EXISTS patients (
    id SERIAL PRIMARY KEY,
    patient_id_alt VARCHAR(50) UNIQUE, -- Auto-generated ID
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    dob DATE,
    gender VARCHAR(20),
    contact_number VARCHAR(20),
    address TEXT,
    insurance_info JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS appointments (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id),
    doctor_id INTEGER REFERENCES users(id),
    appointment_date TIMESTAMP NOT NULL,
    status VARCHAR(50) DEFAULT 'Scheduled', -- Scheduled, Completed, Cancelled
    type VARCHAR(50), -- Walk-in, Online, Phone
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- CT2: Clinical Operations
CREATE TABLE IF NOT EXISTS lab_orders (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id),
    doctor_id INTEGER REFERENCES users(id),
    test_name VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'Ordered', -- Ordered, Collected, Resulted
    results JSONB,
    critical_alert BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- CT2: Radiology Orders
CREATE TABLE IF NOT EXISTS radiology_orders (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id),
    doctor_id INTEGER REFERENCES users(id),
    imaging_type VARCHAR(100) NOT NULL, -- X-Ray, MRI, CT Scan, etc.
    status VARCHAR(50) DEFAULT 'Ordered', -- Ordered, In Progress, Resulted
    findings TEXT,
    image_url TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- =====================================================
-- CT2: DNMS (Diet and Nutrition Management System)
-- =====================================================

CREATE TABLE IF NOT EXISTS diet_plans (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
    diet_type VARCHAR(100) NOT NULL, -- General, Liquid, Diabetic, Low Sodium, No Gluten, etc.
    instruction TEXT,
    prescribed_by INTEGER REFERENCES users(id),
    start_date DATE DEFAULT CURRENT_DATE,
    end_date DATE,
    status VARCHAR(50) DEFAULT 'Active', -- Active, Completed, Terminated
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nutritional_assessments (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
    clinician_id INTEGER REFERENCES users(id),
    weight DECIMAL(6, 2), -- kg
    height DECIMAL(6, 2), -- cm
    bmi DECIMAL(6, 2),
    assessment_notes TEXT,
    recommendations TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS meal_tracking (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
    meal_type VARCHAR(50), -- Breakfast, Lunch, Dinner, Snack
    delivery_status VARCHAR(50) DEFAULT 'Pending', -- Pending, Delivered, Consumed, Refused
    delivered_at TIMESTAMP,
    delivery_staff_id INTEGER REFERENCES users(id),
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- RLS for DNMS
ALTER TABLE IF EXISTS diet_plans ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on diet_plans" ON diet_plans FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS nutritional_assessments ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on nutritional_assessments" ON nutritional_assessments FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS meal_tracking ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on meal_tracking" ON meal_tracking FOR ALL USING (true) WITH CHECK (true);

-- CT2: Surgery Management
CREATE TABLE IF NOT EXISTS surgeries (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id),
    surgeon_id INTEGER REFERENCES users(id),
    surgery_name VARCHAR(200) NOT NULL,
    surgery_date TIMESTAMP NOT NULL,
    operating_theater VARCHAR(50),
    status VARCHAR(50) DEFAULT 'Scheduled', -- Scheduled, In Progress, Completed, Post-Op, Cancelled
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS prescriptions (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id),
    doctor_id INTEGER REFERENCES users(id),
    medication_name VARCHAR(200) NOT NULL,
    dosage VARCHAR(100),
    instructions TEXT,
    status VARCHAR(50) DEFAULT 'Pending', -- Pending, Dispensed
    created_at TIMESTAMP DEFAULT NOW()
);

-- CT3: Medical Records
CREATE TABLE IF NOT EXISTS medical_records (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
    doctor_id INTEGER REFERENCES users(id),
    visit_date TIMESTAMP DEFAULT NOW(),
    diagnosis TEXT NOT NULL,
    treatment TEXT,
    vitals JSONB,
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- CT3: Bed Management
CREATE TABLE IF NOT EXISTS beds (
    id SERIAL PRIMARY KEY,
    room_number VARCHAR(20),
    ward_name VARCHAR(50),
    type VARCHAR(50), -- ICU, Regular, Isolation
    status VARCHAR(50) DEFAULT 'Available', -- Available, Occupied, Cleaning
    patient_id INTEGER REFERENCES patients(id) ON DELETE SET NULL
);

-- =====================================================
-- LOGISTICS TABLES
-- =====================================================

CREATE TABLE IF NOT EXISTS inventory (
    id SERIAL PRIMARY KEY,
    item_name VARCHAR(200) NOT NULL,
    category VARCHAR(100), -- Medical, Office, Maintenance
    quantity INTEGER DEFAULT 0,
    unit VARCHAR(50) DEFAULT 'units',
    reorder_level INTEGER DEFAULT 10,
    location VARCHAR(100),
    expiry_date DATE,
    batch_number VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dispensing_history (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id),
    inventory_id INTEGER REFERENCES inventory(id),
    quantity INTEGER NOT NULL,
    dispensed_by INTEGER REFERENCES users(id),
    notes TEXT,
    dispensed_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    asset_name VARCHAR(200) NOT NULL,
    tag_number VARCHAR(100) UNIQUE,
    status VARCHAR(50) DEFAULT 'Active', -- Active, Maintenance, Retired
    last_maintenance DATE,
    warranty_expiry DATE
);

CREATE TABLE IF NOT EXISTS fleet_vehicles (
    id SERIAL PRIMARY KEY,
    plate_number VARCHAR(20) UNIQUE,
    model_name VARCHAR(100),
    vehicle_type VARCHAR(50), -- Ambulance, Service, Logistics
    status VARCHAR(50) DEFAULT 'Available', -- Available, In Use, Maintenance
    last_service DATE,
    mileage INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS drivers (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    license_number VARCHAR(50) UNIQUE,
    phone VARCHAR(20),
    status VARCHAR(50) DEFAULT 'Active', -- Active, On Trip, Leave
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS fleet_dispatch (
    id SERIAL PRIMARY KEY,
    vehicle_id INTEGER REFERENCES fleet_vehicles(id),
    driver_id INTEGER REFERENCES drivers(id),
    destination TEXT,
    purpose TEXT,
    departure_time TIMESTAMP DEFAULT NOW(),
    return_time TIMESTAMP,
    status VARCHAR(50) DEFAULT 'Active', -- Active, Completed, Cancelled
    logged_by INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS fleet_costs (
    id SERIAL PRIMARY KEY,
    vehicle_id INTEGER REFERENCES fleet_vehicles(id),
    cost_type VARCHAR(50), -- Fuel, Maintenance, Insurance, Repair
    amount DECIMAL(12, 2) NOT NULL,
    description TEXT,
    log_date DATE DEFAULT CURRENT_DATE,
    logged_by INTEGER REFERENCES users(id)
);

-- RLS for Fleet
ALTER TABLE IF EXISTS fleet_vehicles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on fleet_vehicles" ON fleet_vehicles;
CREATE POLICY "Allow all on fleet_vehicles" ON fleet_vehicles FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS drivers ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on drivers" ON drivers;
CREATE POLICY "Allow all on drivers" ON drivers FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS fleet_dispatch ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on fleet_dispatch" ON fleet_dispatch;
CREATE POLICY "Allow all on fleet_dispatch" ON fleet_dispatch FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS fleet_costs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on fleet_costs" ON fleet_costs;
CREATE POLICY "Allow all on fleet_costs" ON fleet_costs FOR ALL USING (true) WITH CHECK (true);

-- Asset Maintenance Logging
CREATE TABLE IF NOT EXISTS asset_maintenance_logs (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    maintenance_date DATE DEFAULT CURRENT_DATE,
    maintenance_type VARCHAR(50) DEFAULT 'Other',
    performed_by INTEGER REFERENCES users(id),
    notes TEXT,
    cost DECIMAL(12, 2) DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT NOW()
);

ALTER TABLE IF EXISTS asset_maintenance_logs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on asset_maintenance_logs" ON asset_maintenance_logs;
CREATE POLICY "Allow all on asset_maintenance_logs" ON asset_maintenance_logs FOR ALL USING (true) WITH CHECK (true);

-- =====================================================
-- LOGISTICS PROCUREMENT & DOCUMENTS
-- =====================================================

CREATE TABLE IF NOT EXISTS suppliers (
    id SERIAL PRIMARY KEY,
    supplier_name VARCHAR(200) NOT NULL,
    contact_person VARCHAR(100),
    email VARCHAR(120),
    phone VARCHAR(20),
    category VARCHAR(100), -- Medical, Office, etc.
    status VARCHAR(50) DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS purchase_orders (
    id SERIAL PRIMARY KEY,
    po_number VARCHAR(50) UNIQUE NOT NULL,
    supplier_id INTEGER REFERENCES suppliers(id),
    total_amount DECIMAL(12, 2) DEFAULT 0.00,
    status VARCHAR(50) DEFAULT 'Draft', -- Draft, Sent, Received, Cancelled
    notes TEXT,
    requested_by INTEGER REFERENCES users(id),
    approved_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS po_items (
    id SERIAL PRIMARY KEY,
    po_id INTEGER REFERENCES purchase_orders(id) ON DELETE CASCADE,
    item_name VARCHAR(200) NOT NULL,
    quantity INTEGER NOT NULL,
    unit_price DECIMAL(12, 2) NOT NULL,
    total_price DECIMAL(12, 2) NOT NULL
);

CREATE TABLE IF NOT EXISTS log_documents (
    id SERIAL PRIMARY KEY,
    doc_type VARCHAR(50) NOT NULL, -- Invoice, Delivery Receipt, Certification
    doc_number VARCHAR(100),
    title VARCHAR(200) NOT NULL,
    file_url TEXT,
    status VARCHAR(50) DEFAULT 'Pending', -- Pending, Verified, Archived
    uploaded_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- =====================================================
-- PROJECT LOGISTICS TRACKER (PLT)
-- =====================================================

CREATE TABLE IF NOT EXISTS logistics_projects (
    id SERIAL PRIMARY KEY,
    project_name VARCHAR(200) NOT NULL,
    project_code VARCHAR(50),
    description TEXT,
    priority VARCHAR(20) DEFAULT 'Normal', -- Normal, Medium, High, Critical
    status VARCHAR(50) DEFAULT 'Planning', -- Planning, In Progress, On Hold, Completed, Cancelled
    progress INTEGER DEFAULT 0, -- 0-100
    start_date DATE,
    end_date DATE,
    category VARCHAR(100) DEFAULT 'Other', -- Equipment Relocation, Facility Setup, Supply Chain, etc.
    budget DECIMAL(12, 2) DEFAULT 0.00,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS project_milestones (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES logistics_projects(id) ON DELETE CASCADE,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    due_date DATE,
    status VARCHAR(50) DEFAULT 'Pending', -- Pending, In Progress, Completed
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS project_tasks (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES logistics_projects(id) ON DELETE CASCADE,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    assigned_to VARCHAR(100),
    priority VARCHAR(20) DEFAULT 'Normal', -- Normal, Medium, High, Critical
    status VARCHAR(50) DEFAULT 'To Do', -- To Do, In Progress, Done
    due_date DATE,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS project_expenses (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES logistics_projects(id) ON DELETE CASCADE,
    description VARCHAR(200) NOT NULL,
    amount DECIMAL(12, 2) NOT NULL,
    category VARCHAR(100), -- Labor, Materials, Equipment, Transport, Other
    date_incurred DATE DEFAULT CURRENT_DATE,
    recorded_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS project_activities (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES logistics_projects(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(200) NOT NULL,
    details TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- RLS for PLT
ALTER TABLE IF EXISTS logistics_projects ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on logistics_projects" ON logistics_projects;
CREATE POLICY "Allow all on logistics_projects" ON logistics_projects FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS project_milestones ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on project_milestones" ON project_milestones;
CREATE POLICY "Allow all on project_milestones" ON project_milestones FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS project_tasks ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on project_tasks" ON project_tasks;
CREATE POLICY "Allow all on project_tasks" ON project_tasks FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS project_expenses ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on project_expenses" ON project_expenses;
CREATE POLICY "Allow all on project_expenses" ON project_expenses FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS project_activities ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on project_activities" ON project_activities;
CREATE POLICY "Allow all on project_activities" ON project_activities FOR ALL USING (true) WITH CHECK (true);

-- Indexes for PLT
CREATE INDEX IF NOT EXISTS idx_logistics_projects_status ON logistics_projects(status);
CREATE INDEX IF NOT EXISTS idx_project_milestones_project_id ON project_milestones(project_id);
CREATE INDEX IF NOT EXISTS idx_project_tasks_project_id ON project_tasks(project_id);
CREATE INDEX IF NOT EXISTS idx_project_expenses_project_id ON project_expenses(project_id);
CREATE INDEX IF NOT EXISTS idx_project_activities_project_id ON project_activities(project_id);

-- =====================================================
-- FINANCIAL TABLES
-- =====================================================

CREATE TABLE IF NOT EXISTS billing_records (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id),
    total_amount DECIMAL(12, 2) DEFAULT 0.00,
    status VARCHAR(50) DEFAULT 'Unpaid', -- Unpaid, Paid, Partially Paid
    insurance_claim_status VARCHAR(50),
    billing_date TIMESTAMP DEFAULT NOW(),
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS general_ledger (
    id SERIAL PRIMARY KEY,
    account_code VARCHAR(20) UNIQUE,
    account_name VARCHAR(100) NOT NULL,
    balance DECIMAL(15, 2) DEFAULT 0.00,
    last_updated TIMESTAMP DEFAULT NOW()
);

-- Extended Financial Tables
CREATE TABLE IF NOT EXISTS vendors (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    contact_person VARCHAR(100),
    email VARCHAR(100),
    phone VARCHAR(20),
    status VARCHAR(50) DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vendor_invoices (
    id SERIAL PRIMARY KEY,
    vendor_id INTEGER REFERENCES vendors(id),
    invoice_number VARCHAR(50) UNIQUE,
    invoice_date DATE,
    due_date DATE,
    amount DECIMAL(12, 2) NOT NULL,
    status VARCHAR(50) DEFAULT 'Unpaid',
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vendor_payments (
    id SERIAL PRIMARY KEY,
    invoice_id INTEGER REFERENCES vendor_invoices(id),
    payment_date DATE DEFAULT CURRENT_DATE,
    amount DECIMAL(12, 2) NOT NULL,
    payment_method VARCHAR(50),
    reference_number VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS receivables (
    id SERIAL PRIMARY KEY,
    billing_id INTEGER REFERENCES billing_records(id),
    amount_due DECIMAL(12, 2) NOT NULL,
    due_date DATE,
    status VARCHAR(50) DEFAULT 'Unpaid',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS collections (
    id SERIAL PRIMARY KEY,
    receivable_id INTEGER REFERENCES receivables(id),
    collection_date TIMESTAMP DEFAULT NOW(),
    amount DECIMAL(12, 2) NOT NULL,
    payment_method VARCHAR(50),
    collected_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS bank_accounts (
    id SERIAL PRIMARY KEY,
    bank_name VARCHAR(100) NOT NULL,
    account_number VARCHAR(50) UNIQUE NOT NULL,
    account_type VARCHAR(50),
    balance DECIMAL(15, 2) DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cash_transactions (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES bank_accounts(id),
    transaction_type VARCHAR(20) NOT NULL, -- DEPOSIT, WITHDRAWAL, TRANSFER
    amount DECIMAL(12, 2) NOT NULL,
    description TEXT,
    transaction_date TIMESTAMP DEFAULT NOW(),
    performed_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS generated_reports (
    id SERIAL PRIMARY KEY,
    report_name VARCHAR(200) NOT NULL,
    report_type VARCHAR(50),
    generated_by INTEGER REFERENCES users(id),
    file_path TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Add RLS for new tables
ALTER TABLE IF EXISTS vendors ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on vendors" ON vendors FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS vendor_invoices ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on vendor_invoices" ON vendor_invoices FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS vendor_payments ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on vendor_payments" ON vendor_payments FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS receivables ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on receivables" ON receivables FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS collections ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on collections" ON collections FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS bank_accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on bank_accounts" ON bank_accounts FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS cash_transactions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on cash_transactions" ON cash_transactions FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS generated_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on generated_reports" ON generated_reports FOR ALL USING (true) WITH CHECK (true);

-- =====================================================
-- SAMPLE DATA FOR HR4
-- =====================================================

INSERT INTO salary_grades (grade_name, min_salary, max_salary) VALUES
('Grade 1', 15000.00, 25000.00),
('Grade 2', 25001.00, 40000.00),
('Grade 3', 40001.00, 65000.00),
('Grade 4', 65001.00, 100000.00)
ON CONFLICT (grade_name) DO NOTHING;

-- =====================================================
-- INDEXES FOR PERFORMANCE
-- =====================================================

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_subsystem ON users(subsystem);
CREATE INDEX IF NOT EXISTS idx_patients_name ON patients(last_name, first_name);
CREATE INDEX IF NOT EXISTS idx_inventory_expiry ON inventory(expiry_date);

-- =====================================================
-- ROW LEVEL SECURITY POLICIES
-- =====================================================
-- Enable RLS and add basic allow-all policies for development
-- In production, these should be more restrictive

-- Salary Grades
ALTER TABLE IF EXISTS salary_grades ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on salary_grades" ON salary_grades;
CREATE POLICY "Allow all on salary_grades" ON salary_grades FOR ALL USING (true) WITH CHECK (true);

-- Compensation Records
ALTER TABLE IF EXISTS compensation_records ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on compensation_records" ON compensation_records;
CREATE POLICY "Allow all on compensation_records" ON compensation_records FOR ALL USING (true) WITH CHECK (true);

-- Payroll Records
ALTER TABLE IF EXISTS payroll_records ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on payroll_records" ON payroll_records;
CREATE POLICY "Allow all on payroll_records" ON payroll_records FOR ALL USING (true) WITH CHECK (true);

-- Users
ALTER TABLE IF EXISTS users ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on users" ON users;
CREATE POLICY "Allow all on users" ON users FOR ALL USING (true) WITH CHECK (true);

-- =====================================================
-- ROW LEVEL SECURITY POLICIES (Consolidated)
-- =====================================================

-- HR Module
ALTER TABLE IF EXISTS applicants ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on applicants" ON applicants;
CREATE POLICY "Allow all on applicants" ON applicants FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS vacancies ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on vacancies" ON vacancies;
CREATE POLICY "Allow all on vacancies" ON vacancies FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS onboarding ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on onboarding" ON onboarding;
CREATE POLICY "Allow all on onboarding" ON onboarding FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS interviews ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on interviews" ON interviews;
CREATE POLICY "Allow all on interviews" ON interviews FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS attendance_logs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on attendance_logs" ON attendance_logs;
CREATE POLICY "Allow all on attendance_logs" ON attendance_logs FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS leave_requests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on leave_requests" ON leave_requests;
CREATE POLICY "Allow all on leave_requests" ON leave_requests FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS trainings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on trainings" ON trainings;
CREATE POLICY "Allow all on trainings" ON trainings FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS competencies ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on competencies" ON competencies;
CREATE POLICY "Allow all on competencies" ON competencies FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS staff_competencies ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on staff_competencies" ON staff_competencies;
CREATE POLICY "Allow all on staff_competencies" ON staff_competencies FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS training_participants ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on training_participants" ON training_participants;
CREATE POLICY "Allow all on training_participants" ON training_participants FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS career_paths ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on career_paths" ON career_paths;
CREATE POLICY "Allow all on career_paths" ON career_paths FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS staff_career_paths ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on staff_career_paths" ON staff_career_paths;
CREATE POLICY "Allow all on staff_career_paths" ON staff_career_paths FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS succession_plans ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on succession_plans" ON succession_plans;
CREATE POLICY "Allow all on succession_plans" ON succession_plans FOR ALL USING (true) WITH CHECK (true);

-- Core Transaction Module
ALTER TABLE IF EXISTS patients ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on patients" ON patients;
CREATE POLICY "Allow all on patients" ON patients FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS appointments ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on appointments" ON appointments;
CREATE POLICY "Allow all on appointments" ON appointments FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS lab_orders ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on lab_orders" ON lab_orders;
CREATE POLICY "Allow all on lab_orders" ON lab_orders FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS radiology_orders ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on radiology_orders" ON radiology_orders;
CREATE POLICY "Allow all on radiology_orders" ON radiology_orders FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS surgeries ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on surgeries" ON surgeries;
CREATE POLICY "Allow all on surgeries" ON surgeries FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS prescriptions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on prescriptions" ON prescriptions;
CREATE POLICY "Allow all on prescriptions" ON prescriptions FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS medical_records ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on medical_records" ON medical_records;
CREATE POLICY "Allow all on medical_records" ON medical_records FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS beds ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on beds" ON beds;
CREATE POLICY "Allow all on beds" ON beds FOR ALL USING (true) WITH CHECK (true);

-- Logistics Module
ALTER TABLE IF EXISTS inventory ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on inventory" ON inventory;
CREATE POLICY "Allow all on inventory" ON inventory FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS dispensing_history ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on dispensing_history" ON dispensing_history;
CREATE POLICY "Allow all on dispensing_history" ON dispensing_history FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS assets ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on assets" ON assets;
CREATE POLICY "Allow all on assets" ON assets FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS suppliers ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on suppliers" ON suppliers;
CREATE POLICY "Allow all on suppliers" ON suppliers FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS purchase_orders ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on purchase_orders" ON purchase_orders;
CREATE POLICY "Allow all on purchase_orders" ON purchase_orders FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS po_items ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on po_items" ON po_items;
CREATE POLICY "Allow all on po_items" ON po_items FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS log_documents ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on log_documents" ON log_documents;
CREATE POLICY "Allow all on log_documents" ON log_documents FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS fleet_vehicles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on fleet_vehicles" ON fleet_vehicles;
CREATE POLICY "Allow all on fleet_vehicles" ON fleet_vehicles FOR ALL USING (true) WITH CHECK (true);

-- Financials
ALTER TABLE IF EXISTS billing_records ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on billing_records" ON billing_records;
CREATE POLICY "Allow all on billing_records" ON billing_records FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS general_ledger ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on general_ledger" ON general_ledger;
CREATE POLICY "Allow all on general_ledger" ON general_ledger FOR ALL USING (true) WITH CHECK (true);

-- =====================================================
-- DATABASE MAINTENANCE & SYNC
-- Safe column injections for existing tables
-- =====================================================

-- HR Module Fixes
ALTER TABLE IF EXISTS trainings ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE IF EXISTS trainings ADD COLUMN IF NOT EXISTS location VARCHAR(200);
ALTER TABLE IF EXISTS trainings ADD COLUMN IF NOT EXISTS trainer VARCHAR(100);
ALTER TABLE IF EXISTS trainings ADD COLUMN IF NOT EXISTS target_department VARCHAR(100);
ALTER TABLE IF EXISTS trainings ADD COLUMN IF NOT EXISTS max_participants INTEGER;

-- Logistics Module Fixes (Fix for PGRST200/PGRST204)
ALTER TABLE IF EXISTS inventory ADD COLUMN IF NOT EXISTS batch_number VARCHAR(100);
ALTER TABLE IF EXISTS inventory ADD COLUMN IF NOT EXISTS unit VARCHAR(50) DEFAULT 'units';
ALTER TABLE IF EXISTS inventory ADD COLUMN IF NOT EXISTS reorder_level INTEGER DEFAULT 10;
ALTER TABLE IF EXISTS inventory ADD COLUMN IF NOT EXISTS location VARCHAR(100);
ALTER TABLE IF EXISTS inventory ADD COLUMN IF NOT EXISTS expiry_date DATE;

-- Logistics Transactions
CREATE TABLE IF NOT EXISTS inventory_transactions (
    id SERIAL PRIMARY KEY,
    item_id INTEGER REFERENCES inventory(id) ON DELETE CASCADE,
    transaction_type VARCHAR(20) NOT NULL, -- DISPENSE, RESTOCK, ADJUST
    quantity INTEGER NOT NULL,
    notes TEXT,
    performed_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- RLS for Transactions
ALTER TABLE IF EXISTS inventory_transactions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on transactions" ON inventory_transactions;
CREATE POLICY "Allow all on transactions" ON inventory_transactions FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS purchase_orders ADD COLUMN IF NOT EXISTS po_number VARCHAR(50);
ALTER TABLE IF EXISTS purchase_orders ADD COLUMN IF NOT EXISTS supplier_id INTEGER;
ALTER TABLE IF EXISTS purchase_orders ADD COLUMN IF NOT EXISTS total_amount DECIMAL(12, 2) DEFAULT 0.00;
ALTER TABLE IF EXISTS purchase_orders ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Draft';
ALTER TABLE IF EXISTS purchase_orders ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE IF EXISTS purchase_orders ADD COLUMN IF NOT EXISTS requested_by INTEGER;
ALTER TABLE IF EXISTS purchase_orders ADD COLUMN IF NOT EXISTS approved_by INTEGER;

ALTER TABLE IF EXISTS dispensing_history ADD COLUMN IF NOT EXISTS patient_id INTEGER;

-- Patient & Medical Fixes
ALTER TABLE IF EXISTS patients ADD COLUMN IF NOT EXISTS allergies TEXT DEFAULT 'None known';
ALTER TABLE IF EXISTS medical_records ADD COLUMN IF NOT EXISTS vitals JSONB DEFAULT '{}'::jsonb;

-- Robust Constraint Injection (Required for Foreign Keys)
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name='purchase_orders_supplier_id_fkey' AND table_name='purchase_orders') THEN
        ALTER TABLE purchase_orders ADD CONSTRAINT purchase_orders_supplier_id_fkey FOREIGN KEY (supplier_id) REFERENCES suppliers(id);
    END IF;
EXCEPTION WHEN OTHERS THEN 
    RAISE NOTICE 'Constraint might already exist or table missing';
END $$;

-- Robust column injection for Financials
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='generated_reports' AND column_name='created_at') THEN
        ALTER TABLE generated_reports ADD COLUMN created_at TIMESTAMP DEFAULT NOW();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='generated_reports' AND column_name='file_path') THEN
        ALTER TABLE generated_reports ADD COLUMN file_path TEXT;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='generated_reports' AND column_name='report_type') THEN
        ALTER TABLE generated_reports ADD COLUMN report_type VARCHAR(50);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='generated_reports' AND column_name='report_name') THEN
        ALTER TABLE generated_reports ADD COLUMN report_name VARCHAR(200);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='receivables' AND column_name='created_at') THEN
        ALTER TABLE receivables ADD COLUMN created_at TIMESTAMP DEFAULT NOW();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='payroll_records' AND column_name='gross_salary') THEN
        ALTER TABLE payroll_records ADD COLUMN gross_salary DECIMAL(12, 2) DEFAULT 0.00;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='bank_accounts' AND column_name='balance') THEN
        ALTER TABLE bank_accounts ADD COLUMN balance DECIMAL(15, 2) DEFAULT 0.00;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='vendor_invoices' AND column_name='status') THEN
        ALTER TABLE vendor_invoices ADD COLUMN status VARCHAR(50) DEFAULT 'Unpaid';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='receivables' AND column_name='status') THEN
        ALTER TABLE receivables ADD COLUMN status VARCHAR(50) DEFAULT 'Unpaid';
    END IF;
END $$;

-- Fleet Module Fixes (Fix for PGRST204)
ALTER TABLE IF EXISTS fleet_vehicles ADD COLUMN IF NOT EXISTS plate_number VARCHAR(20);
ALTER TABLE IF EXISTS fleet_vehicles ADD COLUMN IF NOT EXISTS model_name VARCHAR(100);
ALTER TABLE IF EXISTS fleet_vehicles ADD COLUMN IF NOT EXISTS vehicle_type VARCHAR(50);
ALTER TABLE IF EXISTS fleet_vehicles ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Available';
ALTER TABLE IF EXISTS fleet_vehicles ADD COLUMN IF NOT EXISTS last_service DATE;
ALTER TABLE IF EXISTS fleet_vehicles ADD COLUMN IF NOT EXISTS mileage INTEGER DEFAULT 0;
ALTER TABLE IF EXISTS fleet_vehicles ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();

ALTER TABLE IF EXISTS drivers ADD COLUMN IF NOT EXISTS full_name VARCHAR(100);
ALTER TABLE IF EXISTS drivers ADD COLUMN IF NOT EXISTS license_number VARCHAR(50);
ALTER TABLE IF EXISTS drivers ADD COLUMN IF NOT EXISTS phone VARCHAR(20);
ALTER TABLE IF EXISTS drivers ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Active';
ALTER TABLE IF EXISTS drivers ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();

ALTER TABLE IF EXISTS fleet_dispatch ADD COLUMN IF NOT EXISTS vehicle_id INTEGER REFERENCES fleet_vehicles(id);
ALTER TABLE IF EXISTS fleet_dispatch ADD COLUMN IF NOT EXISTS driver_id INTEGER REFERENCES drivers(id);
ALTER TABLE IF EXISTS fleet_dispatch ADD COLUMN IF NOT EXISTS destination TEXT;
ALTER TABLE IF EXISTS fleet_dispatch ADD COLUMN IF NOT EXISTS purpose TEXT;
ALTER TABLE IF EXISTS fleet_dispatch ADD COLUMN IF NOT EXISTS departure_time TIMESTAMP DEFAULT NOW();
ALTER TABLE IF EXISTS fleet_dispatch ADD COLUMN IF NOT EXISTS return_time TIMESTAMP;
ALTER TABLE IF EXISTS fleet_dispatch ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'On Trip';
ALTER TABLE IF EXISTS fleet_dispatch ADD COLUMN IF NOT EXISTS logged_by INTEGER REFERENCES users(id);
ALTER TABLE IF EXISTS fleet_dispatch ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();

ALTER TABLE IF EXISTS fleet_costs ADD COLUMN IF NOT EXISTS vehicle_id INTEGER REFERENCES fleet_vehicles(id);
ALTER TABLE IF EXISTS fleet_costs ADD COLUMN IF NOT EXISTS cost_type VARCHAR(50);
ALTER TABLE IF EXISTS fleet_costs ADD COLUMN IF NOT EXISTS amount DECIMAL(12, 2);
ALTER TABLE IF EXISTS fleet_costs ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE IF EXISTS fleet_costs ADD COLUMN IF NOT EXISTS log_date DATE DEFAULT CURRENT_DATE;
ALTER TABLE IF EXISTS fleet_costs ADD COLUMN IF NOT EXISTS logged_by INTEGER REFERENCES users(id);

-- ROBUST BILLING_RECORDS FIX
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='billing_records' AND column_name='billing_date') THEN
        ALTER TABLE billing_records ADD COLUMN billing_date TIMESTAMP DEFAULT NOW();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='billing_records' AND column_name='description') THEN
        ALTER TABLE billing_records ADD COLUMN description TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='vendor_invoices' AND column_name='description') THEN
        ALTER TABLE vendor_invoices ADD COLUMN description TEXT;
    END IF;

    -- ROBUST RECEIVABLES FIX
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='receivables' AND column_name='billing_id') THEN
        ALTER TABLE receivables ADD COLUMN billing_id INTEGER REFERENCES billing_records(id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='receivables' AND column_name='amount_due') THEN
        ALTER TABLE receivables ADD COLUMN amount_due DECIMAL(12, 2) DEFAULT 0.00;
    END IF;

    -- ROBUST COLLECTIONS FIX
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='collections' AND column_name='collected_by') THEN
        ALTER TABLE collections ADD COLUMN collected_by INTEGER REFERENCES users(id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='collections' AND column_name='reference') THEN
        ALTER TABLE collections ADD COLUMN reference VARCHAR(100);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='collections' AND column_name='account_id') THEN
        ALTER TABLE collections ADD COLUMN account_id INTEGER REFERENCES bank_accounts(id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='collections' AND column_name='payment_method') THEN
        ALTER TABLE collections ADD COLUMN payment_method VARCHAR(50);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='collections' AND column_name='collection_date') THEN
        ALTER TABLE collections ADD COLUMN collection_date TIMESTAMP DEFAULT NOW();
    END IF;

    -- ROBUST VENDOR PAYMENTS FIX
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='vendor_payments' AND column_name='account_id') THEN
        ALTER TABLE vendor_payments ADD COLUMN account_id INTEGER REFERENCES bank_accounts(id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='vendor_payments' AND column_name='payment_method') THEN
        ALTER TABLE vendor_payments ADD COLUMN payment_method VARCHAR(50);
    END IF;

    -- ROBUST CASH_TRANSACTIONS FIX
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='cash_transactions' AND column_name='account_id') THEN
        ALTER TABLE cash_transactions ADD COLUMN account_id INTEGER REFERENCES bank_accounts(id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='cash_transactions' AND column_name='transaction_type') THEN
        ALTER TABLE cash_transactions ADD COLUMN transaction_type VARCHAR(20);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='cash_transactions' AND column_name='amount') THEN
        ALTER TABLE cash_transactions ADD COLUMN amount DECIMAL(12, 2) DEFAULT 0.00;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='cash_transactions' AND column_name='performed_by') THEN
        ALTER TABLE cash_transactions ADD COLUMN performed_by INTEGER REFERENCES users(id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='cash_transactions' AND column_name='transaction_date') THEN
        ALTER TABLE cash_transactions ADD COLUMN transaction_date TIMESTAMP DEFAULT NOW();
    END IF;
END $$;
ALTER TABLE IF EXISTS fleet_costs ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();

-- =====================================================
-- AUDIT LOGGING
-- =====================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(255) NOT NULL,
    subsystem VARCHAR(50) NOT NULL,
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

-- =====================================================
-- NOTIFICATIONS SYSTEM
-- =====================================================
CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    target_subsystem VARCHAR(50), -- Target subsystem (e.g. fin1, hr3)
    target_role VARCHAR(50),      -- Optional: Target role (e.g. Manager)
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    sender_subsystem VARCHAR(50), -- Source subsystem
    type VARCHAR(50) DEFAULT 'info', -- info, success, warning, danger
    target_url TEXT,              -- Optional: Link to relevant page
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Robust fix for Notifications system RLS
ALTER TABLE IF EXISTS notifications ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on notifications" ON notifications;
CREATE POLICY "Allow all on notifications" ON notifications FOR ALL USING (true) WITH CHECK (true);
ALTER TABLE notifications DISABLE ROW LEVEL SECURITY; -- Temporary for development reliability

-- Patch for medical_records table
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='medical_records' AND column_name='treatment') THEN
        ALTER TABLE medical_records ADD COLUMN treatment TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='medical_records' AND column_name='vitals') THEN
        ALTER TABLE medical_records ADD COLUMN vitals JSONB;
    END IF;
END $$;

-- =====================================================
-- SYSTEM AUDIT LOGS (For Backup/Restore and other actions)
-- =====================================================
CREATE TABLE IF NOT EXISTS system_audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT NOW(),
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(20), -- BACKUP, RESTORE
    scope VARCHAR(20), -- DEPARTMENT, SUBSYSTEM
    target_id VARCHAR(50), -- e.g., HR1, Logistics
    status VARCHAR(20), -- SUCCESS, FAIL
    file_name VARCHAR(255),
    details TEXT
);

-- CT1 Features: Telehealth and ER Triage
CREATE TABLE IF NOT EXISTS er_triage (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
    complaint TEXT NOT NULL,
    vitals JSONB DEFAULT '{}'::jsonb, -- bp, hr, temp, resp, spo2
    pain_score INTEGER, -- 1-10
    priority_level VARCHAR(50), -- Level 1 (Resuscitation) to Level 5 (Non-Urgent)
    triage_officer_id INTEGER REFERENCES users(id),
    status VARCHAR(50) DEFAULT 'Waiting', -- Waiting, Seen, Admitted, Discharged
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS telehealth_sessions (
    id SERIAL PRIMARY KEY,
    appointment_id INTEGER REFERENCES appointments(id) ON DELETE SET NULL,
    patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
    doctor_id INTEGER REFERENCES users(id),
    scheduled_at TIMESTAMP NOT NULL,
    meeting_link TEXT,
    status VARCHAR(50) DEFAULT 'Scheduled', -- Scheduled, In Progress, Completed, Cancelled
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- RLS for ER Triage and Telehealth
ALTER TABLE IF EXISTS er_triage ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on er_triage" ON er_triage;
CREATE POLICY "Allow all on er_triage" ON er_triage FOR ALL USING (true) WITH CHECK (true);
ALTER TABLE er_triage DISABLE ROW LEVEL SECURITY;

ALTER TABLE IF EXISTS telehealth_sessions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on telehealth_sessions" ON telehealth_sessions;
CREATE POLICY "Allow all on telehealth_sessions" ON telehealth_sessions FOR ALL USING (true) WITH CHECK (true);
ALTER TABLE telehealth_sessions DISABLE ROW LEVEL SECURITY;

-- Ensure correct permissions for audit logs
ALTER TABLE IF EXISTS system_audit_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on system_audit_logs" ON system_audit_logs FOR ALL USING (true) WITH CHECK (true);

-- =====================================================
-- STORAGE BUCKETS SETUP
-- =====================================================
-- Bucket for career proof evidence
INSERT INTO storage.buckets (id, name, public) 
VALUES ('career_proofs', 'career_proofs', true)
ON CONFLICT (id) DO UPDATE SET public = true;

-- Bucket for user profiles
INSERT INTO storage.buckets (id, name, public) 
VALUES ('profiles', 'profiles', true)
ON CONFLICT (id) DO UPDATE SET public = true;

-- Storage policies (Allow public access for development - refine for production)
-- Policies for career_proofs
DROP POLICY IF EXISTS "Public Access Proofs" ON storage.objects;
CREATE POLICY "Public Access Proofs" ON storage.objects FOR SELECT USING (bucket_id = 'career_proofs');

DROP POLICY IF EXISTS "Public Upload Proofs" ON storage.objects;
CREATE POLICY "Public Upload Proofs" ON storage.objects FOR INSERT WITH CHECK (bucket_id = 'career_proofs');

DROP POLICY IF EXISTS "Public Update Proofs" ON storage.objects;
CREATE POLICY "Public Update Proofs" ON storage.objects FOR UPDATE WITH CHECK (bucket_id = 'career_proofs');

-- Policies for profiles
DROP POLICY IF EXISTS "Public Access Profiles" ON storage.objects;
CREATE POLICY "Public Access Profiles" ON storage.objects FOR SELECT USING (bucket_id = 'profiles');

DROP POLICY IF EXISTS "Public Upload Profiles" ON storage.objects;
CREATE POLICY "Public Upload Profiles" ON storage.objects FOR INSERT WITH CHECK (bucket_id = 'profiles');

DROP POLICY IF EXISTS "Public Update Profiles" ON storage.objects;
CREATE POLICY "Public Update Profiles" ON storage.objects FOR UPDATE WITH CHECK (bucket_id = 'profiles');

-- Policies for logistics documents
DROP POLICY IF EXISTS "Public Access Logistics Docs" ON storage.objects;
CREATE POLICY "Public Access Logistics Docs" ON storage.objects FOR SELECT USING (bucket_id = 'logistics_docs');

DROP POLICY IF EXISTS "Public Upload Logistics Docs" ON storage.objects;
CREATE POLICY "Public Upload Logistics Docs" ON storage.objects FOR INSERT WITH CHECK (bucket_id = 'logistics_docs');

DROP POLICY IF EXISTS "Public Update Logistics Docs" ON storage.objects;
CREATE POLICY "Public Update Logistics Docs" ON storage.objects FOR UPDATE WITH CHECK (bucket_id = 'logistics_docs');

DROP POLICY IF EXISTS "Public Delete Logistics Docs" ON storage.objects;
CREATE POLICY "Public Delete Logistics Docs" ON storage.objects FOR DELETE USING (bucket_id = 'logistics_docs');

-- Bucket for applicant resumes / CVs (used by public careers portal and HR1)
INSERT INTO storage.buckets (id, name, public)
VALUES ('resumes', 'resumes', true)
ON CONFLICT (id) DO UPDATE SET public = true;

DROP POLICY IF EXISTS "Public Access Resumes" ON storage.objects;
CREATE POLICY "Public Access Resumes" ON storage.objects FOR SELECT USING (bucket_id = 'resumes');

DROP POLICY IF EXISTS "Public Upload Resumes" ON storage.objects;
CREATE POLICY "Public Upload Resumes" ON storage.objects FOR INSERT WITH CHECK (bucket_id = 'resumes');

DROP POLICY IF EXISTS "Public Update Resumes" ON storage.objects;
CREATE POLICY "Public Update Resumes" ON storage.objects FOR UPDATE WITH CHECK (bucket_id = 'resumes');

DROP POLICY IF EXISTS "Public Delete Resumes" ON storage.objects;
CREATE POLICY "Public Delete Resumes" ON storage.objects FOR DELETE USING (bucket_id = 'resumes');

-- Bucket for ESS leave request supporting documents (HR3)
INSERT INTO storage.buckets (id, name, public)
VALUES ('ess-documents', 'ess-documents', true)
ON CONFLICT (id) DO UPDATE SET public = true;

DROP POLICY IF EXISTS "Public Access ESS Docs" ON storage.objects;
CREATE POLICY "Public Access ESS Docs" ON storage.objects FOR SELECT USING (bucket_id = 'ess-documents');

DROP POLICY IF EXISTS "Public Upload ESS Docs" ON storage.objects;
CREATE POLICY "Public Upload ESS Docs" ON storage.objects FOR INSERT WITH CHECK (bucket_id = 'ess-documents');

DROP POLICY IF EXISTS "Public Update ESS Docs" ON storage.objects;
CREATE POLICY "Public Update ESS Docs" ON storage.objects FOR UPDATE WITH CHECK (bucket_id = 'ess-documents');

DROP POLICY IF EXISTS "Public Delete ESS Docs" ON storage.objects;
CREATE POLICY "Public Delete ESS Docs" ON storage.objects FOR DELETE USING (bucket_id = 'ess-documents');

-- Bucket for reimbursement receipt images (HR3)
INSERT INTO storage.buckets (id, name, public)
VALUES ('receipts', 'receipts', true)
ON CONFLICT (id) DO UPDATE SET public = true;

DROP POLICY IF EXISTS "Public Access Receipts" ON storage.objects;
CREATE POLICY "Public Access Receipts" ON storage.objects FOR SELECT USING (bucket_id = 'receipts');

DROP POLICY IF EXISTS "Public Upload Receipts" ON storage.objects;
CREATE POLICY "Public Upload Receipts" ON storage.objects FOR INSERT WITH CHECK (bucket_id = 'receipts');

DROP POLICY IF EXISTS "Public Update Receipts" ON storage.objects;
CREATE POLICY "Public Update Receipts" ON storage.objects FOR UPDATE WITH CHECK (bucket_id = 'receipts');

DROP POLICY IF EXISTS "Public Delete Receipts" ON storage.objects;
CREATE POLICY "Public Delete Receipts" ON storage.objects FOR DELETE USING (bucket_id = 'receipts');

-- Bucket for HR2 training & assessment files
INSERT INTO storage.buckets (id, name, public)
VALUES ('hr2-assessments', 'hr2-assessments', true)
ON CONFLICT (id) DO UPDATE SET public = true;

DROP POLICY IF EXISTS "Public Access HR2 Assessments" ON storage.objects;
CREATE POLICY "Public Access HR2 Assessments" ON storage.objects FOR SELECT USING (bucket_id = 'hr2-assessments');

DROP POLICY IF EXISTS "Public Upload HR2 Assessments" ON storage.objects;
CREATE POLICY "Public Upload HR2 Assessments" ON storage.objects FOR INSERT WITH CHECK (bucket_id = 'hr2-assessments');

DROP POLICY IF EXISTS "Public Update HR2 Assessments" ON storage.objects;
CREATE POLICY "Public Update HR2 Assessments" ON storage.objects FOR UPDATE WITH CHECK (bucket_id = 'hr2-assessments');

DROP POLICY IF EXISTS "Public Delete HR2 Assessments" ON storage.objects;
CREATE POLICY "Public Delete HR2 Assessments" ON storage.objects FOR DELETE USING (bucket_id = 'hr2-assessments');

-- Bucket for recognition nomination supporting attachments (HR1)
INSERT INTO storage.buckets (id, name, public)
VALUES ('recognition-docs', 'recognition-docs', true)
ON CONFLICT (id) DO UPDATE SET public = true;

DROP POLICY IF EXISTS "Public Access Recognition Docs" ON storage.objects;
CREATE POLICY "Public Access Recognition Docs" ON storage.objects FOR SELECT USING (bucket_id = 'recognition-docs');

DROP POLICY IF EXISTS "Public Upload Recognition Docs" ON storage.objects;
CREATE POLICY "Public Upload Recognition Docs" ON storage.objects FOR INSERT WITH CHECK (bucket_id = 'recognition-docs');

DROP POLICY IF EXISTS "Public Update Recognition Docs" ON storage.objects;
CREATE POLICY "Public Update Recognition Docs" ON storage.objects FOR UPDATE WITH CHECK (bucket_id = 'recognition-docs');

DROP POLICY IF EXISTS "Public Delete Recognition Docs" ON storage.objects;
CREATE POLICY "Public Delete Recognition Docs" ON storage.objects FOR DELETE USING (bucket_id = 'recognition-docs');

-- Bucket for logistics supply-chain documents (LOG1)
INSERT INTO storage.buckets (id, name, public)
VALUES ('logistics_docs', 'logistics_docs', true)
ON CONFLICT (id) DO UPDATE SET public = true;

-- =====================================================
-- ESS (EMPLOYEE SELF-SERVICE) WORKFLOW MIGRATION
-- Full multi-step leave request approval workflow
-- =====================================================

-- Extended leave_requests table for full ESS workflow
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS document_url TEXT;
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS workflow_step VARCHAR(50) DEFAULT 'Supervisor Review';

-- Step 1: Supervisor review
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS supervisor_id INTEGER REFERENCES users(id);
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS supervisor_decision VARCHAR(20);
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS supervisor_notes TEXT;
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS supervisor_decided_at TIMESTAMP;

-- Step 2: HR / Payroll validation
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS hr_validated BOOLEAN DEFAULT FALSE;
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS hr_validated_by INTEGER REFERENCES users(id);
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS hr_validated_at TIMESTAMP;
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS hr_notes TEXT;

-- Step 3: Final decision
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS final_decision VARCHAR(20);
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS final_decided_by INTEGER REFERENCES users(id);
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS final_decided_at TIMESTAMP;

-- Archive
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS is_archived BOOLEAN DEFAULT FALSE;
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP;

-- Bucket for ESS supporting documents (medical certs, etc.)
INSERT INTO storage.buckets (id, name, public)
VALUES ('ess-documents', 'ess-documents', true)
ON CONFLICT (id) DO UPDATE SET public = true;

DROP POLICY IF EXISTS "Public Access ESS Docs" ON storage.objects;
CREATE POLICY "Public Access ESS Docs" ON storage.objects FOR SELECT USING (bucket_id = 'ess-documents');

DROP POLICY IF EXISTS "Public Upload ESS Docs" ON storage.objects;
CREATE POLICY "Public Upload ESS Docs" ON storage.objects FOR INSERT WITH CHECK (bucket_id = 'ess-documents');

DROP POLICY IF EXISTS "Public Update ESS Docs" ON storage.objects;
CREATE POLICY "Public Update ESS Docs" ON storage.objects FOR UPDATE WITH CHECK (bucket_id = 'ess-documents');

DROP POLICY IF EXISTS "Public Delete ESS Docs" ON storage.objects;
CREATE POLICY "Public Delete ESS Docs" ON storage.objects FOR DELETE USING (bucket_id = 'ess-documents');

-- =====================================================
-- HR3 MISSING FEATURES MIGRATION
-- Overtime, Schedule Change Requests, Reimbursements
-- =====================================================

-- 1. Overtime tracking on attendance_logs
ALTER TABLE IF EXISTS attendance_logs ADD COLUMN IF NOT EXISTS overtime_hours DECIMAL(4,2) DEFAULT 0.00;

-- 2. Schedule Change Requests
CREATE TABLE IF NOT EXISTS schedule_change_requests (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    current_day VARCHAR(20),
    current_start TIME,
    current_end TIME,
    requested_day VARCHAR(20),
    requested_start TIME,
    requested_end TIME,
    reason TEXT,
    status VARCHAR(20) DEFAULT 'Pending', -- Pending, Approved, Rejected
    reviewed_by INTEGER REFERENCES users(id),
    reviewed_at TIMESTAMP,
    reviewer_notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

ALTER TABLE IF EXISTS schedule_change_requests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on schedule_change_requests" ON schedule_change_requests;
CREATE POLICY "Allow all on schedule_change_requests" ON schedule_change_requests FOR ALL USING (true) WITH CHECK (true);

-- 3. Reimbursement Claims
CREATE TABLE IF NOT EXISTS reimbursement_claims (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    claim_type VARCHAR(50),           -- Travel, Medical, Meal, Equipment, Other
    amount DECIMAL(12,2) NOT NULL,
    receipt_url TEXT,
    description TEXT,
    expense_date DATE,
    status VARCHAR(20) DEFAULT 'Pending', -- Pending, HR Approved, Finance Approved, Rejected, Paid
    workflow_step VARCHAR(50) DEFAULT 'HR Review', -- HR Review, Finance Review, Completed
    hr_approved_by INTEGER REFERENCES users(id),
    hr_approved_at TIMESTAMP,
    hr_notes TEXT,
    finance_approved_by INTEGER REFERENCES users(id),
    finance_approved_at TIMESTAMP,
    finance_notes TEXT,
    is_archived BOOLEAN DEFAULT FALSE,
    archived_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

ALTER TABLE IF EXISTS reimbursement_claims ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on reimbursement_claims" ON reimbursement_claims;
CREATE POLICY "Allow all on reimbursement_claims" ON reimbursement_claims FOR ALL USING (true) WITH CHECK (true);

-- 4. Storage bucket for receipts
INSERT INTO storage.buckets (id, name, public)
VALUES ('receipts', 'receipts', true)
ON CONFLICT (id) DO UPDATE SET public = true;

DROP POLICY IF EXISTS "Public Access Receipts" ON storage.objects;
CREATE POLICY "Public Access Receipts" ON storage.objects FOR SELECT USING (bucket_id = 'receipts');

DROP POLICY IF EXISTS "Public Upload Receipts" ON storage.objects;
CREATE POLICY "Public Upload Receipts" ON storage.objects FOR INSERT WITH CHECK (bucket_id = 'receipts');

DROP POLICY IF EXISTS "Public Update Receipts" ON storage.objects;
CREATE POLICY "Public Update Receipts" ON storage.objects FOR UPDATE WITH CHECK (bucket_id = 'receipts');

DROP POLICY IF EXISTS "Public Delete Receipts" ON storage.objects;
CREATE POLICY "Public Delete Receipts" ON storage.objects FOR DELETE USING (bucket_id = 'receipts');

-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Reimbursement payment method tracking
-- Run this if reimbursement_claims table already exists in your database
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE reimbursement_claims
    ADD COLUMN IF NOT EXISTS payment_method VARCHAR(50),       -- 'Direct Payment' | 'Payroll'
    ADD COLUMN IF NOT EXISTS payroll_included BOOLEAN DEFAULT FALSE; -- TRUE once included in a payroll run
