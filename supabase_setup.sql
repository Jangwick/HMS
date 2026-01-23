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
    
    CONSTRAINT unique_username_per_subsystem UNIQUE (username, subsystem),
    CONSTRAINT unique_email_per_subsystem UNIQUE (email, subsystem)
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
    status VARCHAR(50) DEFAULT 'Screening', -- Screening, Interview, Offer, Handoff
    documents JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vacancies (
    id SERIAL PRIMARY KEY,
    position_name VARCHAR(100) NOT NULL,
    department VARCHAR(50),
    reason VARCHAR(100), -- Replacement, New position, New service
    requirements TEXT,
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
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- CT3: Bed Management
CREATE TABLE IF NOT EXISTS beds (
    id SERIAL PRIMARY KEY,
    room_number VARCHAR(20),
    ward_name VARCHAR(50),
    type VARCHAR(50), -- ICU, Regular, Isolation
    status VARCHAR(50) DEFAULT 'Available' -- Available, Occupied, Cleaning
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
-- FINANCIAL TABLES
-- =====================================================

CREATE TABLE IF NOT EXISTS billing_records (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id),
    total_amount DECIMAL(12, 2) DEFAULT 0.00,
    status VARCHAR(50) DEFAULT 'Unpaid', -- Unpaid, Paid, Partially Paid
    insurance_claim_status VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS general_ledger (
    id SERIAL PRIMARY KEY,
    account_code VARCHAR(20) UNIQUE,
    account_name VARCHAR(100) NOT NULL,
    balance DECIMAL(15, 2) DEFAULT 0.00,
    last_updated TIMESTAMP DEFAULT NOW()
);

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
ALTER TABLE IF EXISTS fleet_costs ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();
