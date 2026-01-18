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
    competency_id INTEGER REFERENCES competencies(id),
    assessment_date DATE DEFAULT CURRENT_DATE,
    level VARCHAR(50), -- Beginner, Intermediate, Expert
    assessor_id INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS trainings (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    type VARCHAR(100), -- Mandatory, Role-based
    schedule_date TIMESTAMP,
    materials_url TEXT,
    status VARCHAR(50) DEFAULT 'Scheduled'
);

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
    approved_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

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
    reorder_level INTEGER DEFAULT 10,
    expiry_date DATE,
    batch_number VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
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
    vehicle_type VARCHAR(50), -- Ambulance, Service
    status VARCHAR(50) DEFAULT 'Available',
    last_service DATE
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
CREATE INDEX IF NOT EXISTS idx_billing_patient ON billing_records(patient_id);
