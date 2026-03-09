-- =====================================================
-- HR1 MODULE FEATURES — DATABASE MIGRATION
-- Hospital Management System
-- Features: Role Separation, Employee Portal,
--           Performance Management, Social Recognition
-- =====================================================
-- Run this script in Supabase SQL Editor AFTER supabase_setup.sql

-- =====================================================
-- FEATURE 1: ACCOUNT ROLE SEPARATION
-- =====================================================

-- Note: We do NOT add a CHECK constraint on users.role because the
-- existing system uses flexible string roles across all subsystems.
-- Role enforcement is handled at the application layer via role_guards.py.

-- =====================================================
-- FEATURE 2: EMPLOYEE PORTAL — ANNOUNCEMENTS & TASKS
-- =====================================================

-- Company Announcements
CREATE TABLE IF NOT EXISTS announcements (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    priority VARCHAR(20) DEFAULT 'Normal',   -- Normal, Important, Urgent
    target_department VARCHAR(50),            -- NULL = all departments
    target_subsystem VARCHAR(20),             -- NULL = all subsystems
    published_by INTEGER REFERENCES users(id),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Employee Tasks / Pending Actions
CREATE TABLE IF NOT EXISTS employee_tasks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    task_type VARCHAR(50) DEFAULT 'general',  -- kpi_acknowledge, evaluation, onboarding, recognition, general
    reference_id INTEGER,                      -- FK to related record
    reference_table VARCHAR(50),               -- e.g., 'probation_cycles', 'recognition_nominations'
    status VARCHAR(20) DEFAULT 'Pending',      -- Pending, Completed, Dismissed
    due_date DATE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- RLS for Feature 2
ALTER TABLE IF EXISTS announcements ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on announcements" ON announcements;
CREATE POLICY "Allow all on announcements" ON announcements FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS employee_tasks ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on employee_tasks" ON employee_tasks;
CREATE POLICY "Allow all on employee_tasks" ON employee_tasks FOR ALL USING (true) WITH CHECK (true);

-- Indexes for Feature 2
CREATE INDEX IF NOT EXISTS idx_announcements_active ON announcements(is_active);
CREATE INDEX IF NOT EXISTS idx_announcements_dept ON announcements(target_department);
CREATE INDEX IF NOT EXISTS idx_employee_tasks_user ON employee_tasks(user_id);
CREATE INDEX IF NOT EXISTS idx_employee_tasks_status ON employee_tasks(status);

-- =====================================================
-- FEATURE 3: PERFORMANCE MANAGEMENT (PROBATIONARY CYCLE)
-- =====================================================

-- Probation Tracker
CREATE TABLE IF NOT EXISTS probation_cycles (
    id SERIAL PRIMARY KEY,
    employee_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    supervisor_id INTEGER REFERENCES users(id),
    cycle_type VARCHAR(30) DEFAULT 'New Hire',   -- New Hire, Promotion, Transfer, Reassignment
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    current_stage VARCHAR(50) DEFAULT 'ASSIGNED',
    status VARCHAR(30) DEFAULT 'Active',          -- Active, Completed, Extended, Terminated
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- KPI Definitions per Probation Cycle
CREATE TABLE IF NOT EXISTS probation_kpis (
    id SERIAL PRIMARY KEY,
    cycle_id INTEGER REFERENCES probation_cycles(id) ON DELETE CASCADE,
    category VARCHAR(50),            -- Job-Specific, Competency, Attendance, Patient Safety
    kpi_name VARCHAR(200) NOT NULL,
    description TEXT,
    target_value VARCHAR(100),
    weight DECIMAL(5,2) DEFAULT 0,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- KPI Acknowledgement
CREATE TABLE IF NOT EXISTS kpi_acknowledgements (
    id SERIAL PRIMARY KEY,
    cycle_id INTEGER REFERENCES probation_cycles(id) ON DELETE CASCADE,
    employee_id INTEGER REFERENCES users(id),
    acknowledged_at TIMESTAMP,
    digital_signature TEXT,          -- Employee typed name as signature
    status VARCHAR(20) DEFAULT 'Pending',  -- Pending, Acknowledged
    created_at TIMESTAMP DEFAULT NOW()
);

-- Performance Notes Log
CREATE TABLE IF NOT EXISTS performance_notes (
    id SERIAL PRIMARY KEY,
    cycle_id INTEGER REFERENCES probation_cycles(id) ON DELETE CASCADE,
    author_id INTEGER REFERENCES users(id),
    note_type VARCHAR(50),           -- Coaching, Commendation, Incident, Disciplinary
    content TEXT NOT NULL,
    is_published BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Mid-Probation Check-in
CREATE TABLE IF NOT EXISTS mid_probation_checkins (
    id SERIAL PRIMARY KEY,
    cycle_id INTEGER REFERENCES probation_cycles(id) ON DELETE CASCADE,
    supervisor_id INTEGER REFERENCES users(id),
    gap_analysis TEXT,
    improvement_plan TEXT,
    overall_rating VARCHAR(30),      -- On Track, Needs Improvement, At Risk
    completed_at TIMESTAMP DEFAULT NOW()
);

-- Final Evaluation
CREATE TABLE IF NOT EXISTS final_evaluations (
    id SERIAL PRIMARY KEY,
    cycle_id INTEGER REFERENCES probation_cycles(id) ON DELETE CASCADE,
    evaluator_id INTEGER REFERENCES users(id),
    kpi_scores JSONB DEFAULT '[]'::jsonb,
    competency_rating DECIMAL(3,1),
    conduct_rating DECIMAL(3,1),
    attendance_rating DECIMAL(3,1),
    overall_score DECIMAL(3,1),
    comments TEXT,
    completed_at TIMESTAMP DEFAULT NOW()
);

-- Supervisor Recommendations
CREATE TABLE IF NOT EXISTS probation_recommendations (
    id SERIAL PRIMARY KEY,
    cycle_id INTEGER REFERENCES probation_cycles(id) ON DELETE CASCADE,
    supervisor_id INTEGER REFERENCES users(id),
    recommendation VARCHAR(50),      -- Regularize, Extend, Reassign, Terminate
    justification TEXT,
    submitted_at TIMESTAMP DEFAULT NOW()
);

-- HR Final Decision
CREATE TABLE IF NOT EXISTS hr_decisions (
    id SERIAL PRIMARY KEY,
    cycle_id INTEGER REFERENCES probation_cycles(id) ON DELETE CASCADE,
    hr_officer_id INTEGER REFERENCES users(id),
    decision VARCHAR(50),            -- Regularize, Extend, Reassign, Terminate
    modified_from VARCHAR(50),       -- Original recommendation if changed
    notice_document_url TEXT,
    effective_date DATE,
    notes TEXT,
    decided_at TIMESTAMP DEFAULT NOW()
);

-- RLS for Feature 3
ALTER TABLE IF EXISTS probation_cycles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on probation_cycles" ON probation_cycles;
CREATE POLICY "Allow all on probation_cycles" ON probation_cycles FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS probation_kpis ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on probation_kpis" ON probation_kpis;
CREATE POLICY "Allow all on probation_kpis" ON probation_kpis FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS kpi_acknowledgements ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on kpi_acknowledgements" ON kpi_acknowledgements;
CREATE POLICY "Allow all on kpi_acknowledgements" ON kpi_acknowledgements FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS performance_notes ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on performance_notes" ON performance_notes;
CREATE POLICY "Allow all on performance_notes" ON performance_notes FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS mid_probation_checkins ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on mid_probation_checkins" ON mid_probation_checkins;
CREATE POLICY "Allow all on mid_probation_checkins" ON mid_probation_checkins FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS final_evaluations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on final_evaluations" ON final_evaluations;
CREATE POLICY "Allow all on final_evaluations" ON final_evaluations FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS probation_recommendations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on probation_recommendations" ON probation_recommendations;
CREATE POLICY "Allow all on probation_recommendations" ON probation_recommendations FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS hr_decisions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on hr_decisions" ON hr_decisions;
CREATE POLICY "Allow all on hr_decisions" ON hr_decisions FOR ALL USING (true) WITH CHECK (true);

-- Indexes for Feature 3
CREATE INDEX IF NOT EXISTS idx_probation_cycles_employee ON probation_cycles(employee_id);
CREATE INDEX IF NOT EXISTS idx_probation_cycles_supervisor ON probation_cycles(supervisor_id);
CREATE INDEX IF NOT EXISTS idx_probation_cycles_status ON probation_cycles(status);
CREATE INDEX IF NOT EXISTS idx_probation_cycles_stage ON probation_cycles(current_stage);
CREATE INDEX IF NOT EXISTS idx_probation_kpis_cycle ON probation_kpis(cycle_id);
CREATE INDEX IF NOT EXISTS idx_kpi_acknowledgements_cycle ON kpi_acknowledgements(cycle_id);
CREATE INDEX IF NOT EXISTS idx_performance_notes_cycle ON performance_notes(cycle_id);
CREATE INDEX IF NOT EXISTS idx_mid_probation_checkins_cycle ON mid_probation_checkins(cycle_id);
CREATE INDEX IF NOT EXISTS idx_final_evaluations_cycle ON final_evaluations(cycle_id);
CREATE INDEX IF NOT EXISTS idx_probation_recommendations_cycle ON probation_recommendations(cycle_id);
CREATE INDEX IF NOT EXISTS idx_hr_decisions_cycle ON hr_decisions(cycle_id);

-- Periodic KPI Progress Logs (during MONITORING stage)
CREATE TABLE IF NOT EXISTS probation_kpi_progress (
    id SERIAL PRIMARY KEY,
    cycle_id INTEGER REFERENCES probation_cycles(id) ON DELETE CASCADE,
    kpi_id INTEGER REFERENCES probation_kpis(id) ON DELETE CASCADE,
    logged_by INTEGER REFERENCES users(id),
    score NUMERIC(4,2) NOT NULL,
    notes TEXT,
    logged_at TIMESTAMP DEFAULT NOW()
);

ALTER TABLE IF EXISTS probation_kpi_progress ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on probation_kpi_progress" ON probation_kpi_progress;
CREATE POLICY "Allow all on probation_kpi_progress" ON probation_kpi_progress FOR ALL USING (true) WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_kpi_progress_cycle ON probation_kpi_progress(cycle_id);
CREATE INDEX IF NOT EXISTS idx_kpi_progress_kpi ON probation_kpi_progress(kpi_id);

-- =====================================================
-- FEATURE 4: SOCIAL RECOGNITION MODULE
-- =====================================================

-- Recognition Types (admin-configurable)
CREATE TABLE IF NOT EXISTS recognition_types (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    icon VARCHAR(50) DEFAULT 'award',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Nominations
CREATE TABLE IF NOT EXISTS recognition_nominations (
    id SERIAL PRIMARY KEY,
    nominee_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    nominator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    recognition_type_id INTEGER REFERENCES recognition_types(id),
    justification TEXT NOT NULL,
    supporting_details TEXT,
    attachment_url TEXT,
    status VARCHAR(30) DEFAULT 'Pending',     -- Pending, Approved, Rejected, Auto-Rejected
    supervisor_id INTEGER REFERENCES users(id),
    reviewed_at TIMESTAMP,
    review_notes TEXT,
    auto_reject_date DATE,                     -- created_at + 30 days
    created_at TIMESTAMP DEFAULT NOW()
);

-- RLS for Feature 4
ALTER TABLE IF EXISTS recognition_types ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on recognition_types" ON recognition_types;
CREATE POLICY "Allow all on recognition_types" ON recognition_types FOR ALL USING (true) WITH CHECK (true);

ALTER TABLE IF EXISTS recognition_nominations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Allow all on recognition_nominations" ON recognition_nominations;
CREATE POLICY "Allow all on recognition_nominations" ON recognition_nominations FOR ALL USING (true) WITH CHECK (true);

-- Indexes for Feature 4
CREATE INDEX IF NOT EXISTS idx_recognition_nominations_status ON recognition_nominations(status);
CREATE INDEX IF NOT EXISTS idx_recognition_nominations_nominee ON recognition_nominations(nominee_id);
CREATE INDEX IF NOT EXISTS idx_recognition_nominations_nominator ON recognition_nominations(nominator_id);
CREATE INDEX IF NOT EXISTS idx_recognition_nominations_supervisor ON recognition_nominations(supervisor_id);
CREATE INDEX IF NOT EXISTS idx_recognition_types_active ON recognition_types(is_active);

-- Seed default recognition types
INSERT INTO recognition_types (name, description, icon) VALUES
    ('Team Award', 'Outstanding team collaboration and achievement', 'people-fill'),
    ('Perfect Attendance', 'Zero absences for the evaluation period', 'calendar-check-fill'),
    ('Service Award', 'Years of dedicated service to the institution', 'award-fill'),
    ('Employee of the Month', 'Exceptional performance and dedication', 'star-fill')
ON CONFLICT DO NOTHING;

-- =====================================================
-- ADDENDUM: WORKFLOW DIAGRAM ALIGNMENT
-- (Run this after the initial setup if upgrading)
-- =====================================================

-- Widen status column to accommodate multi-level approval status values
-- (Supervisor_Approved, Management_Pending, Management_Rejected, HR_Rejected, Returned)
ALTER TABLE IF EXISTS recognition_nominations
    ALTER COLUMN status TYPE VARCHAR(50);

-- Performance Management: IMPROVEMENT_PLAN stage is handled entirely at the
-- application layer (utils/probation_engine.py). No schema changes required —
-- the existing probation_cycles.current_stage VARCHAR(50) and
-- mid_probation_checkins.improvement_plan TEXT columns already support it.
-- The improvement plan acknowledgement and HR review are tracked via
-- performance_notes with note_type IN ('IP_Acknowledged','IP_HR_Approved','IP_HR_Rejected').

-- Social Recognition: New multi-level nomination status values:
--   Pending            → Awaiting supervisor review (30-day auto-reject deadline)
--   Returned           → Supervisor returned to nominator for revision
--   Supervisor_Approved→ Supervisor approved; forwarded to HR for validation
--   HR_Rejected        → HR rejected during policy validation
--   Management_Pending → HR validated; awaiting Management/Committee decision
--   Management_Rejected→ Management committee rejected the nomination
--   Approved           → Fully approved; featured on Wall of Fame
--   Auto-Rejected      → System auto-rejected after 30-day supervisor inaction

-- Index for new multi-level status routing
CREATE INDEX IF NOT EXISTS idx_recognition_nominations_supervisor_pending
    ON recognition_nominations(supervisor_id, status);

-- =====================================================
-- STORAGE: Create the recognition-docs bucket
-- In Supabase Dashboard → Storage → New Bucket:
--   Name: recognition-docs
--   Public: true  (so reviewers can open the file URL directly)
-- Or run via Supabase Management API / psql (storage schema):
-- INSERT INTO storage.buckets (id, name, public) VALUES ('recognition-docs', 'recognition-docs', true) ON CONFLICT DO NOTHING;
-- =====================================================
