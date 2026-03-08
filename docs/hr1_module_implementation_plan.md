# HR1 Module — Implementation Plan
## Hospital Management System (HMS)
**Date:** March 9, 2026  
**Author:** System Architect  
**Module:** HR1 — Personnel Management  
**Tech Stack:** Flask + Supabase (PostgreSQL) + Jinja2 Templates  

---

## Table of Contents
1. [Codebase Analysis Summary](#1-codebase-analysis-summary)
2. [Feature 1 — Account Role Separation](#2-feature-1--account-role-separation)
3. [Feature 2 — Employee Portal / Personal Dashboard](#3-feature-2--employee-portal--personal-dashboard)
4. [Feature 3 — Performance Management (Probationary Cycle)](#4-feature-3--performance-management-probationary-cycle)
5. [Feature 4 — Social Recognition Module](#5-feature-4--social-recognition-module)
6. [Database Migration Script](#6-database-migration-script)
7. [Implementation Order & Dependencies](#7-implementation-order--dependencies)

---

## 1. Codebase Analysis Summary

### Current Architecture
| Layer | Technology | Key Files |
|-------|-----------|-----------|
| **Backend** | Flask (Python) | `app.py`, `routes/hr/hr1.py` |
| **Database** | Supabase (PostgreSQL) | `supabase_setup.sql` |
| **Auth** | Flask-Login + Supabase `users` table | `utils/supabase_client.py` → `User` class |
| **Templates** | Jinja2 + Bootstrap | `templates/subsystems/hr/hr1/` |
| **Security** | `HMSFundamentalsPolicy` decorator | `utils/policy.py` → `policy_required()` |
| **Models** | Supabase-backed classes | `utils/hms_models.py` |
| **Notifications** | DB-backed system | `utils/hms_models.py` → `Notification` class |

### Current User Role System
```python
# utils/supabase_client.py — User.role_level property
levels = {
    'Staff': 1,
    'Manager': 2,
    'Admin': 3,
    'Administrator': 3,
    'SuperAdmin': 99
}
```

### Current HR1 Tables
- `users` — single shared table, column `subsystem = 'hr1'`
- `applicants` — recruitment candidates
- `vacancies` — job postings
- `interviews` — scheduled interviews (FK → `users.id` for interviewer)
- `onboarding` — handoff records to HR2

### Key Patterns Identified
1. **Blueprint pattern:** Each route file defines `SUBSYSTEM_NAME`, `ACCENT_COLOR`, `SUBSYSTEM_ICON`, `BLUEPRINT_NAME`
2. **Auth guards:** `@login_required` + `@policy_required(BLUEPRINT_NAME)`
3. **Admin checks:** `if not current_user.is_admin(): flash(...)` inline
4. **DB access:** Direct Supabase client calls (`get_supabase_client()`)
5. **Audit logging:** `AuditLog.log(user_id, action, subsystem, details)`
6. **Notifications:** `Notification.create(subsystem=..., title=..., message=...)`
7. **Template context:** All routes pass `subsystem_name`, `accent_color`, `blueprint_name`
8. **Template base:** All subsystem templates extend `base/subsystem_base.html`

### ⚠️ Current Problem Identified
The `interviews` table uses `interviewer_id INTEGER REFERENCES users(id)` — **any user from any subsystem** can be assigned as an interviewer. There is NO role-based guard preventing applicant-type accounts from being assigned interviewer duties. The `users.role` column currently only has `Staff`, `Manager`, `Admin`, `Administrator`, `SuperAdmin`.

---

## 2. Feature 1 — Account Role Separation

### Problem Statement
Applicant accounts (created during recruitment) are being reused as HR Staff/Interviewers. The system must enforce strict separation between account types.

### Affected Files

| Action | File Path |
|--------|-----------|
| **Modify** | `utils/supabase_client.py` — Add new role constants + validation helpers |
| **Modify** | `routes/hr/hr1.py` — Add role guards on interview routes |
| **Modify** | `utils/hms_models.py` — Update `Interview.create()` with role validation |
| **Modify** | `supabase_setup.sql` — Migration for role column constraint |
| **Create** | `utils/role_guards.py` — Centralized role checking decorators |
| **Modify** | `templates/subsystems/hr/hr1/schedule_interview.html` — Hide UI for non-staff |
| **Modify** | `templates/subsystems/hr/hr1/interviews.html` — Conditional rendering |

### Implementation Details

#### 2.1 Role Constants & Enum
```python
# utils/supabase_client.py — Add at top-level

class HRRoles:
    """Strict role definitions for the HR module."""
    APPLICANT = 'Applicant'
    HR_STAFF = 'HR_Staff'
    INTERVIEWER = 'Interviewer'
    MANAGER = 'Manager'
    ADMIN = 'Admin'
    SUPER_ADMIN = 'SuperAdmin'

    # Roles allowed to perform interviewer duties
    INTERVIEWER_CAPABLE = [HR_STAFF, INTERVIEWER, MANAGER, ADMIN, SUPER_ADMIN]

    # Roles that are strictly applicant-level (cannot access HR functions)
    APPLICANT_ONLY = [APPLICANT]

    @staticmethod
    def can_interview(role: str) -> bool:
        return role in HRRoles.INTERVIEWER_CAPABLE

    @staticmethod
    def is_applicant(role: str) -> bool:
        return role == HRRoles.APPLICANT
```

#### 2.2 Role Guard Decorator
```python
# utils/role_guards.py — NEW FILE

from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user

def hr_role_required(*allowed_roles):
    """Decorator that restricts access to specific HR roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('hr1.login'))
            if current_user.role not in allowed_roles and not current_user.is_super_admin():
                flash('Access denied: insufficient role privileges.', 'danger')
                return redirect(url_for('hr1.dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def prevent_applicant_access(f):
    """Blocks any user with Applicant role from accessing the route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.role == 'Applicant':
            flash('Applicant accounts cannot access HR staff functions.', 'danger')
            return redirect(url_for('portal.index'))
        return f(*args, **kwargs)
    return decorated_function
```

#### 2.3 Route-Level Guards (routes/hr/hr1.py)
Apply to all interview-related routes:
- `schedule_interview()` — add `@hr_role_required('HR_Staff', 'Interviewer', 'Manager', 'Admin')`
- `schedule_interview_quick()` — same guard
- `update_interview_status()` — same guard
- `list_interviews()` — keep accessible but hide action buttons in template

#### 2.4 Applicant-to-Staff Transition (Handoff)
In `handoff_hr2()` route — when an applicant is hired:
- **DO NOT** convert the applicant's existing user account
- **CREATE** a new user record with role `HR_Staff` via `User.create()`
- Keep the applicant record intact for audit trail
- Link via `onboarding.applicant_id`

#### 2.5 Interview Validation
Modify `Interview.create()` in `utils/hms_models.py`:
```python
@staticmethod
def create(data: dict):
    # Validate that interviewer has appropriate role
    interviewer_id = data.get('interviewer_id')
    if interviewer_id:
        from utils.supabase_client import User, HRRoles
        interviewer = User.get_by_id(interviewer_id)
        if not interviewer or not HRRoles.can_interview(interviewer.role):
            raise ValueError("Selected interviewer does not have interviewer privileges.")
    # ... proceed with insert
```

#### 2.6 Database Migration
```sql
-- Add CHECK constraint for role values
ALTER TABLE users DROP CONSTRAINT IF EXISTS check_user_role;
ALTER TABLE users ADD CONSTRAINT check_user_role
    CHECK (role IN ('Staff', 'HR_Staff', 'Interviewer', 'Manager', 'Admin', 'Administrator', 'SuperAdmin', 'Applicant'));
```

#### 2.7 Template Changes
In `schedule_interview.html` — the interviewer dropdown must only show users with `HR_Staff` or `Interviewer` roles:
```python
# In route: filter interviewers query
interviewers = client.table('users').select('id, username, role').eq('subsystem', 'hr1') \
    .in_('role', ['HR_Staff', 'Interviewer', 'Manager', 'Admin']).execute().data
```

### Acceptance Criteria Mapping
| Criterion | Implementation |
|-----------|---------------|
| ✅ Role enum/constants | `HRRoles` class in `supabase_client.py` |
| ✅ Middleware blocks applicants | `role_guards.py` decorators on routes |
| ✅ UI hides interviewer scheduling | Template conditional `{% if current_user.role not in ['Applicant'] %}` |
| ✅ Migration reflects role structure | SQL `CHECK` constraint + seed data update |

---

## 3. Feature 2 — Employee Portal / Personal Dashboard

### Affected Files

| Action | File Path |
|--------|-----------|
| **Modify** | `routes/hr/hr1.py` — Add/modify dashboard route with widget data |
| **Create** | `templates/subsystems/hr/hr1/employee_dashboard.html` — New dashboard template |
| **Modify** | `utils/hms_models.py` — Add dashboard data helpers |
| **Modify** | `supabase_setup.sql` — Add `announcements` table, `employee_tasks` table |

### Implementation Details

#### 3.1 New Database Tables
```sql
-- Company Announcements
CREATE TABLE IF NOT EXISTS announcements (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    priority VARCHAR(20) DEFAULT 'Normal',  -- Normal, Important, Urgent
    target_department VARCHAR(50),           -- NULL = all departments
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
    task_type VARCHAR(50),     -- 'kpi_acknowledge', 'evaluation', 'onboarding', 'general'
    reference_id INTEGER,       -- FK to related record (e.g., kpi_id, evaluation_id)
    reference_table VARCHAR(50),
    status VARCHAR(20) DEFAULT 'Pending',  -- Pending, Completed, Dismissed
    due_date DATE,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### 3.2 Dashboard Route Logic
```python
@hr1_bp.route('/dashboard')
@login_required
@policy_required(BLUEPRINT_NAME)
def dashboard():
    client = get_supabase_client()
    user = current_user

    # 1. Welcome banner data (already available via current_user)
    # user.full_name, user.role, user.department

    # 2. Quick links (static, role-based)
    quick_links = [
        {'label': 'My Schedule', 'icon': 'calendar3', 'url': url_for('hr3.my_schedule')},
        {'label': 'Leave Requests', 'icon': 'calendar-x', 'url': url_for('hr3.leave_requests')},
        {'label': 'My KPIs', 'icon': 'graph-up', 'url': url_for('hr1.my_kpis')},
        {'label': 'Payslip', 'icon': 'cash-stack', 'url': url_for('hr4.my_payslip')},
    ]

    # 3. Announcements feed
    announcements = client.table('announcements').select('*') \
        .eq('is_active', True).order('created_at', desc=True).limit(5).execute().data or []

    # 4. Pending tasks
    tasks = client.table('employee_tasks').select('*') \
        .eq('user_id', user.id).eq('status', 'Pending') \
        .order('due_date').limit(10).execute().data or []

    # 5. Notifications (already injected via context processor)

    # 6. Supervisor widgets (role-based)
    team_data = None
    if user.role in ['Manager', 'Admin', 'Administrator', 'SuperAdmin']:
        team_data = client.table('users').select('id, full_name, role, status') \
            .eq('department', user.department).neq('id', user.id).execute().data or []

    # 7. Onboarding checklist (for new hires)
    onboarding_status = None
    onboarding_resp = client.table('onboarding').select('*') \
        .eq('status', 'In Progress').execute()
    # Match by name or linked applicant_id if available

    # Existing HR1 stats
    vacancies_count = client.table('vacancies').select('id', count='exact') \
        .eq('status', 'Open').execute().count
    applicants_count = client.table('applicants').select('id', count='exact').execute().count

    return render_template('subsystems/hr/hr1/employee_dashboard.html',
        quick_links=quick_links,
        announcements=announcements,
        pending_tasks=tasks,
        team_data=team_data,
        onboarding_status=onboarding_status,
        vacancies_count=vacancies_count,
        applicants_count=applicants_count,
        subsystem_name=SUBSYSTEM_NAME,
        accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME)
```

#### 3.3 Template Structure — `employee_dashboard.html`
```
{% extends "base/subsystem_base.html" %}
{% block content %}
  ┌──────────────────────────────────────────────────┐
  │  Welcome Banner (name, position, department)     │
  ├──────────────────┬───────────────────────────────┤
  │  Quick Links     │  Announcements Feed           │
  │  (4 card grid)   │  (scrollable list)            │
  ├──────────────────┴───────────────────────────────┤
  │  My Pending Tasks / Actions                      │
  ├──────────────────────────────────────────────────┤
  │  [IF Manager+] Team Performance Widgets          │
  ├──────────────────────────────────────────────────┤
  │  [IF New Hire] Onboarding Checklist              │
  └──────────────────────────────────────────────────┘
{% endblock %}
```

### Acceptance Criteria Mapping
| Criterion | Implementation |
|-----------|---------------|
| ✅ Dashboard protected by auth | `@login_required` + `@policy_required` |
| ✅ Data from existing APIs | Supabase queries for announcements, tasks, notifications |
| ✅ New hire onboarding widget | Conditional `onboarding` table check |

---

## 4. Feature 3 — Performance Management (Probationary Cycle)

### Process Flow — State Machine
```
ASSIGNED → KPI_SETUP → KPI_ACKNOWLEDGED → MONITORING →
MID_CHECK_IN → DOCUMENTATION → FINAL_EVALUATION →
RECOMMENDATION → HR_DECISION
```

### New Database Tables

```sql
-- Probation Tracker
CREATE TABLE IF NOT EXISTS probation_cycles (
    id SERIAL PRIMARY KEY,
    employee_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    supervisor_id INTEGER REFERENCES users(id),
    cycle_type VARCHAR(30) DEFAULT 'New Hire',   -- New Hire, Promotion, Transfer, Reassignment
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,                       -- Auto-calculated: start + 90 days
    current_stage VARCHAR(50) DEFAULT 'ASSIGNED',
    status VARCHAR(30) DEFAULT 'Active',          -- Active, Completed, Extended, Terminated
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- KPI Definitions per Probation Cycle
CREATE TABLE IF NOT EXISTS probation_kpis (
    id SERIAL PRIMARY KEY,
    cycle_id INTEGER REFERENCES probation_cycles(id) ON DELETE CASCADE,
    category VARCHAR(50),           -- Job-Specific, Competency, Attendance, Patient Safety
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
    status VARCHAR(20) DEFAULT 'Pending'  -- Pending, Acknowledged
);

-- Performance Notes Log
CREATE TABLE IF NOT EXISTS performance_notes (
    id SERIAL PRIMARY KEY,
    cycle_id INTEGER REFERENCES probation_cycles(id) ON DELETE CASCADE,
    author_id INTEGER REFERENCES users(id),
    note_type VARCHAR(50),          -- Coaching, Commendation, Incident, Disciplinary
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
    overall_rating VARCHAR(30),     -- On Track, Needs Improvement, At Risk
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
```

### Affected Files

| Action | File Path |
|--------|-----------|
| **Create** | `utils/probation_engine.py` — State machine + workflow logic |
| **Modify** | `routes/hr/hr1.py` — Add 10+ probation routes |
| **Modify** | `utils/hms_models.py` — Add model classes for probation tables |
| **Create** | `templates/subsystems/hr/hr1/probation/` — 7 template files |
| **Modify** | `supabase_setup.sql` — 8 new tables |

### State Machine Implementation
```python
# utils/probation_engine.py

class ProbationStage:
    ASSIGNED = 'ASSIGNED'
    KPI_SETUP = 'KPI_SETUP'
    KPI_ACKNOWLEDGED = 'KPI_ACKNOWLEDGED'
    MONITORING = 'MONITORING'
    MID_CHECK_IN = 'MID_CHECK_IN'
    DOCUMENTATION = 'DOCUMENTATION'
    FINAL_EVALUATION = 'FINAL_EVALUATION'
    RECOMMENDATION = 'RECOMMENDATION'
    HR_DECISION = 'HR_DECISION'

STAGE_ORDER = [
    ProbationStage.ASSIGNED,
    ProbationStage.KPI_SETUP,
    ProbationStage.KPI_ACKNOWLEDGED,
    ProbationStage.MONITORING,
    ProbationStage.MID_CHECK_IN,
    ProbationStage.DOCUMENTATION,
    ProbationStage.FINAL_EVALUATION,
    ProbationStage.RECOMMENDATION,
    ProbationStage.HR_DECISION,
]

STAGE_TRANSITIONS = {
    'ASSIGNED': ['KPI_SETUP'],
    'KPI_SETUP': ['KPI_ACKNOWLEDGED'],
    'KPI_ACKNOWLEDGED': ['MONITORING'],
    'MONITORING': ['MID_CHECK_IN'],
    'MID_CHECK_IN': ['DOCUMENTATION'],
    'DOCUMENTATION': ['FINAL_EVALUATION'],
    'FINAL_EVALUATION': ['RECOMMENDATION'],
    'RECOMMENDATION': ['HR_DECISION'],
    'HR_DECISION': [],  # Terminal
}

def can_advance(current_stage: str, target_stage: str) -> bool:
    return target_stage in STAGE_TRANSITIONS.get(current_stage, [])

def advance_stage(cycle_id: int, target_stage: str, user_id: int):
    """Validate and advance the probation cycle to the next stage."""
    client = get_supabase_client()
    cycle = client.table('probation_cycles').select('*').eq('id', cycle_id).single().execute()
    if not cycle.data:
        raise ValueError("Probation cycle not found.")

    current = cycle.data['current_stage']
    if not can_advance(current, target_stage):
        raise ValueError(f"Cannot transition from {current} to {target_stage}")

    client.table('probation_cycles').update({
        'current_stage': target_stage,
        'updated_at': datetime.utcnow().isoformat()
    }).eq('id', cycle_id).execute()

    # Trigger stage-specific notifications
    _send_stage_notification(cycle.data, target_stage)
```

### Routes to Create
| Route | Method | Purpose |
|-------|--------|---------|
| `/probation` | GET | List all probation cycles |
| `/probation/create` | POST | Create new cycle |
| `/probation/<id>` | GET | View cycle detail + timeline |
| `/probation/<id>/kpis` | GET/POST | KPI builder |
| `/probation/<id>/acknowledge` | POST | Employee KPI acknowledgement |
| `/probation/<id>/notes` | GET/POST | Performance notes CRUD |
| `/probation/<id>/mid-checkin` | GET/POST | Mid-probation form |
| `/probation/<id>/evaluate` | GET/POST | Final evaluation form |
| `/probation/<id>/recommend` | POST | Supervisor recommendation |
| `/probation/<id>/decision` | POST | HR final decision |
| `/probation/<id>/notice` | GET | Download formal notice PDF |

### Templates to Create
```
templates/subsystems/hr/hr1/probation/
├── list.html                 # All probation cycles
├── detail.html               # Cycle detail + visual timeline
├── kpi_builder.html          # Create/edit KPIs
├── kpi_acknowledge.html      # Employee acknowledgement view
├── notes.html                # Performance notes log
├── mid_checkin.html           # Mid-probation check-in form
├── final_evaluation.html      # Final evaluation form
└── hr_decision.html           # HR review & decision form
```

### Acceptance Criteria Mapping
| Criterion | Implementation |
|-----------|---------------|
| ✅ Correct stage sequencing | `STAGE_TRANSITIONS` dict + `can_advance()` |
| ✅ Employee can't see draft notes | `is_published` boolean filter |
| ✅ All forms timestamped + linked | `cycle_id` FK + `created_at` timestamps |
| ✅ Downloadable notice | PDF generation from `hr_decisions` record |
| ✅ Auto-calculated end date | `start_date + INTERVAL '90 days'` |

---

## 5. Feature 4 — Social Recognition Module

### New Database Tables

```sql
-- Recognition Types (admin-configurable)
CREATE TABLE IF NOT EXISTS recognition_types (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,         -- Team Award, Perfect Attendance, etc.
    description TEXT,
    icon VARCHAR(50),
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
    status VARCHAR(30) DEFAULT 'Pending',  -- Pending, Approved, Rejected, Auto-Rejected
    supervisor_id INTEGER REFERENCES users(id),
    reviewed_at TIMESTAMP,
    review_notes TEXT,
    auto_reject_date DATE,                  -- created_at + 30 days
    created_at TIMESTAMP DEFAULT NOW()
);

-- Seed default recognition types
INSERT INTO recognition_types (name, description, icon) VALUES
('Team Award', 'Outstanding team collaboration', 'people-fill'),
('Perfect Attendance', 'Zero absences for the period', 'calendar-check-fill'),
('Service Award', 'Years of dedicated service', 'award-fill'),
('Employee of the Month', 'Exceptional performance', 'star-fill')
ON CONFLICT DO NOTHING;
```

### Affected Files

| Action | File Path |
|--------|-----------|
| **Modify** | `routes/hr/hr1.py` — Add 6+ recognition routes |
| **Create** | `templates/subsystems/hr/hr1/recognition/` — 4 template files |
| **Modify** | `utils/hms_models.py` — Add `RecognitionNomination` model class |
| **Modify** | `supabase_setup.sql` — 2 new tables |

### Routes to Create
| Route | Method | Purpose |
|-------|--------|---------|
| `/recognition` | GET | Wall of Fame + nomination list |
| `/recognition/nominate` | GET/POST | Nomination form |
| `/recognition/inbox` | GET | Supervisor approval inbox |
| `/recognition/<id>/approve` | POST | Approve nomination |
| `/recognition/<id>/reject` | POST | Reject nomination |
| `/recognition/types` | GET/POST | Admin: manage recognition types |

### Key Business Rules
1. **Self-nomination prevention:** Backend check `nominator_id != nominee_id`
2. **Auto-rejection cron:** Scheduled task or route-triggered check:
```python
def auto_reject_stale_nominations():
    """Called via cron or on page load to reject 30-day-old pending nominations."""
    client = get_supabase_client()
    cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()
    stale = client.table('recognition_nominations').select('id') \
        .eq('status', 'Pending').lt('created_at', cutoff).execute()
    if stale.data:
        for nom in stale.data:
            client.table('recognition_nominations').update({
                'status': 'Auto-Rejected',
                'reviewed_at': datetime.utcnow().isoformat(),
                'review_notes': 'Auto-rejected: No supervisor action within 30 days.'
            }).eq('id', nom['id']).execute()
            AuditLog.log(None, "Auto-Reject Nomination", "hr1", {"nomination_id": nom['id']})
```
3. **Notification triggers:**
   - On nomination submit → notify supervisor (in-app + email via `mail_system.py`)
   - On approval → notify nominator + nominee
   - On rejection → notify nominator

### Templates to Create
```
templates/subsystems/hr/hr1/recognition/
├── wall_of_fame.html         # Public recognition display
├── nominate.html             # Nomination form
├── inbox.html                # Supervisor approval queue
└── types_admin.html          # Admin: manage recognition types
```

### Acceptance Criteria Mapping
| Criterion | Implementation |
|-----------|---------------|
| ✅ Cannot self-nominate | Backend validation + form JS |
| ✅ Supervisor notifications | `Notification.create()` + `mail_system.py` |
| ✅ Auto-rejection at 30 days | `auto_reject_stale_nominations()` function |
| ✅ Approved on profile + wall | Query filter `status='Approved'` on wall page |

---

## 6. Database Migration Script

A single migration file combining all new tables:

**File:** `supabase_setup_hr1_features.sql`

This file will contain:
1. Role constraint on `users.role` column
2. `announcements` table
3. `employee_tasks` table
4. 8 probation-related tables (with indexes)
5. `recognition_types` table + seed data
6. `recognition_nominations` table
7. RLS policies for all new tables
8. Indexes on all foreign key columns

### Index Strategy
```sql
CREATE INDEX idx_probation_cycles_employee ON probation_cycles(employee_id);
CREATE INDEX idx_probation_cycles_supervisor ON probation_cycles(supervisor_id);
CREATE INDEX idx_probation_cycles_status ON probation_cycles(status);
CREATE INDEX idx_probation_kpis_cycle ON probation_kpis(cycle_id);
CREATE INDEX idx_performance_notes_cycle ON performance_notes(cycle_id);
CREATE INDEX idx_recognition_nominations_status ON recognition_nominations(status);
CREATE INDEX idx_recognition_nominations_nominee ON recognition_nominations(nominee_id);
CREATE INDEX idx_recognition_nominations_supervisor ON recognition_nominations(supervisor_id);
CREATE INDEX idx_employee_tasks_user ON employee_tasks(user_id);
CREATE INDEX idx_announcements_active ON announcements(is_active);
```

---

## 7. Implementation Order & Dependencies

```
 Phase 1: Feature 1 (Account Role Separation)
    ├── 1.1 Add HRRoles class + role_guards.py         [0.5 day]
    ├── 1.2 SQL migration (role constraint)              [0.5 day]
    ├── 1.3 Update hr1.py routes with guards             [1 day]
    ├── 1.4 Update templates (conditional rendering)     [0.5 day]
    └── 1.5 Testing & validation                         [0.5 day]
                         ↓
 Phase 2: Feature 2 (Employee Portal Dashboard)
    ├── 2.1 SQL: announcements + employee_tasks tables   [0.5 day]
    ├── 2.2 Dashboard route logic                        [1 day]
    ├── 2.3 Dashboard template (responsive layout)       [1.5 days]
    └── 2.4 Testing & role-based widget visibility       [0.5 day]
                         ↓
 Phase 3: Feature 3 (Performance Management)
    ├── 3.1 SQL: 8 probation tables + indexes            [1 day]
    ├── 3.2 State machine engine (probation_engine.py)   [1 day]
    ├── 3.3 Model classes in hms_models.py               [1 day]
    ├── 3.4 Routes (11 endpoints)                        [2 days]
    ├── 3.5 Templates (8 pages)                          [3 days]
    ├── 3.6 Notification triggers                        [0.5 day]
    ├── 3.7 PDF notice generation                        [1 day]
    └── 3.8 Testing (stage sequencing, permissions)      [1 day]
                         ↓
 Phase 4: Feature 4 (Social Recognition)
    ├── 4.1 SQL: 2 tables + seed data                    [0.5 day]
    ├── 4.2 Model classes                                [0.5 day]
    ├── 4.3 Routes (6 endpoints)                         [1 day]
    ├── 4.4 Templates (4 pages)                          [1.5 days]
    ├── 4.5 Auto-rejection logic                         [0.5 day]
    ├── 4.6 Notification + email triggers                [0.5 day]
    └── 4.7 Testing                                      [0.5 day]
```

### Total Estimated Effort: ~21 developer-days

### Dependencies Graph
```
Feature 1 (Roles) ──→ Feature 2 (Dashboard) ──→ Feature 3 (Performance)
                                                         │
                                                         ↓
                                                Feature 4 (Recognition)
```
**Feature 1 is foundational** — the role system must be in place before any other feature can properly enforce access control.

---

## Summary of All New Files

| File | Purpose |
|------|---------|
| `utils/role_guards.py` | Role-checking decorators |
| `utils/probation_engine.py` | State machine for probation workflow |
| `supabase_setup_hr1_features.sql` | Migration for all 12 new tables |
| `templates/subsystems/hr/hr1/employee_dashboard.html` | Employee portal |
| `templates/subsystems/hr/hr1/probation/list.html` | Probation cycles list |
| `templates/subsystems/hr/hr1/probation/detail.html` | Cycle detail + timeline |
| `templates/subsystems/hr/hr1/probation/kpi_builder.html` | KPI creation |
| `templates/subsystems/hr/hr1/probation/kpi_acknowledge.html` | Employee sign-off |
| `templates/subsystems/hr/hr1/probation/notes.html` | Performance notes |
| `templates/subsystems/hr/hr1/probation/mid_checkin.html` | Mid-probation form |
| `templates/subsystems/hr/hr1/probation/final_evaluation.html` | Final eval form |
| `templates/subsystems/hr/hr1/probation/hr_decision.html` | HR decision form |
| `templates/subsystems/hr/hr1/recognition/wall_of_fame.html` | Public recognition |
| `templates/subsystems/hr/hr1/recognition/nominate.html` | Nomination form |
| `templates/subsystems/hr/hr1/recognition/inbox.html` | Supervisor queue |
| `templates/subsystems/hr/hr1/recognition/types_admin.html` | Type management |

## Summary of Modified Files

| File | Changes |
|------|---------|
| `utils/supabase_client.py` | Add `HRRoles` class, update `role_level` property |
| `utils/hms_models.py` | Add probation + recognition model classes, update `Interview.create()` |
| `routes/hr/hr1.py` | Add ~27 new route handlers, role guards on existing routes |
| `supabase_setup.sql` | Reference only — actual changes in new migration file |
| `templates/subsystems/hr/hr1/schedule_interview.html` | Role-based UI filtering |
| `templates/subsystems/hr/hr1/interviews.html` | Conditional action buttons |
| `app.py` | No changes needed (hr1 blueprint already registered) |
