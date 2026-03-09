# HR2 – Talent Development: Full Implementation Plan
**Modules:** Career Pathing · Competency Management · Learning Management · Training Management  
**Subsystem:** HR2  
**Date Prepared:** March 10, 2026  

---

## 1. Current State Assessment

| Module | Already Implemented | Missing / Gaps |
|---|---|---|
| **Career Pathing** | `career_paths`, `assign_career_path`, `update_career_progress`, `my_career`, `upload_requirement_evidence`, `request_career_milestone` | Succession integration, readiness levels, talent pool, finalize/update succession workflow |
| **Competency Management** | `list_competencies`, `add_competency`, `edit_competency`, `assess_staff` | License/certificate verification with expiry check, assessment scheduling, supervisor notifications, employee result submission, compliance reporting for Department Head |
| **Learning Management** | *(None — not yet in HR2)* | Content repository, competency-gap matching, enrollment tracking, assessment engine, evidence upload, feedback loop to Competency module, separate Employee/Dept Head dashboards |
| **Training Management** | `list_trainings`, `add_training`, `edit_training`, `enroll_staff`, `mark_attendance`, `complete_training` | Certification records, file upload for requirements, automated notifications, training progress monitoring, admin-set location and schedule |
| **Succession Planning** | `list_succession_plans`, `add_succession_plan`, `edit_succession_plan` | Full workflow: Identify Position → Talent Pool → Readiness → Dev Plan → Review cycle → Finalize/Update loop, employee notifications |

---

## 2. Module Specifications

---

### 2.1 Career Pathing

**Purpose:** Plan and guide an employee's career growth by mapping future positions with the required skills, competencies, training, and experience.

**Roles Involved:**
- `HR / Management` — creates and manages career paths and assigns them to employees
- `Employee` — views and progresses through their assigned career path

**Required Functionality:**

| Feature | Description |
|---|---|
| Career Path Builder | HR creates path with named steps, requirements per step, and target role |
| Assign to Employee | HR assigns a path to a specific employee with a start date |
| Readiness Level | HR tags each assigned employee as `Not Ready`, `Ready in 1–2 Years`, or `Ready Now` |
| Employee View (`My Career`) | Employee sees their current step, requirements, and overall progress |
| Requirement Evidence Upload | Employee uploads proof of completion (certificates, documents) per requirement |
| Milestone Request | Employee requests HR to validate a milestone |
| HR Milestone Approval | HR approves or rejects milestone requests |

**Status Values:** `Not Started` → `Active` → `Pending Approval` → `Completed`

---

### 2.2 Competency Management

**Purpose:** Ensure all staff maintain the required clinical, technical, and behavioral competencies for their role.

**Workflow (per diagrams):**

```
HR Initiates Review
      │
      ▼
Identify Required Competencies
(Clinical / Technical / Behavioral)
      │
      ▼
Verify License & Certificates
      │
   ┌──┴──┐
Expired   Valid
   │         │
   ▼         ▼
Stop     Schedule Assessment
(Notify   (Supervisor notified)
 staff)        │
               ▼
         Competency Assessment
         (Online / Physical / Both)
               │
               ▼
         Employee Submits Result
         (Auto-sent to Supervisor)
               │
         ┌─────┴─────┐
    Not Yet Competent  Competent
         │                  │
   Training/Coaching    Record Result
   Reassessment         Update Profile
                             │
                             ▼
                  Department Head: Compliance Report
```

**Required Functionality:**

| Feature | Description |
|---|---|
| Competency Definition | HR defines competency name, type (Clinical/Technical/Behavioral), and criteria |
| License/Certificate Verification | System checks expiry date field; blocks assessment scheduling if expired |
| Assessment Scheduling | HR schedules an assessment; supervisor receives automated notification |
| Assessment Types | Online (form-based), Physical (manual score entry), or Combination |
| Employee Result Submission | Employee submits assessment; result record auto-created and linked to supervisor |
| Supervisor Evaluation | Supervisor marks `Competent` or `Not Yet Competent`; sets corrective action if needed |
| Competency Profile Update | On competent result, employee's profile is updated automatically |
| Compliance Report | Department Head dashboard shows pass rates, pending assessments, and expired licenses |

**Status Values:** `Scheduled` → `Submitted` → `Competent` / `Not Yet Competent` → `Reassessment Needed`

---

### 2.3 Learning Management (New Module)

**Purpose:** Connect competency gaps to training content and track employee learning progress through a dedicated Learning Management System (LMS) integrated within HR2.

**Problem:** Currently there is no LMS in HR2 — competency gaps identified in Competency Management have no automated bridge to training.

**Required Functionality:**

| Feature | Description |
|---|---|
| Content Repository | HR uploads training materials (PDF, video links, documents) tagged by competency |
| Competency-Gap Matching | System auto-suggests courses for employees who have `Not Yet Competent` assessments |
| Course Enrollment | Employee self-enrolls or HR/Manager enrolls; enrollment status tracked |
| Attendance & Time Tracking | System records session attendance and time spent per course |
| Assessment Engine | Auto-graded quizzes per course; pass/fail with configurable threshold |
| Evidence Upload | Employee uploads completion proof; flagged for Department Head review |
| Feedback Loop | On course completion, system updates the linked competency record automatically |
| Employee Dashboard | Employee sees enrolled courses, progress, and pending evidence submissions |
| Department Head Dashboard | Dept Head sees team enrollment rates, completions, and flagged submissions |

**Data Integration Points:**
- Reads from `competency_assessments` → `Not Yet Competent` flags trigger course suggestion
- Writes to `competency_assessments` → updates status after course completion
- Reads from `trainings` → pulls scheduled programs into LMS catalog

---

### 2.4 Training Management (Enhancements)

**Purpose:** Manage formal training programs including scheduling, file requirements, certification records, notifications, and progress monitoring.

**What is already built:** `list_trainings`, `add_training`, `edit_training`, `enroll_staff`, `mark_attendance`, `complete_training`

**Required Enhancements:**

| Feature | Current State | To Be Added |
|---|---|---|
| Training Location & Schedule | Basic date field | Add `venue`, `location_type` (On-site/Online/Off-site), `start_time`, `end_time` fields |
| File Requirements | Not present | HR can attach requirement documents (PDF/Word) to a training program; enrolled staff can see and download them |
| Certification Records | Not present | On training completion, HR can issue a certificate record with expiry date stored per employee |
| Automated Notifications | Not present | System sends notification to enrolled staff: 7 days before, 1 day before, and on day of training |
| Training Progress Monitor | Basic attendance only | Dashboard widget showing enrollment count, attendance %, completion rate per training |
| Admin Set Place/Schedule | Minimal | Dedicated form fields for location, time, trainer name, and max capacity |

---

### 2.5 Succession Planning (Workflow Completion)

**Purpose:** Ensure critical hospital positions have identified and prepared successors at all times.

**Full Workflow (per diagrams):**

```
HR: Identify Critical Position
          │
          ▼
HR: Assess Potential Employees
          │
          ▼
HR: Create Talent Pool
          │
          ▼
HR: Assign Readiness Level ──────────────────────────┐
          │                                           │
          ▼                                           │
Employee: Implement Development Plan                  │
          │                                           │
          ▼                                           │
Employee: Update Successor Readiness Status           │
          │                                           │
          ▼                                           │
Employee: Record Succession Review Results            │
          │                                           │
          ▼                                           │
HR: Review Succession Plan                            │
          │                                           │
    Is successor ready?                               │
    ┌──── YES ────┐                                   │
    ▼             ▼  NO                               │
Finalize      Update Succession Plan ────────────────┘
Succession    → Implement Development Plan (loop)
Plan
```

**Required Functionality:**

| Feature | Description |
|---|---|
| Position Criticality Flag | HR marks a position as `Critical` with justification |
| Talent Pool Management | HR adds candidates to the succession pool for a specific position |
| Readiness Level Assignment | `Not Ready`, `Ready in 1–2 Years`, `Ready Now` per candidate |
| Employee Notification | Employee notified when added to succession plan with their readiness level |
| Development Plan Linking | Employee links their career path / training plan as their development plan |
| Readiness Status Update | Employee can update their own readiness progress notes |
| Review Results Recording | Both parties record succession review meeting notes |
| HR Review Decision | HR marks successor as `Ready` → Finalize, or `Not Ready` → Update & loop |
| Succession Finalization | Final record created; employee notified of succession decision |

---

## 3. Database Requirements

### New / Modified Tables

```sql
-- Competency Assessment Scheduling
ALTER TABLE competency_assessments ADD COLUMN
    assessment_type VARCHAR(20) DEFAULT 'Online',  -- Online / Physical / Combination
    scheduled_date DATE,
    supervisor_id INTEGER REFERENCES users(id),
    license_verified BOOLEAN DEFAULT FALSE,
    license_expiry DATE,
    corrective_action VARCHAR(50),  -- Training / Coaching / Reassessment
    compliance_report_date DATE;

-- Training Enhancements
ALTER TABLE trainings ADD COLUMN
    venue VARCHAR(255),
    location_type VARCHAR(20) DEFAULT 'On-site',
    start_time TIME,
    end_time TIME,
    trainer_name VARCHAR(100),
    max_capacity INTEGER,
    requirements_file_url TEXT;

-- Training Certifications (New)
CREATE TABLE training_certifications (
    id SERIAL PRIMARY KEY,
    training_id INTEGER REFERENCES trainings(id),
    user_id INTEGER REFERENCES users(id),
    issued_date DATE,
    expiry_date DATE,
    certificate_url TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- LMS Courses (New)
CREATE TABLE lms_courses (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255),
    description TEXT,
    content_url TEXT,           -- link or file URL
    content_type VARCHAR(20),   -- PDF / Video / Document
    competency_id INTEGER REFERENCES competencies(id),
    pass_threshold INTEGER DEFAULT 70,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- LMS Enrollments (New)
CREATE TABLE lms_enrollments (
    id SERIAL PRIMARY KEY,
    course_id INTEGER REFERENCES lms_courses(id),
    user_id INTEGER REFERENCES users(id),
    enrolled_at TIMESTAMP DEFAULT NOW(),
    status VARCHAR(20) DEFAULT 'Enrolled',  -- Enrolled / In Progress / Completed / Failed
    score INTEGER,
    time_spent_mins INTEGER DEFAULT 0,
    evidence_url TEXT,
    evidence_flagged BOOLEAN DEFAULT FALSE,
    completed_at TIMESTAMP
);

-- Succession Plan Candidates (New)
ALTER TABLE succession_plans ADD COLUMN
    position_title VARCHAR(255),
    is_critical BOOLEAN DEFAULT FALSE,
    readiness_level VARCHAR(30),  -- Not Ready / Ready in 1-2 Years / Ready Now
    status VARCHAR(20) DEFAULT 'Active',  -- Active / Finalized
    development_plan_notes TEXT,
    review_notes TEXT,
    finalized_at TIMESTAMP;
```

---

## 4. Implementation Plan

### Phase 1 — Training Management Enhancements *(~3 days)*
> Lowest risk — builds on existing, working foundation.

| Task | File(s) |
|---|---|
| Add `venue`, `location_type`, `start_time`, `end_time`, `trainer_name`, `max_capacity` to `add_training` / `edit_training` routes | `routes/hr/hr2.py` |
| Add `requirements_file_url` upload to training form | `routes/hr/hr2.py` |
| Show downloadable requirements file in enrolled staff view | `templates/subsystems/hr/hr2/trainings.html` |
| Certification record issuance on `complete_training` | `routes/hr/hr2.py` |
| Training notification scheduler (7 days, 1 day, day-of) | `routes/hr/hr2.py` + `utils/hms_models.py` |
| Training progress monitoring widgets on dashboard | `templates/subsystems/hr/hr2/dashboard.html` |

---

### Phase 2 — Competency Management Workflow *(~4 days)*
> Extends what exists with the full HR → Supervisor → Employee → Dept Head workflow.

| Task | File(s) |
|---|---|
| Add `license_expiry` and `license_verified` fields to competency assessment form | `routes/hr/hr2.py` |
| License expiry check — block scheduling if expired, notify staff | `routes/hr/hr2.py` |
| Assessment scheduling with `scheduled_date`, `assessment_type`, `supervisor_id` | `routes/hr/hr2.py` |
| Supervisor notification on scheduling | `utils/hms_models.py` |
| Employee result submission form (online score or physical score entry) | New route: `submit_assessment_result` |
| Auto-notify supervisor on employee submission | `routes/hr/hr2.py` |
| Supervisor evaluation form (`Competent` / `Not Yet Competent` + corrective action) | New route: `evaluate_assessment` |
| Auto-update competency profile on `Competent` result | `routes/hr/hr2.py` |
| Department Head compliance report page | New template + route: `competency_compliance_report` |

---

### Phase 3 — Succession Planning Workflow *(~3 days)*
> Completes the partially built succession module with the full cycle.

| Task | File(s) |
|---|---|
| Add `is_critical`, `position_title`, `readiness_level`, `status` fields to succession plan form | `routes/hr/hr2.py` |
| Talent Pool management (add/remove candidates per plan) | New route: `manage_talent_pool` |
| Readiness level assignment per candidate | `routes/hr/hr2.py` |
| Employee notification on being added to succession pool | `utils/hms_models.py` |
| Employee: update own readiness notes + development plan link | New route: `update_succession_status` |
| HR review decision form (Ready/Not Ready) | New route: `review_succession` |
| If Not Ready → loop back: notify employee to update plan | `routes/hr/hr2.py` |
| Succession finalization + employee notification | New route: `finalize_succession` |

---

### Phase 4 — Learning Management System (New Module) *(~5 days)*
> Largest new module — built from scratch.

| Task | File(s) |
|---|---|
| LMS course content repository (HR creates courses, tags competency) | New routes: `list_lms_courses`, `add_lms_course`, `edit_lms_course` |
| Competency-gap auto-suggestion (reads `Not Yet Competent` records) | New route: `lms_suggestions` |
| Course self-enrollment and HR/Manager-forced enrollment | New route: `lms_enroll` |
| Attendance and time tracking per course session | New route: `lms_track_time` |
| Built-in quiz/assessment engine with auto-grading | New routes: `lms_take_quiz`, `lms_submit_quiz` |
| Evidence upload and Dept Head flagging | New route: `lms_upload_evidence` |
| Feedback loop: on completion, update `competency_assessments` | `routes/hr/hr2.py` |
| Employee LMS dashboard (`My Learning`) | New template: `templates/subsystems/hr/hr2/lms_dashboard.html` |
| Department Head LMS oversight dashboard | New template: `templates/subsystems/hr/hr2/lms_dept_head.html` |

---

## 5. Summary Timeline

| Phase | Module | Estimated Effort |
|---|---|---|
| Phase 1 | Training Management Enhancements | 3 days |
| Phase 2 | Competency Management Full Workflow | 4 days |
| Phase 3 | Succession Planning Workflow Completion | 3 days |
| Phase 4 | Learning Management System (New) | 5 days |
| **Total** | | **~15 development days** |

---

## 6. Dependencies

- `supabase_setup.sql` must be updated with all new table columns before Phase 1 begins.
- Phase 4 (LMS) depends on Phase 2 (Competency) being complete for the competency-gap matching to work.
- All notification features depend on `utils/hms_models.py` `Notification.create()` (already working).
- File uploads (certifications, evidence, training requirements) use the existing Supabase storage client pattern already established in HR1 and the portal.
