# CT3 — Hospital Activity & Documentation System (HADS): Full Implementation Plan

**Prepared:** March 13, 2026
**Subsystem:** CT3 (`/ct3` blueprint, `routes/core_transaction/ct3.py`)
**Stack:** Flask + Supabase + Jinja2 / Tailwind CSS
**Scope:** Extend CT3 from Admin & Finance into the unified Hospital Activity & Documentation System (HADS) — the authoritative source of patient lifecycle status, activity logs, clinical documentation records, billing integration, and hospital-wide discharge management.

---

## Current State Audit (Already Implemented)

| Module | Routes Existing | Status |
|--------|----------------|--------|
| Auth | `/login`, `/logout`, `/change-password` | ✅ Done |
| Dashboard | `/dashboard` | ⚠️ Partial (basic widgets only) |
| Billing | `/billing`, `/billing/create`, `/billing/pay/<id>` | ⚠️ Partial |
| Medical Records | `/records`, `/records/<id>`, add / edit / delete | ⚠️ Partial |
| Patient Print | `/print/<id>` | ✅ Done |
| Discharge | `/discharge`, `/discharge/<id>/clear` | ⚠️ Partial |
| Security Logs | `/security-logs`, `/security-report`, `/export-logs` | ✅ Done |
| Analytics | `/analytics` | ⚠️ Partial |
| Settings | `/settings` | ⚠️ Partial |
| Patient Status Tracker | — | ❌ Not started |
| Activity Feed | — | ❌ Not started |
| Patient Timeline | — | ❌ Not started |
| Census Board | — | ❌ Not started |
| Discharge Planner | — | ❌ Not started |
| Transfer Management | — | ❌ Not started |
| Document Vault | — | ❌ Not started |
| Reporting Center | — | ❌ Not started |

---

## Patient Status Reference

CT3-HADS is the authoritative owner of patient lifecycle status. Every status change is timestamped, user-attributed, and stored in the audit trail.

| # | Status | Description | Typical Next Status |
|---|--------|-------------|---------------------|
| 1 | **Registered** | Patient is recorded in the system but has not yet received any treatment | Waiting |
| 2 | **Waiting** | Patient is waiting for consultation, examination, or service | Under Consultation, Admitted |
| 3 | **Admitted** | Patient is officially admitted and assigned to a room or ward | Under Treatment, Under Observation, In Surgery |
| 4 | **Under Consultation / Under Treatment** | Patient is currently being examined or treated by a physician | Under Observation, In Surgery, Recovered, Discharged |
| 5 | **Under Observation** | Patient is being monitored to observe symptoms or recovery progression | Recovered, Under Treatment, Admitted |
| 6 | **In Surgery / Procedure** | Patient is currently undergoing surgery or a medical procedure | Under Observation, Recovered |
| 7 | **Recovered / Stable** | Patient's condition has improved or stabilized | Discharged, Under Observation |
| 8 | **Discharged** | Patient has completed treatment and is authorized to leave the hospital | — (terminal) |
| 9 | **Transferred** | Patient has been moved to another department, ward, or hospital | — (terminal or re-admitted externally) |
| 10 | **Deceased** | Patient passed away during the course of treatment | — (terminal) |

### Status Transition Rules

```
Registered      → Waiting
Waiting         → Under Consultation / Admitted
Admitted        → Under Treatment / Under Observation / In Surgery
Under Treatment → Under Observation / In Surgery / Recovered / Discharged
Under Observation → Recovered / Under Treatment / Admitted
In Surgery      → Under Observation / Recovered
Recovered       → Discharged / Under Observation
Discharged      → (terminal — no further transitions)
Transferred     → (terminal — record locked, note destination)
Deceased        → (terminal — record locked, COD required)
```

Terminal statuses (`Discharged`, `Transferred`, `Deceased`) lock the record from further status changes and trigger billing finalization.

---

## Implementation Phases

---

### Phase 1 — Patient Status Engine (Core of HADS)

**Purpose:** Give every patient an authoritative, auditable lifecycle status. This is the foundation all other HADS phases build on.

#### 1.1 Database Changes

```sql
-- Add status column to patients table
ALTER TABLE patients
    ADD COLUMN current_status     VARCHAR(50)  DEFAULT 'Registered',
    ADD COLUMN status_updated_at  TIMESTAMPTZ  DEFAULT NOW(),
    ADD COLUMN status_updated_by  UUID         REFERENCES users(id),
    ADD COLUMN admission_date     TIMESTAMPTZ,
    ADD COLUMN discharge_date     TIMESTAMPTZ,
    ADD COLUMN ward_id            INT          REFERENCES wards(id),
    ADD COLUMN bed_id             INT          REFERENCES beds(id),
    ADD COLUMN attending_doctor_id UUID        REFERENCES users(id);

-- Status history log (every change is recorded)
CREATE TABLE patient_status_history (
    id              SERIAL PRIMARY KEY,
    patient_id      INT          NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    old_status      VARCHAR(50),
    new_status      VARCHAR(50)  NOT NULL,
    changed_by      UUID         REFERENCES users(id),
    changed_at      TIMESTAMPTZ  DEFAULT NOW(),
    reason          TEXT,                          -- required for terminal statuses
    metadata        JSONB                          -- e.g. ward, bed, destination hospital
);

-- Allowed status transitions enforcement table
CREATE TABLE allowed_status_transitions (
    id          SERIAL PRIMARY KEY,
    from_status VARCHAR(50),   -- NULL = any
    to_status   VARCHAR(50)    NOT NULL,
    requires_reason BOOLEAN    DEFAULT FALSE
);

-- Seed allowed transitions
INSERT INTO allowed_status_transitions (from_status, to_status, requires_reason) VALUES
    ('Registered',                        'Waiting',                           FALSE),
    ('Waiting',                           'Under Consultation',                 FALSE),
    ('Waiting',                           'Admitted',                          FALSE),
    ('Admitted',                          'Under Consultation',                 FALSE),
    ('Admitted',                          'Under Observation',                  FALSE),
    ('Admitted',                          'In Surgery / Procedure',             FALSE),
    ('Under Consultation',                'Under Observation',                  FALSE),
    ('Under Consultation',                'In Surgery / Procedure',             FALSE),
    ('Under Consultation',                'Recovered / Stable',                 FALSE),
    ('Under Consultation',                'Discharged',                        TRUE),
    ('Under Observation',                 'Recovered / Stable',                 FALSE),
    ('Under Observation',                 'Under Consultation',                 FALSE),
    ('Under Observation',                 'Admitted',                          FALSE),
    ('In Surgery / Procedure',            'Under Observation',                  FALSE),
    ('In Surgery / Procedure',            'Recovered / Stable',                 FALSE),
    ('Recovered / Stable',                'Discharged',                        TRUE),
    ('Recovered / Stable',                'Under Observation',                  FALSE),
    (NULL,                                'Transferred',                       TRUE),
    (NULL,                                'Deceased',                          TRUE);
```

#### 1.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct3/patients` | Patient census — all patients with current status, filters by status |
| GET | `/ct3/patients/<id>/status` | Status detail panel for one patient |
| POST | `/ct3/patients/<id>/status/update` | Change patient status (validates transition, logs history) |
| GET | `/ct3/patients/<id>/status/history` | Full status history timeline |
| GET | `/ct3/status-board` | Live hospital-wide status board (census overview) |

#### 1.3 Status Change Logic (Backend)

```python
def change_patient_status(patient_id, new_status, changed_by_id, reason=None, metadata=None):
    """
    1. Fetch current status from patients table
    2. Validate transition against allowed_status_transitions
    3. If terminal status: require reason, lock record
    4. If Admitted: require ward_id + bed_id in metadata
    5. If Transferred: require destination hospital in metadata
    6. If Deceased: require cause_of_death in metadata
    7. INSERT into patient_status_history
    8. UPDATE patients.current_status
    9. AuditLog.log(changed_by_id, "Status Change", "ct3", {...})
    10. Trigger billing finalization if terminal
    """
```

#### 1.4 Dashboard Widgets (Phase 1)

- **Total Active Patients** (non-terminal statuses)
- **Status Distribution** — donut chart: counts per status
- **Admitted Today** — count
- **Discharged Today** — count
- **Waiting Queue** — count with avg wait time
- **In Surgery Now** — count
- **Under Observation** — count
- **Deceased (Month)** — count

#### 1.5 Template Files

```
templates/subsystems/core_transaction/ct3/
    patient_census.html          ← filterable status grid (all patients)
    patient_status_panel.html    ← single patient status + change form
    patient_status_history.html  ← timeline of all status changes
    status_board.html            ← live hospital-wide board
```

---

### Phase 2 — Activity Feed & Real-Time Hospital Log

**Purpose:** A running log of every significant hospital activity — admissions, discharges, status changes, transfers, procedures started — visible to CT3 staff with filtering and export.

#### 2.1 Database Changes

```sql
CREATE TABLE hospital_activity_log (
    id              SERIAL PRIMARY KEY,
    activity_type   VARCHAR(50)  NOT NULL,
    -- Types: 'Status Change' | 'Admission' | 'Discharge' | 'Transfer' |
    --        'Procedure Started' | 'Procedure Ended' | 'Death' | 'Billing Event' |
    --        'Record Created' | 'Record Updated' | 'Alert Raised'
    patient_id      INT          REFERENCES patients(id),
    performed_by    UUID         REFERENCES users(id),
    source_module   VARCHAR(20)  DEFAULT 'ct3',
    -- Source: ct1 | ct2 | ct3 | hr1 | hr2 | portal
    description     TEXT,
    metadata        JSONB,
    created_at      TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX idx_hospital_activity_log_patient ON hospital_activity_log(patient_id);
CREATE INDEX idx_hospital_activity_log_type    ON hospital_activity_log(activity_type);
CREATE INDEX idx_hospital_activity_log_date    ON hospital_activity_log(created_at DESC);
```

#### 2.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct3/activity` | Hospital activity feed (paginated, filterable) |
| GET | `/ct3/activity/patient/<id>` | Activity feed for a single patient |
| GET | `/ct3/activity/export` | CSV/PDF export of activity log |

#### 2.3 Auto-Log Integration Points

Every status change (Phase 1), admission, discharge, billing event, and document upload auto-inserts into `hospital_activity_log`. A utility function handles this:

```python
# utils/activity_log.py
def log_activity(activity_type, patient_id=None, performed_by=None,
                 source_module='ct3', description='', metadata=None):
    """Insert row into hospital_activity_log."""
```

#### 2.4 Dashboard Widgets

- **Activity Feed Widget** — last 15 events with type badge + patient link
- **Events Today** — count grouped by type

---

### Phase 3 — Patient Timeline View

**Purpose:** A single unified timeline per patient showing every recorded event: registrations, status changes, consultations, procedures, lab results, discharges — in chronological order.

#### 3.1 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct3/patients/<id>/timeline` | Full patient lifecycle timeline |

#### 3.2 Timeline Data Sources

The timeline aggregates from multiple tables via parallel Supabase queries:

| Source | Event Type | Fields |
|--------|-----------|--------|
| `patient_status_history` | Status Change | new_status, changed_by, reason |
| `hospital_activity_log` | Activity | activity_type, description |
| `medical_records` | Clinical Record | diagnosis, visit_date, doctor |
| `billing_records` | Billing | total_amount, status, created_at |
| `appointments` | Appointment | type, appointment_date, status |
| `encounters` (CT2) | Encounter | chief_complaint, status |
| `lab_orders` (CT2) | Lab Order | test_name, status, result |
| `surgeries` (CT2) | Procedure | procedure_name, status, started_at |

#### 3.3 Template Files

```
templates/subsystems/core_transaction/ct3/
    patient_timeline.html    ← vertical timeline with event-type icons + color coding
```

---

### Phase 4 — Enhanced Census Board (Live Status Board)

**Purpose:** A real-time hospital ward/department census view showing bed occupancy, patient status, and alerts in a structured grid.

#### 4.1 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct3/census` | Full census board (ward/department grid) |
| GET | `/ct3/census/ward/<ward_id>` | Census for a single ward |
| GET | `/ct3/census/export` | Export census report (PDF/CSV) |

#### 4.2 Census Board View

```
┌─────────────────────────────────────────────────────────────────┐
│  CENSUS BOARD — March 13, 2026 · Auto-refreshes every 60s       │
├──────────┬─────────────────────────────────────────────────────┤
│ Ward A   │  Bed 1: [JUAN DELA CRUZ]  Under Observation  🔴     │
│          │  Bed 2: [MARIA SANTOS]    In Surgery          🟡     │
│          │  Bed 3: Available         —                          │
├──────────┼─────────────────────────────────────────────────────┤
│ Ward B   │  Bed 1: [JOSE REYES]      Admitted            🟢     │
│          │  Bed 2: [ANA CRUZ]        Recovered / Stable  🟢     │
```

#### 4.3 Template Files

```
templates/subsystems/core_transaction/ct3/
    census_board.html        ← responsive ward grid with status badges
    census_ward.html         ← single ward detail
```

---

### Phase 5 — Discharge Planner & Documentation

**Purpose:** Extend the existing `/discharge` route into a full discharge planning workflow with discharge summaries, instructions, and final billing review before clearance.

#### 5.1 Database Changes

```sql
CREATE TABLE discharge_plans (
    id                  SERIAL PRIMARY KEY,
    patient_id          INT          NOT NULL REFERENCES patients(id),
    initiated_at        TIMESTAMPTZ  DEFAULT NOW(),
    initiated_by        UUID         REFERENCES users(id),
    discharge_summary   TEXT,
    discharge_diagnosis TEXT,
    medications_at_discharge JSONB,         -- list of medications to continue
    follow_up_date      DATE,
    follow_up_notes     TEXT,
    activity_restrictions TEXT,
    diet_instructions   TEXT,
    wound_care_notes    TEXT,
    final_billing_reviewed BOOLEAN    DEFAULT FALSE,
    cleared_by          UUID         REFERENCES users(id),
    cleared_at          TIMESTAMPTZ,
    status              VARCHAR(20)  DEFAULT 'Pending'
    -- Pending | Reviewing | Cleared | Discharged
);
```

#### 5.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct3/discharge` | Discharge queue (all pending/reviewing plans) |
| POST | `/ct3/discharge/initiate/<patient_id>` | Start discharge plan for a patient |
| GET | `/ct3/discharge/<plan_id>` | View/edit discharge plan |
| POST | `/ct3/discharge/<plan_id>/update` | Save discharge summary and instructions |
| POST | `/ct3/discharge/<plan_id>/billing-review` | Mark final billing as reviewed |
| POST | `/ct3/discharge/<plan_id>/clear` | Clear patient for discharge (sets status → Discharged) |
| GET | `/ct3/discharge/<plan_id>/print` | Printable discharge summary |

#### 5.3 Discharge Clearance Checklist

Before `clear` action is allowed, the system verifies:

- [ ] Discharge summary completed
- [ ] Final billing reviewed and marked
- [ ] All outstanding lab/radiology orders resolved (no pending results)
- [ ] Pharmacy — no pending medication dispenses
- [ ] Ward/bed assignment cleared

#### 5.4 Template Files

```
templates/subsystems/core_transaction/ct3/
    discharge_queue.html         ← list of pending discharge plans
    discharge_plan.html          ← form: summary, instructions, billing review
    discharge_print.html         ← print-ready discharge document
```

---

### Phase 6 — Transfer Management

**Purpose:** Manage the `Transferred` status lifecycle — internal transfers (ward-to-ward) and external transfers (to another hospital), with full documentation.

#### 6.1 Database Changes

```sql
CREATE TABLE patient_transfers (
    id                  SERIAL PRIMARY KEY,
    patient_id          INT          NOT NULL REFERENCES patients(id),
    transfer_type       VARCHAR(20)  NOT NULL,  -- 'Internal' | 'External'
    from_ward_id        INT          REFERENCES wards(id),
    to_ward_id          INT          REFERENCES wards(id),      -- if internal
    destination_hospital VARCHAR(200),                          -- if external
    destination_department VARCHAR(100),
    reason              TEXT         NOT NULL,
    transport_mode      VARCHAR(50),           -- Ambulance | Private | Walking
    accompanying_staff  JSONB,                 -- [{user_id, name, role}]
    clinical_summary    TEXT,
    medications_sent    JSONB,
    initiated_by        UUID         REFERENCES users(id),
    initiated_at        TIMESTAMPTZ  DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    status              VARCHAR(20)  DEFAULT 'Pending' -- Pending | In Transit | Completed | Cancelled
);
```

#### 6.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct3/transfers` | Transfer queue (pending + recent) |
| POST | `/ct3/transfers/new/<patient_id>` | Initiate transfer (internal or external) |
| GET | `/ct3/transfers/<id>` | View/edit transfer record |
| POST | `/ct3/transfers/<id>/complete` | Mark transfer complete → sets patient status to Transferred |
| POST | `/ct3/transfers/<id>/cancel` | Cancel transfer |
| GET | `/ct3/transfers/<id>/print` | Print transfer note / referral letter |

---

### Phase 7 — Document Vault (Clinical Documentation Repository)

**Purpose:** Central repository for all patient-level documents — consent forms, clinical summaries, lab reports, imaging reports, referral letters, discharge summaries — searchable and version-controlled.

#### 7.1 Database Changes

```sql
CREATE TABLE patient_documents (
    id              SERIAL PRIMARY KEY,
    patient_id      INT          NOT NULL REFERENCES patients(id),
    document_type   VARCHAR(50)  NOT NULL,
    -- Types: 'Consent Form' | 'Lab Report' | 'Imaging Report' | 'Clinical Summary'
    --        'Discharge Summary' | 'Referral Letter' | 'Prescription' | 'Transfer Note' | 'Other'
    title           VARCHAR(200) NOT NULL,
    description     TEXT,
    file_url        TEXT,                    -- Supabase Storage URL
    file_name       VARCHAR(200),
    file_size_kb    INT,
    mime_type       VARCHAR(100),
    version         INT          DEFAULT 1,
    uploaded_by     UUID         REFERENCES users(id),
    uploaded_at     TIMESTAMPTZ  DEFAULT NOW(),
    is_confidential BOOLEAN      DEFAULT FALSE,
    tags            TEXT[]
);
```

#### 7.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct3/documents` | Document vault search and browse |
| GET | `/ct3/documents/patient/<patient_id>` | All documents for one patient |
| POST | `/ct3/documents/upload` | Upload new document |
| GET | `/ct3/documents/<doc_id>` | View document metadata + download link |
| POST | `/ct3/documents/<doc_id>/delete` | Delete document (soft-delete) |

---

### Phase 8 — Billing System Enhancement

**Purpose:** Upgrade the existing `/billing` module with itemized billing, insurance tracking, payment history, and billing-to-discharge linkage.

#### 8.1 Database Changes

```sql
-- Enhance billing_records with more detail
ALTER TABLE billing_records
    ADD COLUMN encounter_id         INT          REFERENCES encounters(id),
    ADD COLUMN discharge_plan_id    INT          REFERENCES discharge_plans(id),
    ADD COLUMN insurance_provider   VARCHAR(100),
    ADD COLUMN insurance_policy_no  VARCHAR(100),
    ADD COLUMN insurance_coverage   NUMERIC(10,2) DEFAULT 0,
    ADD COLUMN philhealth_coverage  NUMERIC(10,2) DEFAULT 0,
    ADD COLUMN senior_discount      NUMERIC(10,2) DEFAULT 0,
    ADD COLUMN pwd_discount         NUMERIC(10,2) DEFAULT 0,
    ADD COLUMN net_amount           NUMERIC(10,2),
    ADD COLUMN payment_method       VARCHAR(50),
    -- Cash | GCash | Credit Card | Insurance | PhilHealth | Corporate
    ADD COLUMN payment_reference    VARCHAR(100),
    ADD COLUMN partially_paid_amount NUMERIC(10,2) DEFAULT 0,
    ADD COLUMN finalized_at         TIMESTAMPTZ,
    ADD COLUMN finalized_by         UUID         REFERENCES users(id);

-- Itemized billing lines
CREATE TABLE billing_line_items (
    id              SERIAL PRIMARY KEY,
    billing_id      INT          NOT NULL REFERENCES billing_records(id) ON DELETE CASCADE,
    source_module   VARCHAR(30),  -- CT1 | CT2-Lab | CT2-Radiology | CT2-Pharmacy | CT2-Surgery | CT3
    source_record_id INT,
    description     VARCHAR(200) NOT NULL,
    quantity        INT          DEFAULT 1,
    unit_price      NUMERIC(10,2) NOT NULL,
    discount        NUMERIC(10,2) DEFAULT 0,
    line_total      NUMERIC(10,2) NOT NULL,
    posted_at       TIMESTAMPTZ  DEFAULT NOW()
);
```

#### 8.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct3/billing` | Billing list — filterable by status, date, patient |
| POST | `/ct3/billing/create` | Create new billing record (enhanced form) |
| GET | `/ct3/billing/<id>` | Billing detail with itemized line items |
| POST | `/ct3/billing/<id>/add-item` | Add line item to existing bill |
| POST | `/ct3/billing/<id>/remove-item/<item_id>` | Remove line item |
| POST | `/ct3/billing/<id>/apply-discount` | Apply PhilHealth / senior / insurance coverage |
| POST | `/ct3/billing/<id>/pay` | Record payment (partial or full) |
| POST | `/ct3/billing/<id>/finalize` | Lock bill and generate receipt |
| GET | `/ct3/billing/<id>/print` | Printable official receipt / statement of account |
| GET | `/ct3/billing/summary` | Revenue summary dashboard |

---

### Phase 9 — Reporting Center

**Purpose:** Pre-built reports for hospital administration, finance, and clinical governance.

#### 9.1 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct3/reports` | Reports hub |
| GET | `/ct3/reports/census` | Daily/weekly/monthly census report |
| GET | `/ct3/reports/admissions` | Admission statistics (by ward, by diagnosis, by doctor) |
| GET | `/ct3/reports/discharges` | Discharge report with LOS (length of stay) |
| GET | `/ct3/reports/mortality` | Mortality report (Deceased status patients) |
| GET | `/ct3/reports/transfers` | Transfer activity report |
| GET | `/ct3/reports/billing` | Revenue and outstanding balance report |
| GET | `/ct3/reports/activity` | Hospital activity log export |
| POST | `/ct3/reports/generate` | Dynamic report generator (date range + type) |

#### 9.2 Key Report Definitions

| Report | Key Metrics |
|--------|------------|
| **Census Report** | Beds occupied, available, occupancy rate %, average daily census |
| **Admission Report** | Admissions by period, by ward, by diagnosis, by attending physician |
| **Discharge Report** | Discharges by period, average length of stay, readmission count |
| **Mortality Report** | Deceased count by period, cause of death distribution, ward breakdown |
| **Revenue Report** | Total billed, total collected, outstanding, by payment method, by insurance |
| **Activity Report** | Event count by type, by user, by module, filtered by date range |

---

### Phase 10 — Analytics Dashboard Enhancement

**Purpose:** Replace the existing partial `/analytics` route with a fully data-driven analytics dashboard.

#### 10.1 Routes to Build (Enhance Existing)

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct3/analytics` | Full analytics dashboard |
| GET | `/ct3/analytics/api/status-distribution` | JSON: patient count per status |
| GET | `/ct3/analytics/api/admissions-trend` | JSON: daily admission counts (30 days) |
| GET | `/ct3/analytics/api/discharge-los` | JSON: average LOS per month |
| GET | `/ct3/analytics/api/revenue-trend` | JSON: daily revenue (30 days) |
| GET | `/ct3/analytics/api/mortality-trend` | JSON: monthly mortality count |

#### 10.2 Charts to Implement

| Chart | Type | Description |
|-------|------|-------------|
| Status Distribution | Donut | Count per patient status |
| Admissions Trend | Line | Last 30 days daily count |
| Length of Stay | Bar | Average LOS per ward |
| Revenue vs Outstanding | Stacked Bar | Monthly billing breakdown |
| Discharge vs Admission | Line (dual) | Net bed pressure per day |
| Mortality Rate | Line | Monthly count (with benchmarks) |
| Top Diagnoses | Bar | Most common diagnoses |

---

## Recommended Build Order

```
Phase 1  →  Patient Status Engine (all other phases depend on current_status)
Phase 2  →  Activity Feed + Log utility (needed for timeline + reporting)
Phase 3  →  Patient Timeline (depends on Phase 1 & 2)
Phase 4  →  Census Board (depends on Phase 1)
Phase 5  →  Discharge Planner (depends on Phase 1 + existing discharge route)
Phase 6  →  Transfer Management (depends on Phase 1)
Phase 7  →  Document Vault (independent — can build in parallel with 4-6)
Phase 8  →  Billing Enhancement (builds on existing billing routes)
Phase 9  →  Reporting Center (depends on all prior data)
Phase 10 →  Analytics Dashboard (depends on Phase 9 API endpoints)
```

---

## New Database Tables Summary

| Table | Phase | Purpose |
|-------|-------|---------|
| `patient_status_history` | 1 | Audit trail of every status change |
| `allowed_status_transitions` | 1 | Transition rule enforcement |
| `hospital_activity_log` | 2 | Hospital-wide event log |
| `discharge_plans` | 5 | Discharge planning and documentation |
| `patient_transfers` | 6 | Internal and external transfer records |
| `patient_documents` | 7 | Document vault metadata |
| `billing_line_items` | 8 | Itemized billing records |

## Column Additions Summary

| Table | Columns Added | Phase |
|-------|--------------|-------|
| `patients` | `current_status`, `status_updated_at`, `status_updated_by`, `admission_date`, `discharge_date`, `ward_id`, `bed_id`, `attending_doctor_id` | 1 |
| `billing_records` | insurance fields, discount fields, `payment_method`, `net_amount`, `finalized_at` | 8 |

---

## Status Badge Color Coding

| Status | Badge Color | Hex |
|--------|------------|-----|
| Registered | Gray | `#6B7280` |
| Waiting | Amber | `#F59E0B` |
| Admitted | Blue | `#3B82F6` |
| Under Consultation / Treatment | Indigo | `#6366F1` |
| Under Observation | Cyan | `#06B6D4` |
| In Surgery / Procedure | Orange | `#F97316` |
| Recovered / Stable | Green | `#22C55E` |
| Discharged | Teal | `#14B8A6` |
| Transferred | Purple | `#A855F7` |
| Deceased | Red-Gray | `#9F1239` |

---

## Technical Notes

- All new routes follow the existing pattern: `@ct3_bp.route(...)` + `@login_required` + `@policy_required('ct3')`
- Every status transition must call `AuditLog.log()` and `log_activity()` (Phase 2 utility)
- Terminal statuses (`Discharged`, `Transferred`, `Deceased`) auto-trigger billing finalization logic
- The `allowed_status_transitions` table is seeded once via `init_db.py` / migration script
- Census board auto-refresh: use `<meta http-equiv="refresh" content="60">` or minimal JS `setInterval` fetch
- Document uploads: use Supabase Storage bucket (`patient-documents`) with signed URLs
- All reports must support CSV export via Python `csv` module streamed as `text/csv` response
- Length of Stay (LOS) calculated as: `(discharge_date or NOW()) - admission_date` in days
- Status `Deceased` requires a `cause_of_death` field in the `reason` / metadata of the status history entry

---

## Migration Script Outline

```sql
-- ct3_hads_migration.sql

-- Phase 1: Extend patients table
ALTER TABLE patients ADD COLUMN IF NOT EXISTS current_status VARCHAR(50) DEFAULT 'Registered';
ALTER TABLE patients ADD COLUMN IF NOT EXISTS status_updated_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE patients ADD COLUMN IF NOT EXISTS status_updated_by UUID REFERENCES users(id);
ALTER TABLE patients ADD COLUMN IF NOT EXISTS admission_date TIMESTAMPTZ;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS discharge_date TIMESTAMPTZ;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS ward_id INT;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS bed_id INT;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS attending_doctor_id UUID REFERENCES users(id);

-- Backfill: patients with existing discharge records → mark as Discharged
UPDATE patients SET current_status = 'Discharged'
WHERE id IN (SELECT DISTINCT patient_id FROM billing_records WHERE status = 'Paid');

-- Create status history table
CREATE TABLE IF NOT EXISTS patient_status_history ( ... );

-- Create activity log table
CREATE TABLE IF NOT EXISTS hospital_activity_log ( ... );

-- Create discharge plans table
CREATE TABLE IF NOT EXISTS discharge_plans ( ... );

-- Create transfers table
CREATE TABLE IF NOT EXISTS patient_transfers ( ... );

-- Create documents table
CREATE TABLE IF NOT EXISTS patient_documents ( ... );

-- Billing enhancements
ALTER TABLE billing_records ADD COLUMN IF NOT EXISTS net_amount NUMERIC(10,2);
ALTER TABLE billing_records ADD COLUMN IF NOT EXISTS payment_method VARCHAR(50);
CREATE TABLE IF NOT EXISTS billing_line_items ( ... );
```

---

*End of CT3-HADS Implementation Plan — v1.0*
