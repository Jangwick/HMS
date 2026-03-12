# CT2 — Clinical Transaction System: Full Implementation Plan

**Prepared:** March 12, 2026  
**Subsystem:** CT2 (`/ct2` blueprint, `routes/core_transaction/ct2.py`)  
**Stack:** Flask + Supabase + Jinja2/Tailwind  

---

## Current State Audit (Already Implemented)

| Module | Routes Existing | Status |
|--------|----------------|--------|
| Auth | `/login`, `/logout`, `/change-password` | ✅ Done |
| Dashboard | `/dashboard` | ⚠️ Partial (basic widgets only) |
| Lab (LIS) | `/lab/orders`, `/lab/order/new`, `/lab/order/<id>/update` | ⚠️ Partial |
| Radiology (RIS) | `/radiology/orders`, `/radiology/order/new`, `/radiology/order/<id>/update`, delete | ⚠️ Partial |
| Surgery (SORS) | `/surgery/schedule`, `/surgery/new`, `/surgery/<id>/update`, delete | ⚠️ Partial |
| Pharmacy (PMS) | `/pharmacy/inventory`, dispense, history, item CRUD | ⚠️ Partial |
| Patients | `/patients`, `/patients/search`, `/patients/view/<id>` | ⚠️ Partial |
| Diet/Nutrition (DNMS) | `/dnms`, diet-plans, assessments, meal-tracking CRUD | ⚠️ Partial |
| EMR / Encounter | — | ❌ Not started |
| Order Hub | — | ❌ Not started |
| Results Inbox | — | ❌ Not started |
| Billing Integration | — | ❌ Not started |
| Alert Center | — | ❌ Not started |
| Worklists / Queues | — | ❌ Not started |

---

## Implementation Phases

---

### Phase 1 — EMR & Patient Encounter Management (Module A)

**Purpose:** Entry point of the clinical workflow. Every patient visit generates an encounter that ties all subsequent orders and results together.

#### 1.1 Database Tables Required

```sql
-- Encounters / Visits
CREATE TABLE encounters (
    id              SERIAL PRIMARY KEY,
    patient_id      INT REFERENCES patients(id),
    physician_id    INT REFERENCES users(id),
    encounter_date  TIMESTAMPTZ DEFAULT NOW(),
    chief_complaint TEXT,
    examination_notes TEXT,
    diagnosis       TEXT,
    icd_code        VARCHAR(20),
    status          VARCHAR(30) DEFAULT 'Active',
    -- Active | Awaiting Results | Ready for Discharge | Discharged
    discharged_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
```

#### 1.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct2/encounters` | List all active encounters |
| POST | `/ct2/encounter/new` | Create new encounter for a patient |
| GET | `/ct2/encounter/<id>` | View single encounter detail |
| POST | `/ct2/encounter/<id>/update` | Update notes/diagnosis/status |
| POST | `/ct2/encounter/<id>/discharge` | Mark encounter as Discharged |

#### 1.3 Dashboard Widgets
- **Active Patients** — count of encounters with `status = 'Active'`
- **Awaiting Results** — count with `status = 'Awaiting Results'`
- **Ready for Discharge** — count with `status = 'Ready for Discharge'`
- **Encounter Timeline** — last 10 encounters sorted by date

#### 1.4 Template Files
```
templates/subsystems/core_transaction/ct2/
    encounters.html          ← list view
    encounter_detail.html    ← single encounter + orders + results all-in-one
```

---

### Phase 2 — Order Management Hub (Module B)

**Purpose:** After diagnosis, the physician issues parallel orders to Lab, Radiology, Pharmacy, Diet, and Surgery from one unified screen.

#### 2.1 Schema Changes

Add `encounter_id` FK and `priority` column to all existing order tables:

```sql
ALTER TABLE lab_orders       ADD COLUMN encounter_id INT REFERENCES encounters(id);
ALTER TABLE lab_orders       ADD COLUMN priority VARCHAR(10) DEFAULT 'Routine';
ALTER TABLE radiology_orders ADD COLUMN encounter_id INT REFERENCES encounters(id);
ALTER TABLE radiology_orders ADD COLUMN priority VARCHAR(10) DEFAULT 'Routine';
-- Same for prescriptions, diet_plans, surgeries
```

Add a unified order tracking view:

```sql
CREATE VIEW encounter_orders AS
    SELECT 'Lab'       AS order_type, id, encounter_id, patient_id, status, created_at FROM lab_orders
    UNION ALL
    SELECT 'Radiology', id, encounter_id, patient_id, status, created_at FROM radiology_orders
    UNION ALL
    SELECT 'Pharmacy',  id, encounter_id, patient_id, status, created_at FROM prescriptions
    UNION ALL
    SELECT 'Diet',      id, encounter_id, patient_id, status, created_at FROM diet_plans
    UNION ALL
    SELECT 'Surgery',   id, encounter_id, patient_id, status, created_at FROM surgeries;
```

#### 2.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct2/encounter/<id>/orders` | Multi-order hub for one encounter |
| POST | `/ct2/encounter/<id>/order/lab` | Quick-create lab order from hub |
| POST | `/ct2/encounter/<id>/order/radiology` | Quick-create imaging order |
| POST | `/ct2/encounter/<id>/order/pharmacy` | Quick-create medication order |
| POST | `/ct2/encounter/<id>/order/diet` | Quick-create diet order |
| POST | `/ct2/encounter/<id>/order/surgery` | Quick-create surgery request |
| GET | `/ct2/orders/tracking` | Multi-order tracking dashboard (all depts) |

#### 2.3 Dashboard Widgets
- **Orders Created Today** — count across all order types
- **Pending by Type** — grouped bar: Lab / Radiology / Pharmacy / Diet / Surgery
- **In-Progress Orders** — list with drill-down
- **Completed Today** — count
- **Rejected / Cancelled** — count with reason

---

### Phase 3 — Lab (LIS) Full Workflow (Module D)

**Purpose:** Complete the lab order lifecycle from receipt through result delivery.

#### 3.1 Schema Changes

```sql
ALTER TABLE lab_orders ADD COLUMN barcode VARCHAR(50) UNIQUE;
ALTER TABLE lab_orders ADD COLUMN specimen_collected_at TIMESTAMPTZ;
ALTER TABLE lab_orders ADD COLUMN specimen_registered_at TIMESTAMPTZ;
ALTER TABLE lab_orders ADD COLUMN rejection_reason TEXT;
ALTER TABLE lab_orders ADD COLUMN result_value TEXT;
ALTER TABLE lab_orders ADD COLUMN result_unit VARCHAR(30);
ALTER TABLE lab_orders ADD COLUMN result_reference_range VARCHAR(50);
ALTER TABLE lab_orders ADD COLUMN is_critical BOOLEAN DEFAULT FALSE;
ALTER TABLE lab_orders ADD COLUMN verified_by INT REFERENCES users(id);
ALTER TABLE lab_orders ADD COLUMN verified_at TIMESTAMPTZ;
ALTER TABLE lab_orders ADD COLUMN report_url TEXT;
ALTER TABLE lab_orders ADD COLUMN charge_posted BOOLEAN DEFAULT FALSE;
-- Status values: Ordered | Specimen Collected | Registered | In Analysis | Awaiting Verification | Verified | Critical | Rejected
```

#### 3.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| POST | `/ct2/lab/order/<id>/collect-specimen` | Record specimen collection + auto-generate barcode |
| POST | `/ct2/lab/order/<id>/register-specimen` | Validate and register specimen |
| POST | `/ct2/lab/order/<id>/reject` | Reject specimen with reason |
| POST | `/ct2/lab/order/<id>/enter-results` | Enter analysis results |
| POST | `/ct2/lab/order/<id>/verify` | Verify results (senior lab tech) |
| GET | `/ct2/lab/order/<id>/report` | View/download lab report PDF |
| GET | `/ct2/lab/worklist` | Lab staff role-based worklist |

#### 3.3 Critical Result Logic
- After `enter-results`: if value outside reference range flagged `is_critical = True`
- Auto-create `Notification` to the ordering physician
- Dashboard badge shows unacknowledged critical results

#### 3.4 Dashboard Widgets
- Pending specimen collection
- Specimens awaiting registration
- Rejected specimens (today)
- Tests in analysis
- Awaiting verification
- Critical unacknowledged results
- Average turnaround time

---

### Phase 4 — Radiology (RIS) Full Workflow (Module E)

#### 4.1 Schema Changes

```sql
ALTER TABLE radiology_orders ADD COLUMN scheduled_at TIMESTAMPTZ;
ALTER TABLE radiology_orders ADD COLUMN patient_prep_status VARCHAR(30) DEFAULT 'Pending';
ALTER TABLE radiology_orders ADD COLUMN imaging_completed_at TIMESTAMPTZ;
ALTER TABLE radiology_orders ADD COLUMN interpreter_id INT REFERENCES users(id);
ALTER TABLE radiology_orders ADD COLUMN report_text TEXT;
ALTER TABLE radiology_orders ADD COLUMN report_url TEXT;
ALTER TABLE radiology_orders ADD COLUMN is_critical BOOLEAN DEFAULT FALSE;
ALTER TABLE radiology_orders ADD COLUMN critical_findings TEXT;
ALTER TABLE radiology_orders ADD COLUMN report_validated_at TIMESTAMPTZ;
ALTER TABLE radiology_orders ADD COLUMN charge_posted BOOLEAN DEFAULT FALSE;
-- Status: Ordered | Scheduled | Patient Prep | Imaging | Interpretation | Report Validated | Critical | Completed
```

#### 4.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| POST | `/ct2/radiology/order/<id>/schedule` | Set appointment datetime |
| POST | `/ct2/radiology/order/<id>/prep-status` | Update patient preparation status |
| POST | `/ct2/radiology/order/<id>/imaging-done` | Mark imaging completed |
| POST | `/ct2/radiology/order/<id>/interpret` | Radiologist enters report + critical flag |
| POST | `/ct2/radiology/order/<id>/validate` | Senior validates report |
| GET | `/ct2/radiology/order/<id>/report` | Report viewer / PDF |
| GET | `/ct2/radiology/worklist` | Radiologist interpretation queue |

#### 4.3 Dashboard Widgets
- Pending scheduling
- Awaiting scan (scheduled but not done)
- Awaiting interpretation
- Critical findings unacknowledged
- Average imaging turnaround

---

### Phase 5 — Pharmacy (PMS) Full Workflow (Module F)

**Purpose:** Complete the existing `/pharmacy/dispense` into a full clinical safety + eMAR workflow.

#### 5.1 Schema Changes

```sql
ALTER TABLE prescriptions ADD COLUMN encounter_id INT REFERENCES encounters(id);
ALTER TABLE prescriptions ADD COLUMN safety_check_status VARCHAR(20) DEFAULT 'Pending';
ALTER TABLE prescriptions ADD COLUMN safety_flag_reason TEXT;
ALTER TABLE prescriptions ADD COLUMN dispensed_at TIMESTAMPTZ;
ALTER TABLE prescriptions ADD COLUMN dispensed_by INT REFERENCES users(id);
ALTER TABLE prescriptions ADD COLUMN label_printed BOOLEAN DEFAULT FALSE;
ALTER TABLE prescriptions ADD COLUMN charge_posted BOOLEAN DEFAULT FALSE;

CREATE TABLE emar_records (
    id              SERIAL PRIMARY KEY,
    prescription_id INT REFERENCES prescriptions(id),
    patient_id      INT REFERENCES patients(id),
    administered_at TIMESTAMPTZ,
    administered_by INT REFERENCES users(id),
    dose_given      VARCHAR(50),
    notes           TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
```

#### 5.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| POST | `/ct2/pharmacy/order/<id>/safety-check` | Run clinical safety check, flag unsafe |
| POST | `/ct2/pharmacy/order/<id>/override` | Physician override unsafe flag |
| POST | `/ct2/pharmacy/order/<id>/dispense` | Confirm dispense + inventory deduction |
| POST | `/ct2/pharmacy/order/<id>/label` | Print/generate medication label |
| POST | `/ct2/pharmacy/emar/add` | Record medication administration |
| GET | `/ct2/pharmacy/emar/<patient_id>` | eMAR view for a patient |
| GET | `/ct2/pharmacy/worklist` | Pharmacist dispensing queue |

#### 5.3 Dashboard Widgets
- Medication orders pending verification
- Unsafe medication alerts
- Out-of-stock medications
- Dispensed today
- Pharmacy interventions (overrides)

---

### Phase 6 — Diet / Nutrition (DNMS) Full Workflow (Module G)

**Purpose:** Extend existing DNMS with approval, delivery tracking, and intake monitoring.

#### 6.1 Schema Changes

```sql
ALTER TABLE diet_plans ADD COLUMN encounter_id INT REFERENCES encounters(id);
ALTER TABLE diet_plans ADD COLUMN approved_by INT REFERENCES users(id);
ALTER TABLE diet_plans ADD COLUMN approved_at TIMESTAMPTZ;

ALTER TABLE meal_tracking ADD COLUMN scheduled_time TIMESTAMPTZ;
ALTER TABLE meal_tracking ADD COLUMN delivered_at TIMESTAMPTZ;
ALTER TABLE meal_tracking ADD COLUMN intake_percentage INT;  -- 0-100
ALTER TABLE meal_tracking ADD COLUMN intake_exception_reason TEXT;
```

#### 6.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| POST | `/ct2/dnms/diet-plans/<id>/approve` | Dietitian approves plan |
| POST | `/ct2/dnms/meal-tracking/<id>/deliver` | Mark meal delivered |
| POST | `/ct2/dnms/meal-tracking/<id>/intake` | Record patient intake % |
| GET | `/ct2/dnms/worklist` | Pending diet assessments queue |

#### 6.3 Dashboard Widgets
- Pending diet assessments
- Meals scheduled today
- Meals delivered
- Intake exceptions (< 50% consumed)
- Active therapeutic diets

---

### Phase 7 — Surgery / OR (SORS) Full Workflow (Module H)

**Purpose:** Extend existing surgery schedule with pre-op, resource checks, intraoperative, and post-op tracking.

#### 7.1 Schema Changes

```sql
ALTER TABLE surgeries ADD COLUMN encounter_id INT REFERENCES encounters(id);
ALTER TABLE surgeries ADD COLUMN preop_cleared BOOLEAN DEFAULT FALSE;
ALTER TABLE surgeries ADD COLUMN preop_notes TEXT;
ALTER TABLE surgeries ADD COLUMN or_room VARCHAR(20);
ALTER TABLE surgeries ADD COLUMN surgical_team JSONB;          -- [{user_id, role}]
ALTER TABLE surgeries ADD COLUMN equipment_checklist JSONB;
ALTER TABLE surgeries ADD COLUMN resource_conflict BOOLEAN DEFAULT FALSE;
ALTER TABLE surgeries ADD COLUMN resource_conflict_reason TEXT;
ALTER TABLE surgeries ADD COLUMN started_at TIMESTAMPTZ;
ALTER TABLE surgeries ADD COLUMN ended_at TIMESTAMPTZ;
ALTER TABLE surgeries ADD COLUMN intraop_notes TEXT;
ALTER TABLE surgeries ADD COLUMN postop_status VARCHAR(30);
ALTER TABLE surgeries ADD COLUMN recovery_location VARCHAR(50);
ALTER TABLE surgeries ADD COLUMN charge_posted BOOLEAN DEFAULT FALSE;
-- Status: Requested | Pre-Op | Resource Check | Scheduled | In Progress | Post-Op | Recovery | Completed | Cancelled
```

#### 7.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| POST | `/ct2/surgery/<id>/preop-assessment` | Record pre-op clearance notes |
| POST | `/ct2/surgery/<id>/resource-check` | Check OR / team / equipment availability |
| POST | `/ct2/surgery/<id>/reschedule` | Reschedule with conflict reason + notification |
| POST | `/ct2/surgery/<id>/start` | Mark surgery in-progress + record start time |
| POST | `/ct2/surgery/<id>/intraop-update` | Update intraoperative notes |
| POST | `/ct2/surgery/<id>/complete` | Mark complete + transfer to recovery |
| POST | `/ct2/surgery/<id>/postop-update` | Post-operative status update |
| POST | `/ct2/surgery/<id>/post-charges` | Send charge to billing |
| GET | `/ct2/surgery/or-board` | Real-time OR status board |

#### 7.3 Dashboard Widgets
- Pending surgery requests
- Awaiting pre-op clearance
- Resource conflicts
- Scheduled (upcoming)
- In-progress surgeries
- Post-op / recovery patients
- Charge capture status

---

### Phase 8 — Results & Reports Inbox (Module C)

**Purpose:** Unified physician inbox for reviewing results from all departments.

#### 8.1 Schema — Results Inbox

```sql
CREATE TABLE result_inbox (
    id              SERIAL PRIMARY KEY,
    encounter_id    INT REFERENCES encounters(id),
    patient_id      INT REFERENCES patients(id),
    physician_id    INT REFERENCES users(id),
    source_module   VARCHAR(20),  -- Lab | Radiology | Pharmacy | Diet | Surgery
    source_record_id INT,
    summary         TEXT,
    is_critical     BOOLEAN DEFAULT FALSE,
    acknowledged    BOOLEAN DEFAULT FALSE,
    acknowledged_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
```

#### 8.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct2/inbox` | Consolidated results inbox (all sources) |
| POST | `/ct2/inbox/<id>/acknowledge` | Mark result reviewed + update encounter status |
| GET | `/ct2/inbox/critical` | Critical-only filtered view |

#### 8.3 Auto-Population Triggers
Each result-entry route (lab verify, radiology validate, pharmacy dispense, surgery complete) auto-inserts a row into `result_inbox` for the ordering physician.

#### 8.4 Dashboard Widgets
- Results awaiting review (by module)
- Critical results not yet acknowledged
- Recently completed reports

---

### Phase 9 — Central Billing Integration (Module I)

**Purpose:** Aggregate charge postings from Lab, Radiology, Pharmacy, and Surgery into the central `invoices` table.

#### 9.1 Billing Route (Shared Utility)

```python
# utils/billing.py
def post_charge(patient_id, encounter_id, source_module, description, amount):
    """Insert a charge row into invoices and mark charge_posted on the source record."""
```

#### 9.2 Routes to Build

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct2/billing/charges` | Unposted charges view (per department) |
| POST | `/ct2/billing/post/<module>/<record_id>` | Manually post a charge |
| GET | `/ct2/billing/encounter/<encounter_id>` | Full bill for one encounter |

#### 9.3 Dashboard Widgets
- Unposted charges (by dept)
- Charges received today
- Bills generated
- Billing exceptions (missing charges)

---

### Phase 10 — Alert Center & Worklists (Modules J & K)

#### 10.1 Alert Center Routes

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct2/alerts` | All active system alerts (critical results + safety flags) |
| POST | `/ct2/alerts/<id>/acknowledge` | Acknowledge with timestamp |

#### 10.2 Role-Based Worklists

| Route | Audience |
|-------|----------|
| `/ct2/lab/worklist` | Lab technicians |
| `/ct2/radiology/worklist` | Radiologists |
| `/ct2/pharmacy/worklist` | Pharmacists |
| `/ct2/dnms/worklist` | Dietitians |
| `/ct2/surgery/or-board` | Surgeons / OR nurses |

---

### Phase 11 — End-to-End Status Tracking (Module L)

#### 11.1 Routes

| Method | Route | Function |
|--------|-------|----------|
| GET | `/ct2/encounter/<id>/timeline` | Full order + result lifecycle for one patient |
| GET | `/ct2/tracking` | System-wide order lifecycle board |

#### 11.2 Timeline Entry Logic
Every status transition (order created → specimen collected → result entered → reviewed) auto-appends to a `transaction_log` JSONB column on the encounter, or a separate `encounter_events` table.

---

## Recommended Build Order

```
Phase 1  →  EMR Encounter (foundation — all phases depend on encounter_id)
Phase 2  →  Order Hub (wires encounter to all departments)
Phase 3  →  Lab full workflow
Phase 4  →  Radiology full workflow
Phase 5  →  Pharmacy full workflow
Phase 6  →  Diet/Nutrition full workflow
Phase 7  →  Surgery full workflow
Phase 8  →  Results Inbox (depends on all dept workflows being complete)
Phase 9  →  Billing integration
Phase 10 →  Alert Center + Worklists
Phase 11 →  End-to-end Timeline
```

---

## New Database Tables Summary

| Table | Phase |
|-------|-------|
| `encounters` | 1 |
| `emar_records` | 5 |
| `result_inbox` | 8 |

## Column Additions Summary

| Table | Columns Added | Phase |
|-------|--------------|-------|
| `lab_orders` | barcode, specimen timestamps, result fields, is_critical, charge_posted | 3 |
| `radiology_orders` | scheduled_at, prep status, report fields, is_critical, charge_posted | 4 |
| `prescriptions` | safety_check_status, safety_flag_reason, dispense fields, eMAR link | 5 |
| `diet_plans` | approved_by, approved_at, encounter_id | 6 |
| `meal_tracking` | scheduled_time, delivered_at, intake_percentage | 6 |
| `surgeries` | preop, resource_check, OR fields, intraop, postop, charge_posted | 7 |
| All order tables | `encounter_id`, `priority` | 2 |

---

## Notes

- All new routes follow the existing pattern: `@ct2_bp.route(...)` + `@login_required` + `@policy_required('ct2')`
- Critical result alerts use the existing `Notification.create()` model
- Billing charges write to `invoices` table (already used by CT1 telehealth)
- Barcode generation: use `uuid.uuid4().hex[:12].upper()` as specimen barcode
- All status transitions should write an entry to `AuditLog` for traceability
