# CT1 – Core Transaction 1: Implementation Plan
**Prepared:** March 11, 2026  
**Author:** Reiniel (requirements) / Development Team  
**Scope:** Smart Patient Registration, Appointment Scheduling, Telehealth & Outpatient, Bed Management

---

## Table of Contents
1. [Smart Patient Registration — Input Validation Fixes](#1-smart-patient-registration--input-validation-fixes)
2. [Patient Portal Registration — To-Be Features](#2-patient-portal-registration--to-be-features)
3. [Appointment Scheduling — Patient Portal](#3-appointment-scheduling--patient-portal)
4. [Telehealth & Outpatient Module](#4-telehealth--outpatient-module)
5. [Bed Management Module](#5-bed-management-module)
6. [Database Changes Required](#6-database-changes-required)
7. [Files Affected](#7-files-affected)
8. [Implementation Priority](#8-implementation-priority)

---

## 1. Smart Patient Registration — Input Validation Fixes

These are **bug fixes** on existing fields — no new features, just input enforcement.

| # | Field | Current Problem | Fix |
|---|---|---|---|
| 1.1 | First Name / Last Name | Accepts numbers | Restrict to letters only (alpha + spaces + hyphens) |
| 1.2 | Date of Birth — Year | Accepts 6 digits | Restrict to exactly 4 digits; enforce valid range (e.g. 1900–current year) |
| 1.3 | Contact Number | Accepts letters | Restrict to digits only; enforce PH format |
| 1.4 | Insurance Group # | Accepts letters | Restrict to digits only |
| 1.5 | Insurance Details — Group # | Accepts letters | Restrict to digits only |

### Implementation Notes
- All validations should fire **both client-side** (HTML5 `pattern` + JS `oninput`) and **server-side** (Python route).
- Use `pattern="[A-Za-z\s\-]+"` on name fields.
- Use `pattern="[0-9]{4}"` on year; `min` / `max` attributes on the date field.
- Use `pattern="[0-9]+"` on group # fields.

---

## 2. Patient Portal Registration — To-Be Features

### 2.1 Phone Number Validation
- **Rule:** Only Philippine standard formats accepted: `+63XXXXXXXXXX` or `09XXXXXXXXX`
- **Client-side:** Regex `^(\+63|09)\d{9}$` on `oninput`; red border + error message if invalid
- **Server-side:** Same regex check before INSERT; return 400 with JSON error for AJAX forms

### 2.2 Required Fields Enforcement
- Every field in the registration form must be marked `required`
- Submit button stays disabled until all fields pass validation (JS `checkValidity()`)
- Server-side: validate each field is non-empty; return field-level error messages

### 2.3 Name Field Validation
- **Surname, First Name:** letters, spaces, hyphens, apostrophes only
- Reject on any digit input (`oninput` strips digits or shows inline error)
- Server-side: `re.match(r"^[A-Za-z\s\-']+$", value)`

### 2.4 Real-Time Duplicate Check (Phone & Username)
- On `blur` of phone number and username fields: fire AJAX call to `/patient/check-duplicate`
- Route returns `{ "exists": true/false, "field": "phone|username" }`
- If exists → show red inline badge **"Already Used"** and disable submit
- Prevents duplicate accounts without a full form submission

### 2.5 Real-Time Field Validation
- Each field validates on `blur` (not just on submit)
- Invalid field gets a red border + helper text below
- Valid field gets a green checkmark
- User does **not** need to restart the form; only the failing field is flagged

### 2.6 Terms & Policy Pop-up
- A modal appears **before** the registration form is submitted
- Contents:
  - Rescheduling policy (within 24 hours, one-time only)
  - Cancellation policy (within 24 hours, ₱560 late cancellation fee)
  - No-show penalty (₱1,500; 3 strikes = account ban)
  - Clinic hours (7:00 AM – 3:00 PM)
- Patient must **tick "I Agree"** checkbox before the modal confirm button activates
- On confirm, form proceeds to submission; on cancel, modal closes with no submission

### 2.7 Temporary Patient ID Generation
- After initial screening passes, system auto-generates a **Temp Patient ID** (format: `TMP-YYYYMMDD-XXXXX`)
- Stored in `patients` table with `status = 'Temporary'`
- Upgraded to official Patient ID after document submission + duplicate check

### 2.8 Real-Time Critical Alert
- If patient flags a critical condition during registration (checkbox or triage field), system sends an immediate notification to on-duty staff
- Uses the existing `Notification.create()` system targeting `ct1` subsystem admins

### 2.9 Document Submission Gate
- Patient cannot advance past the document submission step without uploading required files
- Required documents: Government ID + Insurance card (if applicable)
- File validation: PDF / JPG / PNG only, max 5 MB each

### 2.10 Duplicate Patient Record Check
- Before creating a new patient record, check existing records for matching:
  - Full name + date of birth
  - Phone number
  - Insurance ID
- If match found: show warning with options to merge or continue as new
- Prevents duplicate `patients` table entries

### 2.11 Official Patient ID Generation
- After all checks pass, system generates official ID (format: `PT-YYYY-XXXXX`, sequential)
- Temporary record is updated: `status = 'Active'`, `patient_id = generated_id`

### 2.12 Insurance Verification
- System checks `insurance_group_number` against existing records in `patients` table
- Flags if same group number is already linked to another active patient with same insurer
- Warning shown; admin can override

### 2.13 Queue Number Assignment
- On successful registration completion, system auto-assigns a **queue number** for the day
- Format: `Q-HHMMSS` or sequential counter per day, displayed on confirmation screen

### 2.14 Visit Type Selection
- Patient selects visit type during registration/intake:
  - `Consultation`
  - `Follow-up`
  - `Telehealth`
- Saved to `appointments.visit_type` field

---

## 3. Appointment Scheduling — Patient Portal

### 3.1 Date & Time Restrictions
| Rule | Detail |
|---|---|
| No past dates | `min` attribute = today's date; server-side check |
| Allowed hours | 7:00 AM – 3:00 PM only; slots outside this range are hidden/disabled |
| Occupied slots | Already-booked slots are shown as greyed-out and unselectable |
| Duplicate booking | Prevent two bookings for same doctor + same date/time |

### 3.2 Rescheduling Rules
- Patient may reschedule **up to 24 hours before** the appointment
- **One reschedule per appointment** only (tracked via `appointments.reschedule_count`)
- Admin dashboard shows reschedule history: date rescheduled, whether limit has been used
- No admin approval needed if: date is valid + within clinic hours + slot available

### 3.3 Cancellation Rules
- Patient may cancel **up to 24 hours before** the appointment — no penalty
- Cancellation **less than 24 hours before** → auto-generate ₱560 late cancellation fee in billing
- Billing record created automatically and linked to patient account

### 3.4 No-Show Rule
- If patient has not been checked in within **15 minutes** of appointment time → status auto-changes to `No Show`
- System auto-generates ₱1,500 no-show penalty in patient billing
- After **3 no-shows**: patient's phone number is flagged; account is banned from new bookings
- Ban is enforced both at booking form level and server-side on POST

### 3.5 SMS Reminders
- **24 hours before** appointment: SMS reminder sent
- **1 hour before** appointment: second SMS reminder
- SMS content: appointment date, time, doctor name, clinic address
- Requires integration with SMS gateway (e.g. Semaphore, Vonage, Twilio)
- Can be mocked with email fallback if SMS gateway not yet configured

### 3.6 Arrival & No-Show Tagging
- Admin/staff side: **"Mark as Arrived"** button per appointment (sets status = `Show`)
- Admin/staff side: **"Mark as No-Show"** button (manual override, triggers penalty)
- Patient portal: read-only status display

### 3.7 Multiple Click Protection
- **Confirm Appointment** button disables immediately on first click
- Shows spinner / "Submitting…" state to prevent duplicate POSTs
- Server-side: check for existing pending booking with same doctor + timeslot before INSERT

### 3.8 Terms & Policy Display
- Policy clearly shown in the booking form (collapsible or always visible):
  - Reschedule: 24 hours before, one-time only
  - Cancellation: 24 hours before; ₱560 if late
  - No-show: ₱1,500 penalty; 3 no-shows = account ban
  - Clinic hours: 7:00 AM – 3:00 PM
- Checkbox: **"I have read and agree to the policies"** — required before submit

### 3.9 Automatic Billing Integration
- All auto-generated fees (late cancellation, no-show) create records in `billing_records`
- Automatically reflected in patient's portal under "Balance Due"

---

## 4. Telehealth & Outpatient Module

### 4.1 Appointment Year Validation
- Year input field: max 4 digits (`maxlength="4"`, `pattern="\d{4}"`)
- Validate on input; reject if not a valid 4-digit year ≥ current year

### 4.2 Meeting Link Generation
- On telehealth appointment confirmation, system auto-generates a unique meeting link
- Recommended: Daily.co or Jitsi Meet (self-hosted) embedded iframe, or generate a unique URL token
- Link stored in `telehealth_sessions.meeting_link`
- Link only becomes active at scheduled time (validate `scheduled_at <= now()` before allowing entry)

### 4.3 Doctor Availability View
- Patient booking form shows list of available doctors with their open time slots
- Based on `appointments` table: slots already booked for a doctor are excluded
- "No available slots" message shown if doctor is fully booked for selected date

### 4.4 Duplicate Booking Prevention
- Same as appointment scheduling: prevent same patient from booking same doctor + same timeslot
- Alert shown immediately on slot selection if conflict detected

### 4.5 Session Entry Control
- Patient cannot join meeting before `scheduled_at` time
- "Join" button is disabled/hidden until 5 minutes before scheduled time
- Server-side validation: reject join attempts before `scheduled_at - 5 minutes`

### 4.6 Meeting Duration Monitoring
- Record `session_start` and `session_end` timestamps in `telehealth_sessions`
- Duration = `session_end - session_start`
- Displayed in consultation history

### 4.7 Digital Prescription Generation
- After consultation is completed, doctor fills out prescription form (medications, dosage, instructions)
- System generates a PDF prescription automatically
- Stored in patient's medical record; downloadable from patient portal
- Prescription linked to `telehealth_sessions.id` and `medical_records`

### 4.8 File Upload for Medical Documents
- Doctors and patients can upload: lab results, medical images, referral letters
- Accepted formats: PDF, JPG, PNG, DICOM (optional)
- Max file size: 10 MB
- File validation enforced client-side and server-side
- Files stored in a dedicated Supabase storage bucket (`patient-documents`)
- Files linked to patient's `medical_records` entry

### 4.9 Telehealth Appointment Status Tracking
| Status | Trigger |
|---|---|
| `Scheduled` | Booking confirmed |
| `In Progress` | Doctor or patient joins; `session_start` recorded |
| `Completed` | Doctor ends session; `session_end` recorded |
| `Cancelled` | Patient or admin cancels before session |
| `No Show` | Patient did not join within 15 minutes of scheduled time |

### 4.10 Consultation Record & Medical Record Integration
- Each completed telehealth session creates/updates a `medical_records` entry
- Fields saved: chief complaint, doctor notes, diagnosis, prescriptions, uploaded files
- Record visible to patient in their portal

### 4.11 History Tracking
- Doctor portal: view list of all past telehealth consultations per patient with date, diagnosis, prescriptions

### 4.12 Follow-up Scheduling
- After completing a consultation, doctor can immediately schedule a follow-up telehealth appointment
- Pre-fills doctor_id and patient_id; doctor selects new date/time

### 4.13 Outpatient (Face-to-Face) Booking
- Outpatient F2F booking follows the **same flow** as Telehealth booking
- `visit_type = 'Outpatient'` in `appointments` table
- No meeting link generated; physical room/clinic assigned instead

---

## 5. Bed Management Module

### 5.1 Bed Status Filter
- Filter buttons on Bed Management page:
  - **All** (default)
  - **Available** (green)
  - **Occupied** (red)
  - **Cleaning** (amber)
- Clicking a filter shows only beds of that status (client-side JS filter + server-side param)

### 5.2 Automatic Bed Status Workflow
Remove the manual "Mark Occupied" button. The new automated flow:

```
[Assign Patient] → Occupied
      ↓
[Discharge Patient] → Cleaning
      ↓
[Mark Clean] → Available
```

- **Assign Patient:** Bed status → `Occupied`; `assigned_patient_id` and `assigned_at` recorded
- **Discharge Patient:** Bed status → `Cleaning`; `discharged_at` recorded; discharge report auto-generated
- **Mark Clean:** Bed status → `Available`; `cleaned_at` recorded; `assigned_patient_id` cleared

### 5.3 Add Bed Validation
Before saving a new bed, the system must validate:

| Field | Rule |
|---|---|
| Ward | Required |
| Room Number | Required; must be unique within the ward |
| Bed Type | Required |
| Bed ID | Required; must be globally unique |
| Duplicate Check | Alert if same Room Number + Bed ID combination already exists |

- Client-side: AJAX duplicate check on Room Number + Bed ID blur
- Server-side: check `beds` table before INSERT; return clear error if duplicate found

### 5.4 Discharge Report Generation
- Triggered automatically on patient discharge
- Report contents:
  - Patient name and ID
  - Admission date & discharge date
  - Ward and bed number
  - Attending physician
  - Primary diagnosis
  - Treatment summary
  - Follow-up instructions (if any)
  - Discharge status (Recovered, Referred, AMA, Expired)
- Report generated as PDF using `reportlab`
- Stored in `patient-documents` storage bucket; linked to patient record
- Downloadable by patient from portal; visible to admin

---

## 6. Database Changes Required

```sql
-- Patients table additions
ALTER TABLE patients ADD COLUMN IF NOT EXISTS temp_id VARCHAR(30);
ALTER TABLE patients ADD COLUMN IF NOT EXISTS status VARCHAR(30) DEFAULT 'Active'; -- Active, Temporary, Banned
ALTER TABLE patients ADD COLUMN IF NOT EXISTS no_show_count INTEGER DEFAULT 0;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS is_banned BOOLEAN DEFAULT FALSE;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS ban_reason TEXT;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS queue_number VARCHAR(20);
ALTER TABLE patients ADD COLUMN IF NOT EXISTS terms_agreed BOOLEAN DEFAULT FALSE;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS terms_agreed_at TIMESTAMP;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS visit_type VARCHAR(30); -- Consultation, Follow-up, Telehealth, Outpatient

-- Appointments table additions
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS visit_type VARCHAR(30) DEFAULT 'Consultation';
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS reschedule_count INTEGER DEFAULT 0;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS last_rescheduled_at TIMESTAMP;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS original_date DATE;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS cancellation_fee DECIMAL(10,2) DEFAULT 0.00;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS no_show_fee DECIMAL(10,2) DEFAULT 0.00;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS checked_in_at TIMESTAMP;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS terms_agreed BOOLEAN DEFAULT FALSE;

-- Telehealth sessions additions
ALTER TABLE telehealth_sessions ADD COLUMN IF NOT EXISTS session_start TIMESTAMP;
ALTER TABLE telehealth_sessions ADD COLUMN IF NOT EXISTS session_end TIMESTAMP;
ALTER TABLE telehealth_sessions ADD COLUMN IF NOT EXISTS duration_minutes INTEGER;
ALTER TABLE telehealth_sessions ADD COLUMN IF NOT EXISTS prescription_url TEXT;
ALTER TABLE telehealth_sessions ADD COLUMN IF NOT EXISTS no_show_fee_applied BOOLEAN DEFAULT FALSE;

-- Beds table additions
ALTER TABLE beds ADD COLUMN IF NOT EXISTS assigned_patient_id INTEGER REFERENCES patients(id);
ALTER TABLE beds ADD COLUMN IF NOT EXISTS assigned_at TIMESTAMP;
ALTER TABLE beds ADD COLUMN IF NOT EXISTS discharged_at TIMESTAMP;
ALTER TABLE beds ADD COLUMN IF NOT EXISTS cleaned_at TIMESTAMP;
ALTER TABLE beds ADD COLUMN IF NOT EXISTS discharge_report_url TEXT;

-- New: patient-documents bucket (add to storage setup SQL)
-- bucket: 'patient-documents', public: true
-- policies: SELECT, INSERT, UPDATE, DELETE (public for dev)
```

---

## 7. Files Affected

| File | Changes Needed |
|---|---|
| `routes/patient.py` | Add validation helpers, duplicate check endpoint, queue assignment, ban check, billing auto-creation |
| `routes/ct1/` (or equivalent) | Appointment scheduling logic, no-show timer, rescheduling rules, telehealth session control |
| `templates/patient/register.html` | Real-time validation JS, Terms modal, duplicate check AJAX, name/phone/year field patterns |
| `templates/patient/appointment.html` | Date/time restrictions, slot availability display, confirm button protection, terms display |
| `templates/ct1/telehealth.html` | Meeting link display, join-time gating, status tracking |
| `templates/ct1/beds.html` | Status filter buttons, automated workflow buttons (Discharge, Mark Clean), add bed validation |
| `utils/pdf_generator.py` (new) | Discharge report PDF, digital prescription PDF generation using `reportlab` |
| `supabase_setup.sql` | New columns above + `patient-documents` bucket |

---

## 8. Implementation Priority

| Priority | Module | Effort |
|---|---|---|
| 🔴 **P1 — Critical** | Input validation fixes (name, DOB year, phone, group #) | Low |
| 🔴 **P1 — Critical** | Required fields enforcement | Low |
| 🔴 **P1 — Critical** | Duplicate phone/username real-time check | Medium |
| 🟡 **P2 — High** | Terms & Policy pop-up (registration + booking) | Low |
| 🟡 **P2 — High** | Appointment date/time restrictions + occupied slot display | Medium |
| 🟡 **P2 — High** | Bed status workflow automation + filter | Medium |
| 🟡 **P2 — High** | No-show auto-detection (15 min) + ₱1,500 penalty billing | Medium |
| 🟡 **P2 — High** | Rescheduling rules (24h, one-time) + billing for late cancel | Medium |
| 🟢 **P3 — Medium** | Temp Patient ID + Official Patient ID generation | Medium |
| 🟢 **P3 — Medium** | Queue number assignment | Low |
| 🟢 **P3 — Medium** | Telehealth session control (join time gate, duration tracking) | Medium |
| 🟢 **P3 — Medium** | Discharge report PDF auto-generation | Medium |
| 🔵 **P4 — Low** | Digital prescription PDF | High |
| 🔵 **P4 — Low** | Meeting link auto-generation (Jitsi/Daily.co) | High |
| 🔵 **P4 — Low** | SMS reminders (requires SMS gateway integration) | High |
| 🔵 **P4 — Low** | Ban system for 3 no-shows | Medium |

---

*This document reflects all CT1 requirements raised by Reiniel. Each section maps directly to a feature or fix to be built. Implementation begins with P1 items.*
