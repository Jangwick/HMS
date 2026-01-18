# HMS Implementation Plan: Feature Integration from Hospital Interviews

This document outlines the step-by-step process to implement the features identified during the hospital interviews into the Hospital Management System (HMS).

## Phase 1: Database Schema Expansion
The current system only has a `users` table. We need to create a robust schema to support all modules.

### 1.1 HR Module Tables
- `applicants`: Info, documents, screening status.
- `vacancies`: Job requirements, approval status, posting sites.
- `employees`: Extended from `users`, includes 201 file details, bank info, tax.
- `onboarding_checklists`: Tasks, completion status.
- `performance_reviews`: KPIs, notes, evaluation results.
- `competencies`: Skill lists per role, assessment results.
- `trainings`: Schedules, attendance, materials, certificates.
- `attendance_logs`: Clock-in/out, breaks.
- `leave_requests`: Type, balance, approval flow.
- `claims`: Reimbursements, receipts.

### 1.2 Core Transaction Tables
- `patients`: Registration info, identifiers, documents.
- `appointments`: Doctor availability, room/equipment scheduling.
- `telehealth_sessions`: Intake forms, consent, clinical notes.
- `er_triage`: Vitals, pain score, priority level.
- `beds`: Status (occupied, cleaning, etc.), ward assignment.
- `lab_orders`: LIS integration, results, critical alerts.
- `radiology_requests`: RIS/PACS integration, reports.
- `prescriptions`: Pharmacy stock, allergy checks, dispensing.
- `surgery_schedules`: OR room, staff, equipment.

### 1.3 Logistics & Financials Tables
- `inventory`: Stock levels, expiry, batch/lot.
- `purchase_requests/orders`: Procurement flow.
- `assets`: Maintenance history, warranty, tagging.
- `fleet_vehicles`: Maintenance, trip logs, fuel.
- `billing_records`: Charges from all depts, insurance/HMO.
- `general_ledger`: Chart of accounts, postings.

---

## Phase 2: Module-by-Module Implementation

### Step 1: Human Resources (HR1 - HR4)
1.  **Recruitment & Onboarding**: Build the applicant portal and onboarding checklist system.
2.  **Competency & Learning**: Implement the skills assessment and training tracker.
3.  **Time & Attendance**: Integrate biometric data (simulated) and shift scheduling.
4.  **Payroll**: Build the computation engine for OT, taxes, and benefits.

### Step 2: Core Transactions (CT1 - CT3)
1.  **Patient Access**: Smart registration with duplicate detection and appointment booking.
2.  **Clinical Ops**: LIS/RIS/PMS modules with auto-posting to billing.
3.  **EMR & Billing**: Centralized clinical notes and the final discharge clearance workflow.

### Step 3: Logistics & Fleet (Log1 - Log2)
1.  **Supply Chain**: Warehouse management with expiry alerts and 3-way match procurement.
2.  **Fleet**: Vehicle reservation system and trip performance monitoring.

### Step 4: Financials (Fin1 - Fin6)
1.  **Accounting**: Disbursement vouchers, budget monitoring, and GL automation.
2.  **Revenue**: Collection/Cashiering and AR aging reports.

---

## Phase 3: Integration & Intelligence
1.  **Cross-Module Alerts**: e.g., Low stock in Pharmacy alerts Logistics.
2.  **Dashboards (HADS/AN1)**: Real-time KPIs for management (census, revenue, attendance).
3.  **Security (ISASI)**: Role-based access control (RBAC) and audit logs.

---

## Implementation Prompt for AI Assistant
Use the following prompt to guide the AI in building these features:

> "I need to implement the following features into my HMS based on hospital interview data. 
> 1. **HR**: Implement a full recruitment-to-onboarding pipeline, competency tracking, and a payroll system that handles OT and HMO deductions.
> 2. **Clinical**: Create a Smart Patient Registration System (SPRS) with duplicate detection, an EMR for clinical notes, and integrated LIS/RIS/Pharmacy modules that auto-post charges to billing.
> 3. **Logistics**: Build a warehouse system with expiry alerts and a fleet management tool for vehicle reservations.
> 4. **Financials**: Implement a General Ledger that syncs with all modules, a disbursement voucher system, and an AR aging report.
> 
> Please start by updating the database schema in `supabase_setup.sql` to include all necessary tables, then proceed to implement the backend logic in `routes/` and the UI in `templates/subsystems/` following the existing project structure. Ensure all designs are premium, responsive, and use the established CSS variables."
