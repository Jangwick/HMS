# HMS Data Integration Plan

This document outlines the detailed transaction workflows and data integration strategy for the Hospital Management System (HMS), based on requirements gathered from current hospital operations.

## 1. Unified Identity & Lifecycle (Staff Entry to Exit)
The system bridges the gap between manual "Paper 201 Files" and a centralized digital identity.

*   **Workflow: Recruitment to Onboarding (HR1 → HR3)**
    *   **Action**: Applicants are captured (Walk-in/Agency) in `applicants`. After clinical/HR interview and verification (License/PRC check), a job offer is made.
    *   **Data Handshake**: Once accepted, the record moves to `onboarding`.
    *   **Identity Creation**: **HR3** approves the onboarding status, auto-generating a record in the `users` table with an employee ID.
    *   **System Access**: This triggers access rights across clinical (CT) and financial (FIN) portals based on the job role.

## 2. The Integrated Clinical Value Chain (CT1 → CT2 → LOG → FIN)
Aligning patient registration, clinical orders, and inventory consumption with real-time billing.

### Transaction Scenario: Outpatient to Inpatient
1.  **Patient Registration & Booking (CT1)**:
    *   **Source**: Online pre-registration or walk-in.
    *   **Control**: System searches by Full Name/Patient ID to prevent duplicates (SPRS4).
2.  **Clinical Orders & Auto-Charging (CT2 → FIN)**:
    *   **The "Auto-Post" Hook**: When Laboratory (LIS), Radiology (RIS), or Pharmacy (PMS) fulfills an order, charges are automatically posted to the patient's "Running Bill" in **CT3/FIN**.
    *   **Verification**: Pharmacists check for drug-allergy interactions against the `medical_records` history before dispensing.
3.  **Inventory Consumption (CT2 → LOG)**:
    *   **Dispensing**: Pharmacy dispensing updates `inventory` via a "Unit Dose" or "Outpatient" flow.
    *   **Supply Chain Trigger**: If stock (e.g., critical med) falls below the `reorder_level` in **LOG1**, a Purchase Request (PR) is automatically flagged.

## 3. Supply Chain "Three-Way Match" (LOG → FIN)
Ensuring financial accountability for hospital supplies.

### Transaction Scenario: Surgical Supply Replenishment
1.  **Procurement (LOG1)**:
    *   A Purchase Request (PR) is approved and converted into a `purchase_order` (PO).
2.  **Receiving & Verification**:
    *   Supplies arrive with a Delivery Receipt (DR). Logistics records the batch/lot and expiry in the `inventory` system.
3.  **The Three-Way Match (PSM8)**:
    *   **Handshake**: The Finance module performs a validation check: **PO (Order) + DR (Received) + Invoice (Billing)**.
    *   **Payment**: Once matched, the `vendor_invoice` is marked for payment disbursement via `cash_transactions`.

## 4. Administrative Discharge Clearance (CT3 → ALL)
The discharge process is a multi-departmental bottleneck that requires data synchronization.

*   **The Discharge Checklist (BDMS2)**:
    *   Discharge cannot proceed (Status: "Held") until the following subsystems signal "Clear":
        *   **Pharmacy**: All returns/wastage processed.
        *   **Laboratory/Radiology**: All results released.
        *   **Finance**: Payment cleared or Insurance (HMO/PhilHealth) verification uploaded.
        *   **Nursing**: Final vitals and summary recorded in EMR.

## 5. Workforce Operations & Payroll Integration (HR3 → FIN)
Bridging biometrics with the general ledger.

*   **The Payroll Handshake**:
    1.  **Attendance (HR3)**: Biometric clock-ins are validated. Missed punches are corrected via a digital form.
    2.  **Timesheet Sync**: Finalized timesheets are exported to **HR4 (Payroll)**.
    3.  **Disbursement**: Net pay is calculated (Base Salary + Hazard Pay - Tax/Gov't Contrib).
    4.  **GL Posting (GL1)**: Payroll costs are automatically posted as expenses to the `general_ledger` and deducted from `bank_accounts`.

## 6. Auditability & Security Governance

| Layer | Requirement | Technical Control |
| :--- | :--- | :--- |
| **Authentication** | Shared Account Prevention | MFA/OTP requirements and auto-logout after inactivity. |
| **Audit Path** | Traceability | Every edit to `medical_records` or `billing_records` includes a `performed_by` ID and `ip_address`. |
| **Integrity** | Stock Levels | Real-time inventory counts (stocktake) are logged per batch/lot number. |
| **Access** | Role-Based (RBAC) | Permissions restricted by job role (e.g., Only Medtechs can edit Lab results). |

---
*Last Updated: January 24, 2026*
*Based on: Client Hospital Interview Findings* 



