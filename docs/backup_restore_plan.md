# Backup and Restore Plan for HMS

This document outlines the strategy for implementing a granular backup and restore feature for the Hospital Management System (HMS), allowing administrators to manage data at both the **Department** and **Subsystem** levels (e.g., HR1, HR2, CT1, etc.).

## 1. Objectives
- Provide granular data control for each subsystem.
- Enable recovery from data entry errors or specific subsystem failures without affecting the entire database or even the entire department.
- Ensure data portability for auditing and offline analysis.

## 2. Granular Data Mapping (Per Subsystem)

The following table lists the database tables associated with each specific subsystem:

| Department | Subsystem | Tables to Backup |
| :--- | :--- | :--- |
| **Human Resources** | **HR1: Talent Acquisition** | `applicants`, `vacancies`, `interviews`, `onboarding` |
| | **HR2: Talent Development** | `competencies`, `staff_competencies`, `trainings`, `training_participants` |
| | **HR3: Workforce Operations** | `attendance_logs`, `leave_requests`, `staff_schedules` |
| | **HR4: Compensation & Analytics** | `salary_grades`, `compensation_records`, `payroll_records` |
| **Core Transaction** | **CT1: Patient Access** | `patients`, `appointments` |
| | **CT2: Clinical Operations** | `lab_orders`, `prescriptions` |
| | **CT3: Health Records & Beds** | `medical_records`, `beds` |
| **Logistics** | **LOG1: Inventory & Assets** | `inventory`, `dispensing_history`, `assets`, `asset_maintenance_logs` |
| | **LOG2: Fleet & Procurement** | `fleet_vehicles`, `drivers`, `fleet_dispatch`, `fleet_costs`, `suppliers`, `purchase_orders`, `po_items`, `log_documents` |
| **Financials** | **FIN1: Billing & Accounts** | `billing_records`, `general_ledger`, `vendors`, `vendor_invoices`, `vendor_payments`, `receivables`, `collections`, `bank_accounts`, `cash_transactions`, `generated_reports` |

*Note: The `users` table remains shared core data and is excluded from subsystem-level restores to prevent authentication and authorization conflicts.*

## 3. Technical Strategy

### 3.1 Backup Format
- **Format**: JSON (Serialized)
- **Reasoning**: JSON allows for easy parsing, partial restores, and is human-readable. It avoids the complexities of SQL dialect differences when performing granular insertions.

### 3.2 Export/Backup Process (Downloadable)
1. **Selection**: User selects either a full **Department** or a specific **Subsystem** (e.g., "Export HR1 only").
2. **Extraction**: System queries all tables mapped to that selection using a consistent sort order (by primary key) to ensure deterministic exports.
3. **Serialization**: Data from each table is converted into a separate JSON file named `<table_name>.json`.
4. **Packaging**: These JSON files are bundled into a single compressed `.zip` archive (renamed to `.hms-backup` for identification) containing:
   - `metadata.json`: Contains export date, source subsystem/department, and system version.
   - Individual `<table_name>.json` files.
5. **Download**: The server generates a streaming response with `Content-Disposition: attachment`, allowing the user to save the backup file locally.

### 3.3 Import/Restore Process (Uploadable)
1. **File Upload**: User selects a previously exported `.hms-backup` file from their local machine and uploads it via a secure `multipart/form-data` request.
2. **Validation**: 
   - The system extracts the metadata to verify compatibility.
   - It performs a "Dry Run" check to ensure the JSON structure matches the current database schema.
3. **Transaction Initiation**: A database transaction is started to ensure atomsity (all-or-nothing restoration).
4. **Data Injection**:
   - **Dependency Handling**: Tables are restored in a specific order based on foreign key relationships (e.g., parent tables before child tables).
   - **Upsert Logic**: By default, it uses `ON CONFLICT (id) DO UPDATE` to overwrite existing records with matching IDs, while inserting new ones.
5. **Finalization**: If successful, the transaction is committed; otherwise, it is rolled back and an error report is provided.
6. **Logging**: The system logs the filename and the user who imported the data.

## 4. Implementation Roadmap

### Phase 1: Utility Development
- Create `utils/backup_manager.py` with `export_subsystem_data(subsystem_id)` and `import_subsystem_data(file_data)`.
- Implement logic to handle both full department (all subsystems) and single subsystem exports.
- Use `supabase-py` or direct PostgreSQL connection via a service role for high-privilege operations.

### Phase 2: Backend API
- Create routes in `routes/portal.py` or separate `routes/admin.py`:
  - `GET /api/backup/<scope>/<id>` (Scope: `dept` or `subsystem`)
  - `POST /api/restore/<scope>/<id>`

### Phase 3: Frontend Integration
- Add "Data Management" section to each department hub and specific subsystem pages.
- Implement modals for "Backup [Subsystem Name]" and "Restore [Subsystem Name]".

## 5. Security and Constraints
- **Authorization**: Only users with the `Admin` role in their respective department/subsystem (or Super Admins) can perform these actions.
- **Data Integrity**: Foreign key constraints must be strictly observed. Restore order should follow dependency chains (e.g., `suppliers` before `purchase_orders`).
- **File Limits**: Maximum backup file size should be capped (e.g., 50MB) to prevent server timeouts.

## 6. Audit Logging
Every backup and restore operation will be recorded in a new `system_audit_logs` table:
- `timestamp`
- `user_id`
- `action` (BACKUP/RESTORE)
- `scope` (DEPARTMENT/SUBSYSTEM)
- `target_id` (e.g., HR1, Logistics, etc.)
- `status` (SUCCESS/FAIL)
- `file_name`
