# Migration Plan: User Account Access from HR3 to HR2

## 1. Overview
The objective is to consolidate all User Account Management and Approval functionalities into **HR2 (Talent Development)**. Currently, these administrative tasks are handled by HR3 (Workforce Operations). After this migration, only HR2 administrators will have the authority to create, edit, delete, and approve system-wide user accounts.

## 2. Backend Route Migration (Python)

### 2.1 Modifications to `routes/hr/hr2.py`
- Import necessary utilities (`SUBSYSTEM_CONFIG`, `format_db_error`, `PasswordValidationError`, `policy_required`).
- Transfer the following routes from `hr3.py`:
  - `user_list`: `@hr2_bp.route('/admin/users')`
  - `add_user`: `@hr2_bp.route('/admin/users/add')`
  - `edit_user`: `@hr2_bp.route('/admin/users/<int:user_id>/edit')`
  - `delete_user`: `@hr2_bp.route('/admin/users/<int:user_id>/delete')`
  - `pending_approvals`: `@hr2_bp.route('/admin/approvals')`
  - `process_approval`: `@hr2_bp.route('/admin/approvals/<int:user_id>/<action>')`
  - `toggle_user_status`: `@hr2_bp.route('/admin/users/<int:user_id>/toggle')`
  - `reset_user_password`: `@hr2_bp.route('/admin/users/<int:user_id>/reset-password')`
  - `admin_change_password`: `@hr2_bp.route('/admin/users/<int:user_id>/change-password')`
- Update all `url_for('hr3...')` calls inside these routes to `url_for('hr2...')`.
- Ensure `@policy_required('hr2')` or equivalent checks are applied.

### 2.2 Modifications to `routes/hr/hr3.py`
- Remove all transferred User Management and Approval routes.
- Retain only Workforce Operations related routes (Attendance, Leaves, Schedules, Directory).

## 3. Template Migration (HTML/Jinja2)

### 3.1 Directory Changes
- Move all files from `templates/subsystems/hr/hr3/admin/` to `templates/subsystems/hr/hr2/admin/`:
  - `user_list.html`
  - `user_form.html`
  - `approvals.html`

### 3.2 Template Updates
- In each moved template, update all `url_for('hr3.admin_...')` or similar calls to `url_for('hr2.admin_...')`.
- Update breadcrumbs and titles to reflect HR2 administration.

## 4. UI/UX and Navigation Updates

### 4.1 Sidebar Update (`templates/base/subsystem_base.html`)
- **HR3 Section**: Remove "Approvals", "User Management", and "Register User" links.
- **HR2 Section**: Add "Approvals", "User Management", and "Register User" links (accessible only to admins).

### 4.2 Dashboard Updates
- Update `hr2/dashboard.html` to include stats for Pending Registrations (currently in HR3).
- Update `hr3/dashboard.html` to remove user management stats.

## 5. Global Reference Updates

### 5.1 Registration Notifications
Scan all route files (`routes/**/*.py`) and update `Notification.create(subsystem='hr3', ...)` for user registrations to `subsystem='hr2'`.
- Affected Files:
  - `routes/hr/hr1.py`
  - `routes/hr/hr2.py`
  - `routes/hr/hr4.py`
  - `routes/core_transaction/ct1.py`
  - `routes/core_transaction/ct2.py`
  - `routes/core_transaction/ct3.py`
  - `routes/logistics/log1.py`
  - `routes/logistics/log2.py`
  - `routes/financials/main.py`

### 5.2 Login/Registration Feedback
Update flash messages across all login/registration routes:
- Change "Your account is awaiting approval from HR3 Admin" to "Your account is awaiting approval from **HR2 Admin**".

## 6. Verification Plan
- [ ] Log in as an HR2 Admin and verify access to User Management.
- [ ] Log in as an HR3 Admin and verify that User Management links are gone and routes are inaccessible.
- [ ] Register a new user in any subsystem and verify HR2 Admin receives the notification.
- [ ] Approve the new user via the HR2 dashboard.
