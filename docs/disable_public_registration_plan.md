# Plan: Disable Public Registration Across HMS Subsystems

## Objective
To enhance security and centralize account management, public registration will be disabled in all HMS subsystems. From now on, users must be registered by an administrator via the **HR2 (Talent Development)** module.

## 1. Backend: Remove Registration Routes
The following routes and their associated logic will be removed or commented out from their respective blueprint files:

### HR Subsystems
- `routes/hr/hr1.py`: Remove `@hr1_bp.route('/register')`
- `routes/hr/hr2.py`: Remove `@hr2_bp.route('/register')`
- `routes/hr/hr3.py`: Remove `@hr3_bp.route('/register')`
- `routes/hr/hr4.py`: Remove `@hr4_bp.route('/register')`

### Core Transaction Subsystems
- `routes/core_transaction/ct1.py`: Remove `@ct1_bp.route('/register')`
- `routes/core_transaction/ct2.py`: Remove `@ct2_bp.route('/register')`
- `routes/core_transaction/ct3.py`: Remove `@ct3_bp.route('/register')`

### Financials Subsystems
- `routes/financials/main.py`: Remove `@financials_bp.route('/register')`

### Logistics Subsystems
- `routes/logistics/log1.py`: Remove `@log1_bp.route('/register')`
- `routes/logistics/log2.py`: Remove `@log2_bp.route('/register')`

---

## 2. Frontend: Remove Registration Links
The "Register here" or "Don't have an account?" links will be removed from the following login templates to prevent users from attempting to access registration pages.

### Shared Templates
- `templates/shared/login.html`

### Subsystem-Specific Templates
- `templates/subsystems/core_transaction/ct1/login.html`
- `templates/subsystems/core_transaction/ct2/login.html`
- `templates/subsystems/core_transaction/ct3/login.html`
- `templates/subsystems/financials/login.html`
- `templates/subsystems/financials/fin1/login.html`
- `templates/subsystems/financials/fin2/login.html`
- `templates/subsystems/financials/fin3/login.html`
- `templates/subsystems/financials/fin4/login.html`
- `templates/subsystems/financials/fin5/login.html`
- `templates/subsystems/hr/hr1/login.html`
- `templates/subsystems/hr/hr2/login.html`
- `templates/subsystems/hr/hr3/login.html`
- `templates/subsystems/hr/hr4/login.html`
- `templates/subsystems/logistics/log1/login.html`
- `templates/subsystems/logistics/log2/login.html`

---

## 3. Cleanup: Remove Unused Templates
The following registration templates will be deleted if no longer in use:
- `templates/shared/register.html`
- `templates/subsystems/core_transaction/ct1/register.html`
- `templates/subsystems/core_transaction/ct2/register.html`
- `templates/subsystems/core_transaction/ct3/register.html`
- `templates/subsystems/financials/register.html`
- `templates/subsystems/hr/hr1/register.html`
- `templates/subsystems/hr/hr2/register.html`
- `templates/subsystems/hr/hr3/register.html`
- `templates/subsystems/hr/hr4/register.html`
- `templates/subsystems/logistics/log1/register.html`
- `templates/subsystems/logistics/log2/register.html`

---

## 4. Verification Workflow
1. **Try Accessing Routes:** Manually navigate to `/[subsystem]/register` and verify a `404 Not Found` error.
2. **Visual Inspection:** Check all login pages to ensure no registration links are visible.
3. **Verify Admin Registration:** Ensure that the **HR2 Admin** can still add users via the "Register User" feature in the HR2 dashboard.

---

**Approval Required:** Confirm if you would like me to proceed with the implementation of this plan.
