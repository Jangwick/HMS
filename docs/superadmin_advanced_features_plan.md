# SuperAdmin Advanced Phase Plan: Enterprise Control & Reliability

## 🎯 Objective
Transition the SuperAdmin portal from a "Management Console" to a full-scale **"Enterprise Governance Hub"**. This phase introduces advanced system controls, data reliability tools, and dynamic policy management to ensure the HMS system remains secure, performant, and maintainable.

---

## 🛠 Phase 5: Advanced Enterprise Controls

| Feature | Description | Reference Files |
| :--- | :--- | :--- |
| **Backup & Recovery Center** | Web interface for `.hms-backup` generation, restoration, and data resets. Supports subsystem and department level scoping. | `utils/backup_manager.py`, `templates/superadmin/maintenance.html` |
| **Maintenance Mode** | Global and subsystem-specific toggles to prevent user access during updates or migrations. | `utils/policy.py`, `routes/superadmin.py` |
| **Dynamic Policy Manager** | UI to modify security parameters (Password expiry, lockout duration, session TTL) without editing code/env. | `utils/password_validator.py`, `utils/ip_lockout.py` |
| **System Integrity Scan** | Automated health check for orphaned records, weak password detection, and security configuration audit. | `utils/hms_models.py`, `routes/superadmin.py` |
| **Advanced Intelligence** | Trend analysis for user growth, failed login heatmaps, and subsystem resource utilization charts. | `templates/superadmin/dashboard.html` |

---

## 📋 Implementation Tasks

### 1. Data Governance (Backup/Restore)
- [ ] Create `templates/superadmin/maintenance.html` to house backup/restore tools.
- [ ] Implement `/superadmin/backup/export` and `/superadmin/backup/import` routes.
- [ ] Add "Deep Reset" capability for subsystems with mandatory MFA confirmation.

### 2. Service Management (Maintenance Mode)
- [ ] Add `maintenance_mode` table/column in system config.
- [ ] Create a middleware check in `utils/policy.py` to intercept routes when maintenance is active.
- [ ] Design a premium "System Under Maintenance" splash page.

### 3. Security Orchestration (Policy Tuning)
- [ ] Create `system_settings` database table for persistent dynamic configuration.
- [ ] Implement `superadmin/settings/security` UI to manage:
    - Minimum password length/complexity.
    - Account lockout duration (minutes).
    - Session timeout (seconds).
- [ ] Update `ip_lockout.py` and `password_validator.py` to read from DB instead of hardcoded values.

### 4. System Analytics & Health
- [ ] Implement "Security Health Score" on the dashboard.
- [ ] Add charts for "Login Success vs Failure" over 24h.
- [ ] Add "Database Health" metrics (Estimate table counts/sizes).

---

## 🚀 Future Vision
Once Phase 5 is complete, the HMS SuperAdmin will possess true **Sentinel Class** authority—the ability to not only manage users but to reshape the system's security posture and data integrity in real-time.
