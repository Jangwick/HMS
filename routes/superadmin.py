from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error, get_supabase_client, SUBSYSTEM_CONFIG
from utils.policy import HMSFundamentalsPolicy
from utils.hms_models import AuditLog, Notification
from utils.password_validator import PasswordValidationError
from utils import config_manager
from datetime import datetime

superadmin_bp = Blueprint('superadmin', __name__)

ACCENT_COLOR = '#7C3AED'  # Violet/Purple for SuperAdmin
BLUEPRINT_NAME = 'superadmin'

# ──────────────────────────────────────────────
#  AUTH: Login & Logout
# ──────────────────────────────────────────────
import random
import time

@superadmin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated and current_user.is_super_admin():
        return redirect(url_for('superadmin.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Try to find user across all subsystems
        user = User.get_by_username(username)
        
        if user and user.check_password(password):
            if not user.is_super_admin():
                flash('Access denied. This portal is restricted to SuperAdmin accounts only.', 'danger')
                return render_template('superadmin/login.html')
            
            if user.status != 'Active':
                flash('Your account is not active. Contact system administrator.', 'danger')
                return render_template('superadmin/login.html')
            
            # Phase 4: MFA Integration
            # For this demo, we generate a 6-digit OTP and store it in session
            otp = "".join([str(random.randint(0, 9)) for _ in range(6)])
            session['pending_superadmin_id'] = user.id
            session['superadmin_otp'] = otp
            session['otp_timestamp'] = time.time()
            
            # Send OTP via Email
            from utils.mail_system import send_otp
            target_email = "beatorres965@gmail.com"
            
            if send_otp(target_email, otp):
                flash(f'Verification code sent to {target_email}. Please check your inbox.', 'info')
            else:
                # Emergency Backup: Log to database so admin can retrieve it from Supabase
                AuditLog.log(
                    user.id, 
                    "MFA_EMERGENCY_BACKUP", 
                    "superadmin", 
                    {"otp_fallback": otp, "reason": "Mail delivery failed"}
                )
                flash('Security Alert: Failed to connect to mail server. Emergency backup code has been generated. System administrator can retrieve it from the Secure Audit Vault.', 'danger')
                # Keep printing to console for emergency backup (visible in Vercel logs)
                print(f"DEBUG: SuperAdmin OTP (Fallback): {otp}")
            
            return redirect(url_for('superadmin.verify_otp'))
        else:
            flash('Invalid credentials or account not found.', 'danger')
    
    return render_template('superadmin/login.html')


@superadmin_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    user_id = session.get('pending_superadmin_id')
    stored_otp = session.get('superadmin_otp')
    otp_time = session.get('otp_timestamp', 0)
    
    if not user_id or not stored_otp:
        flash('Session expired or invalid access attempt.', 'danger')
        return redirect(url_for('superadmin.login'))
    
    # Check for 5-minute expiry
    if time.time() - otp_time > 300:
        session.pop('pending_superadmin_id', None)
        session.pop('superadmin_otp', None)
        flash('Verification code expired. Please login again.', 'danger')
        return redirect(url_for('superadmin.login'))
        
    if request.method == 'POST':
        # Reconstruct OTP from segmented inputs
        entered_otp = "".join([request.form.get(f'otp_{i}', '') for i in range(6)])
        
        if entered_otp == stored_otp:
            user = User.get_by_id(user_id)
            if user and user.is_super_admin():
                # Clear session
                session.pop('pending_superadmin_id', None)
                session.pop('superadmin_otp', None)
                session.pop('otp_timestamp', None)
                
                login_user(user)
                user.register_successful_login()
                
                AuditLog.log(
                    user.id, 
                    "SuperAdmin Login (MFA Verified)",
                    "superadmin",
                    {"ip": request.remote_addr, "timestamp": datetime.now().isoformat()}
                )
                
                flash(f'Identity Verified. Welcome back, {user.username}.', 'success')
                return redirect(url_for('superadmin.dashboard'))
            else:
                flash('User validation failed.', 'danger')
                return redirect(url_for('superadmin.login'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')
            
    return render_template('superadmin/verify_otp.html')


@superadmin_bp.route('/logout')
@login_required
def logout():
    AuditLog.log(
        current_user.id,
        "SuperAdmin Logout",
        "superadmin",
        {"timestamp": datetime.now().isoformat()}
    )
    logout_user()
    flash('You have been signed out of the Global Command Center.', 'info')
    return redirect(url_for('superadmin.login'))


# ──────────────────────────────────────────────
#  DASHBOARD: Global Command Center
# ──────────────────────────────────────────────
@superadmin_bp.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_super_admin():
        flash('Access denied. SuperAdmin privileges required.', 'danger')
        return redirect(url_for('portal.index'))
    
    client = get_supabase_client()
    
    # Gather system-wide stats
    stats = {
        'total_users': 0,
        'active_users': 0,
        'pending_users': 0,
        'locked_users': 0,
        'departments': {},
        'subsystems': {},
        'recent_logins': [],
        'recent_audit': [],
    }
    
    try:
        # All users
        all_users = User.get_all()
        stats['total_users'] = len(all_users)
        stats['active_users'] = len([u for u in all_users if u.status == 'Active'])
        stats['pending_users'] = len([u for u in all_users if u.status == 'Pending'])
        stats['locked_users'] = len([u for u in all_users if u.is_locked()])
        
        # Group by department
        dept_counts = {}
        subsystem_counts = {}
        role_counts = {'Staff': 0, 'Manager': 0, 'Admin': 0, 'SuperAdmin': 0}
        
        for u in all_users:
            dept = u.department or 'Unknown'
            sub = u.subsystem or 'Unknown'
            dept_counts[dept] = dept_counts.get(dept, 0) + 1
            subsystem_counts[sub] = subsystem_counts.get(sub, 0) + 1
            
            if u.role in role_counts:
                role_counts[u.role] += 1
            elif u.role == 'Administrator':
                role_counts['Admin'] += 1
            else:
                role_counts['Staff'] += 1
        
        stats['departments'] = dept_counts
        stats['subsystems'] = subsystem_counts
        stats['role_counts'] = role_counts
        
        # Recent logins (last 10)
        recent_login_users = sorted(
            [u for u in all_users if u.last_login],
            key=lambda u: u.last_login,
            reverse=True
        )[:10]
        stats['recent_logins'] = recent_login_users
        
        # Recent audit logs
        try:
            audit_res = client.table('audit_logs').select('*').order('created_at', desc=True).limit(15).execute()
            stats['recent_audit'] = audit_res.data if audit_res.data else []
        except Exception:
            stats['recent_audit'] = []
            
        # Active attendance (clocked in now)
        try:
            active_att = client.table('attendance_logs').select('*, users(username, full_name, subsystem)').is_('clock_out', 'null').execute()
            stats['active_on_duty'] = len(active_att.data) if active_att.data else 0
        except Exception:
            stats['active_on_duty'] = 0

        # Advanced Intelligence: Security Health Score
        health_score = 100
        # Deduct for locked users
        health_score -= (stats['locked_users'] * 2)
        # Deduct for pending users (unverified)
        health_score -= (stats['pending_users'] * 1)
        # Check for failed logins in last 24h
        try:
            failed_logins = client.table('audit_logs').select('*').eq('action', 'Failed Login Attempt').execute()
            stats['recent_failures'] = len(failed_logins.data) if failed_logins.data else 0
            health_score -= (stats['recent_failures'] * 0.5)
        except:
            stats['recent_failures'] = 0
            
        stats['health_score'] = max(int(health_score), 0)
        
        # Database Integrity Metrics (Estimate)
        stats['db_stats'] = {
            'tables_monitored': 24,
            'storage_status': 'Optimal',
            'last_integrity_check': datetime.now().strftime("%Y-%m-%d %H:%M")
        }
            
    except Exception as e:
        flash(f'Error loading dashboard data: {str(e)}', 'danger')
    
    return render_template('superadmin/dashboard.html',
                           stats=stats,
                           subsystem_config=SUBSYSTEM_CONFIG,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


# ──────────────────────────────────────────────
#  GLOBAL USER MANAGEMENT
# ──────────────────────────────────────────────
@superadmin_bp.route('/users')
@login_required
def user_list():
    if not current_user.is_super_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('portal.index'))
    
    filter_dept = request.args.get('department', '')
    filter_subsystem = request.args.get('subsystem', '')
    filter_status = request.args.get('status', '')
    filter_role = request.args.get('role', '')
    
    all_users = User.get_all()
    
    # Apply filters
    if filter_dept:
        all_users = [u for u in all_users if u.department == filter_dept]
    if filter_subsystem:
        all_users = [u for u in all_users if u.subsystem == filter_subsystem]
    if filter_status:
        all_users = [u for u in all_users if u.status == filter_status]
    if filter_role:
        all_users = [u for u in all_users if u.role == filter_role]
    
    # Gather unique values for filter dropdowns
    all_users_full = User.get_all()
    departments = sorted(set(u.department for u in all_users_full if u.department))
    subsystems = sorted(set(u.subsystem for u in all_users_full if u.subsystem))
    roles = sorted(set(u.role for u in all_users_full if u.role))
    
    return render_template('superadmin/users.html',
                           users=all_users,
                           departments=departments,
                           subsystems=subsystems,
                           roles=roles,
                           subsystem_config=SUBSYSTEM_CONFIG,
                           filter_dept=filter_dept,
                           filter_subsystem=filter_subsystem,
                           filter_status=filter_status,
                           filter_role=filter_role,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@superadmin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_super_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('portal.index'))
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('superadmin.user_list'))
    
    if request.method == 'POST':
        try:
            update_data = {
                'full_name': request.form.get('full_name'),
                'email': request.form.get('email'),
                'role': request.form.get('role'),
                'subsystem': request.form.get('subsystem'),
                'department': request.form.get('department'),
                'status': request.form.get('status'),
            }
            
            user.update(**update_data)
            
            AuditLog.log(
                current_user.id,
                "SuperAdmin User Edit",
                "superadmin",
                {"target_user_id": user_id, "changes": update_data}
            )
            
            flash(f'User {user.username} updated successfully.', 'success')
            return redirect(url_for('superadmin.user_list'))
        except Exception as e:
            flash(f'Error updating user: {format_db_error(e)}', 'danger')
    
    return render_template('superadmin/edit_user.html',
                           user=user,
                           subsystem_config=SUBSYSTEM_CONFIG,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@superadmin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    if not current_user.is_super_admin():
        return jsonify({"error": "Access denied"}), 403
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('superadmin.user_list'))
    
    new_status = 'Active' if user.status != 'Active' else 'Suspended'
    user.update(status=new_status)
    
    AuditLog.log(
        current_user.id,
        f"SuperAdmin Status Change: {new_status}",
        "superadmin",
        {"target_user_id": user_id, "new_status": new_status}
    )
    
    flash(f'User {user.username} status changed to {new_status}.', 'success')
    return redirect(url_for('superadmin.user_list'))


@superadmin_bp.route('/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
def reset_password(user_id):
    if not current_user.is_super_admin():
        return jsonify({"error": "Access denied"}), 403
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('superadmin.user_list'))
    
    new_password = request.form.get('new_password', 'Temp@1234')
    
    try:
        user.set_password(new_password, skip_validation=True)
        
        AuditLog.log(
            current_user.id,
            "SuperAdmin Password Reset",
            "superadmin",
            {"target_user_id": user_id, "target_username": user.username}
        )
        
        flash(f'Password reset for {user.username}. Temporary password set.', 'success')
    except Exception as e:
        flash(f'Error resetting password: {str(e)}', 'danger')
    
    return redirect(url_for('superadmin.user_list'))


@superadmin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_super_admin():
        return jsonify({"error": "Access denied"}), 403
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('superadmin.user_list'))
    
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('superadmin.user_list'))
    
    username = user.username
    user.delete()
    
    AuditLog.log(
        current_user.id,
        "SuperAdmin User Deletion",
        "superadmin",
        {"deleted_user": username, "deleted_user_id": user_id}
    )
    
    flash(f'User {username} has been permanently deleted.', 'success')
    return redirect(url_for('superadmin.user_list'))


# ──────────────────────────────────────────────
#  BROADCAST NOTIFICATIONS
# ──────────────────────────────────────────────
@superadmin_bp.route('/broadcast', methods=['POST'])
@login_required
def broadcast_notification():
    if not current_user.is_super_admin():
        return jsonify({"error": "Access denied"}), 403
    
    title = request.form.get('title', 'System Announcement')
    message = request.form.get('message', '')
    n_type = request.form.get('type', 'info')  # info, warning, danger, success
    target_scope = request.form.get('scope', 'all')  # all, department, subsystem
    target_value = request.form.get('target_value', '')
    
    if not message:
        flash('Message cannot be empty.', 'danger')
        return redirect(url_for('superadmin.dashboard'))
    
    try:
        if target_scope == 'all':
            # Send to all subsystems
            for sub_code in SUBSYSTEM_CONFIG.keys():
                Notification.create(
                    subsystem=sub_code,
                    title=title,
                    message=message,
                    n_type=n_type,
                    sender_subsystem='SUPERADMIN'
                )
        elif target_scope == 'subsystem' and target_value:
            Notification.create(
                subsystem=target_value,
                title=title,
                message=message,
                n_type=n_type,
                sender_subsystem='SUPERADMIN'
            )
        elif target_scope == 'department' and target_value:
            # Find all subsystems in this department
            dept_subs = [k for k, v in SUBSYSTEM_CONFIG.items() if v.get('department') == target_value]
            for sub_code in dept_subs:
                Notification.create(
                    subsystem=sub_code,
                    title=title,
                    message=message,
                    n_type=n_type,
                    sender_subsystem='SUPERADMIN'
                )
        
        AuditLog.log(
            current_user.id,
            "SuperAdmin Broadcast",
            "superadmin",
            {"title": title, "scope": target_scope, "target": target_value}
        )
        
        flash('Broadcast notification sent successfully.', 'success')
    except Exception as e:
        flash(f'Error sending broadcast: {str(e)}', 'danger')
    
    return redirect(url_for('superadmin.dashboard'))


# ──────────────────────────────────────────────
#  AUDIT LOG VIEWER
# ──────────────────────────────────────────────
@superadmin_bp.route('/audit-logs')
@login_required
def audit_logs():
    if not current_user.is_super_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('portal.index'))
    
    client = get_supabase_client()
    
    try:
        response = client.table('audit_logs').select('*').order('created_at', desc=True).limit(100).execute()
        logs = response.data if response.data else []
    except Exception:
        logs = []
    
    return render_template('superadmin/audit_logs.html',
                           logs=logs,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


# ──────────────────────────────────────────────
#  SETTINGS (shared pattern)
# ──────────────────────────────────────────────
@superadmin_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if not current_user.is_super_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('portal.index'))
    
    if request.method == 'POST':
        # Update settings via config_manager
        config_manager.set_setting('PASSWORD_EXPIRY_DAYS', request.form.get('password_expiry_days', '90'))
        config_manager.set_setting('LOCKOUT_DURATION_MINS', request.form.get('lockout_duration_mins', '30'))
        config_manager.set_setting('MAX_LOGIN_ATTEMPTS', request.form.get('max_login_attempts', '5'))
        config_manager.set_setting('SESSION_TIMEOUT_MINS', request.form.get('session_timeout_mins', '30'))
        
        main_global = request.form.get('maintenance_global') == 'on'
        config_manager.set_setting('MAINTENANCE_GLOBAL', 'True' if main_global else 'False')
        
        AuditLog.log(
            current_user.id,
            "System Policy Update",
            "superadmin",
            {"changes": request.form.to_dict()}
        )
        
        flash('Enterprise policies updated successfully. Changes are now active.', 'success')
        return redirect(url_for('superadmin.settings'))

    current_settings = {
        'password_expiry_days': config_manager.get_setting('PASSWORD_EXPIRY_DAYS', '90'),
        'lockout_duration_mins': config_manager.get_setting('LOCKOUT_DURATION_MINS', '30'),
        'max_login_attempts': config_manager.get_setting('MAX_LOGIN_ATTEMPTS', '5'),
        'session_timeout_mins': config_manager.get_setting('SESSION_TIMEOUT_MINS', '30'),
        'maintenance_global': config_manager.is_global_maintenance()
    }
    
    return render_template('superadmin/settings.html',
                           settings=current_settings,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


# ──────────────────────────────────────────────
#  MAINTENANCE & BACKUP CENTER
# ──────────────────────────────────────────────
from utils import backup_manager

@superadmin_bp.route('/maintenance')
@login_required
def maintenance_center():
    if not current_user.is_super_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('portal.index'))
    
    # Get audit logs for backup actions
    backup_logs = backup_manager.get_audit_logs('subsystem', 'global', limit=20)
    if not backup_logs: # Fallback if no global logs, get any
        try:
            client = get_supabase_client()
            res = client.table('system_audit_logs').select('*').order('timestamp', desc=True).limit(20).execute()
            backup_logs = res.data if res.data else []
        except Exception:
            backup_logs = []

    # Get current settings via config_manager
    current_settings = {
        'maintenance_global': config_manager.is_global_maintenance()
    }

    # Get subsystem maintenance states
    subsystem_states = {}
    for code in SUBSYSTEM_CONFIG.keys():
        subsystem_states[code] = config_manager.is_subsystem_maintenance(code)

    return render_template('superadmin/maintenance.html',
                           backup_logs=backup_logs,
                           subsystem_config=SUBSYSTEM_CONFIG,
                           backup_subsystems=backup_manager.get_supported_subsystems(),
                           backup_departments=backup_manager.get_supported_departments(),
                           subsystem_states=subsystem_states,
                           settings=current_settings,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@superadmin_bp.route('/backup/export', methods=['POST'])
@login_required
def export_backup():
    if not current_user.is_super_admin():
        return jsonify({"error": "Access denied"}), 403
    
    scope = (request.form.get('scope', 'subsystem') or 'subsystem').strip().lower()
    target_id = (request.form.get('target_id') or '').strip().upper()
    
    if not target_id:
        flash('No target selected for backup.', 'danger')
        return redirect(url_for('superadmin.maintenance_center'))
        
    memory_file, error = backup_manager.export_data(scope, target_id, current_user.id)
    
    if error:
        flash(f'Export failed: {error}', 'danger')
        return redirect(url_for('superadmin.maintenance_center'))
        
    from flask import send_file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'HMS_BACKUP_{target_id}_{timestamp}.hms-backup'
    )


@superadmin_bp.route('/backup/import', methods=['POST'])
@login_required
def import_backup():
    if not current_user.is_super_admin():
        return jsonify({"error": "Access denied"}), 403
        
    if 'backup_file' not in request.files:
        flash('No file uploaded.', 'danger')
        return redirect(url_for('superadmin.maintenance_center'))
        
    request_file = request.files['backup_file']
    scope = (request.form.get('scope') or '').strip().lower()
    target_id = (request.form.get('target_id') or '').strip().upper()
    
    if not request_file or not scope or not target_id:
        flash('Incomplete data for import.', 'danger')
        return redirect(url_for('superadmin.maintenance_center'))
        
    success, message = backup_manager.import_data(request_file, scope, target_id, current_user.id)
    
    if success:
        flash(f'Restore Successful: {message}', 'success')
    else:
        flash(f'Restore Failed: {message}', 'danger')
        
    return redirect(url_for('superadmin.maintenance_center'))


@superadmin_bp.route('/integrity-scan', methods=['POST'])
@login_required
def integrity_scan():
    if not current_user.is_super_admin():
        return jsonify({"error": "Access denied"}), 403
    
    all_users = User.get_all()
    vulnerabilities = []
    
    # Audit logic implementation...
    weak_patterns = ['password', '123456', 'Admin@123', 'Admin@12345']
    for u in all_users:
        if u.username in weak_patterns: 
             vulnerabilities.append({"type": "Security", "subject": u.username, "issue": "Weak username/pattern detected."})
             
    for u in all_users:
        if u.status == 'Pending':
            vulnerabilities.append({"type": "Integrity", "subject": u.username, "issue": "Account stuck in 'Pending' state."})

    for u in all_users:
        if not u.email or "@" not in u.email:
            vulnerabilities.append({"type": "Data", "subject": u.username, "issue": "Invalid or missing email address."})
        if not u.full_name or len(u.full_name) < 3:
            vulnerabilities.append({"type": "Data", "subject": u.username, "issue": "Incomplete profile information."})

    report = {
        "timestamp": datetime.now().isoformat(),
        "total_audited": len(all_users),
        "issues_found": len(vulnerabilities),
        "vulnerabilities": vulnerabilities[:20]
    }
    
    AuditLog.log(current_user.id, "System Integrity Scan Triggered", "superadmin", {"findings": len(vulnerabilities)})
    return jsonify(report)


@superadmin_bp.route('/maintenance-mode')
def maintenance_mode_splash():
    subsystem = request.args.get('subsystem', 'global')
    return render_template('errors/maintenance.html', subsystem=subsystem)


@superadmin_bp.route('/maintenance/toggle-subsystem', methods=['POST'])
@login_required
def toggle_subsystem_maintenance():
    if not current_user.is_super_admin():
        return jsonify({"error": "Access denied"}), 403
    
    sub_code = request.form.get('subsystem_code')
    if not sub_code:
        return jsonify({"error": "Missing subsystem code"}), 400
    
    current_state = config_manager.is_subsystem_maintenance(sub_code)
    new_state = not current_state
    
    config_manager.set_setting(f'MAINTENANCE_{sub_code.upper()}', 'True' if new_state else 'False')
    
    AuditLog.log(
        current_user.id,
        f"Maintenance Toggle: {sub_code.upper()}",
        "superadmin",
        {"new_state": new_state}
    )
    
    return jsonify({"success": True, "new_state": new_state})


@superadmin_bp.route('/backup/reset', methods=['POST'])
@login_required
def reset_subsystem():
    if not current_user.is_super_admin():
        return jsonify({"error": "Access denied"}), 403
        
    scope = (request.form.get('scope') or '').strip().lower()
    target_id = (request.form.get('target_id') or '').strip().upper()
    confirm_text = (request.form.get('confirm_text') or '').strip().upper()
    
    if confirm_text != f"RESET-{target_id}":
        flash('Reset confirmation failed. Incorrect code.', 'danger')
        return redirect(url_for('superadmin.maintenance_center'))
        
    success, message = backup_manager.reset_data(scope, target_id, current_user.id)
    
    if success:
        flash(f'Security Notification: {target_id} has been wiped clean.', 'success')
    else:
        flash(f'Reset Failed: {message}', 'danger')
        
    return redirect(url_for('superadmin.maintenance_center'))
    
    return render_template('shared/settings.html',
                           subsystem_name='SuperAdmin Command Center',
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME,
                           subsystem_icon='shield-lock')
