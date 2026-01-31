from flask import Blueprint, send_file, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from utils.backup_manager import export_data, import_data
from datetime import datetime
import io

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/backup/<scope>/<target_id>')
@login_required
def backup(scope, target_id):
    # Security check: Only Admins can perform backup
    if not current_user.is_admin():
        flash("Unauthorized: Admin access required for data management.", "danger")
        return redirect(url_for('portal.index'))
    
    # Departmental isolation check (HR3 admins bypass)
    if current_user.subsystem != 'hr3':
        from utils.supabase_client import SUBSYSTEM_CONFIG
        user_dept = current_user.department
        
        # Check if the target scope matches the user's department
        if scope == 'department' and target_id != user_dept:
            flash(f"Security Violation: You can only backup your own department ({user_dept}).", "danger")
            return redirect(url_for('portal.index'))
        
        if scope == 'subsystem':
            target_config = SUBSYSTEM_CONFIG.get(target_id.lower())
            if not target_config or target_config.get('department') != user_dept:
                flash(f"Security Violation: You can only backup subsystems within {user_dept}.", "danger")
                return redirect(url_for('portal.index'))

    memory_file, error = export_data(scope, target_id, current_user.id)
    if error:
        flash(f"Backup failed: {error}", "danger")
        return redirect(request.referrer or url_for('portal.index'))
    
    filename = f"HMS_{target_id}_{scope}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.hms-backup"
    
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=filename
    )

@admin_bp.route('/restore/<scope>/<target_id>', methods=['POST'])
@login_required
def restore(scope, target_id):
    # Security check: Only Admins can perform restore
    if not current_user.is_admin():
        flash("Unauthorized: Admin access required for data management.", "danger")
        return redirect(url_for('portal.index'))

    # Departmental isolation check (HR3 admins bypass)
    if current_user.subsystem != 'hr3':
        from utils.supabase_client import SUBSYSTEM_CONFIG
        user_dept = current_user.department
        
        if scope == 'department' and target_id != user_dept:
            flash("Security Violation: You can only restore your own department.", "danger")
            return redirect(url_for('portal.index'))
        
        if scope == 'subsystem':
            target_config = SUBSYSTEM_CONFIG.get(target_id.lower())
            if not target_config or target_config.get('department') != user_dept:
                flash("Security Violation: You can only restore subsystems within your department.", "danger")
                return redirect(url_for('portal.index'))

    if 'backup_file' not in request.files:
        flash("No file provided", "danger")
        return redirect(request.referrer or url_for('portal.index'))
    
    file = request.files['backup_file']
    if file.filename == '':
        flash("No file selected", "danger")
        return redirect(request.referrer or url_for('portal.index'))

    # Read file into memory
    file_stream = io.BytesIO(file.read())

    success, message = import_data(file_stream, scope, target_id, current_user.id)
    if success:
        flash(message, "success")
    else:
        # If it failed, the details might be in the first 100 chars
        flash(message, "danger")
    
    return redirect(request.referrer or url_for('portal.index'))

@admin_bp.route('/reset/<scope>/<target_id>', methods=['POST'])
@login_required
def reset(scope, target_id):
    # Security check
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 403

    # Departmental isolation check
    if current_user.subsystem != 'hr3':
        from utils.supabase_client import SUBSYSTEM_CONFIG
        user_dept = current_user.department
        if scope == 'subsystem':
            target_config = SUBSYSTEM_CONFIG.get(target_id.lower())
            if not target_config or target_config.get('department') != user_dept:
                return jsonify({"error": "Security Violation"}), 403

    from utils.backup_manager import reset_data
    success, message = reset_data(scope, target_id, current_user.id)
    if success:
        flash(message, "success")
    else:
        flash(message, "danger")
    
    return redirect(request.referrer or url_for('portal.index'))

@admin_bp.route('/audit-logs/<scope>/<target_id>')
@login_required
def audit_logs(scope, target_id):
    if not current_user.is_admin():
        return jsonify([])
    
    from utils.backup_manager import get_audit_logs
    logs = get_audit_logs(scope, target_id)
    return jsonify(logs)
