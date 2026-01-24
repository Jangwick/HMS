from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_wtf.csrf import generate_csrf
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, SUBSYSTEM_CONFIG, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from datetime import datetime

hr3_bp = Blueprint('hr3', __name__)

# Subsystem configuration
SUBSYSTEM_NAME = 'HR3 - Workforce Operations'
ACCENT_COLOR = '#0EA5E9'
SUBSYSTEM_ICON = 'clock-history'
BLUEPRINT_NAME = 'hr3'

@hr3_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/hr/hr3/login.html', 
                               remaining_seconds=remaining_seconds,
                               subsystem_name=SUBSYSTEM_NAME,
                               accent_color=ACCENT_COLOR,
                               subsystem_icon=SUBSYSTEM_ICON,
                               blueprint_name=BLUEPRINT_NAME,
                               hub_route='portal.hr_hub')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.get_by_username(username, BLUEPRINT_NAME)
        
        if user:
            now_utc = datetime.utcnow()
            
            if user.check_password(password):
                # Check if account is approved
                if user.status != 'Active':
                    if user.status == 'Pending':
                        flash('Your account is awaiting approval from HR3 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('subsystems/hr/hr3/login.html',
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           subsystem_icon=SUBSYSTEM_ICON,
                                           blueprint_name=BLUEPRINT_NAME,
                                           hub_route='portal.hr_hub')

                # Check for password expiration - redirect to change password
                if user.password_expires_at and user.password_expires_at < now_utc:
                    session['expired_user_id'] = user.id
                    session['expired_subsystem'] = BLUEPRINT_NAME
                    flash('Your password has expired. Please set a new password to continue.', 'warning')
                    return redirect(url_for('hr3.change_password'))

                # Clear IP lockout attempts on successful login
                register_successful_login()
                user.register_successful_login()
                
                if login_user(user):
                    days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                    if days_left <= 7:
                        flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    return redirect(url_for('hr3.dashboard'))
                else:
                    flash('Login failed. Your account may be deactivated.', 'danger')
                    return render_template('subsystems/hr/hr3/login.html',
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           subsystem_icon=SUBSYSTEM_ICON,
                                           blueprint_name=BLUEPRINT_NAME,
                                           hub_route='portal.hr_hub')
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/hr/hr3/login.html', 
                                           remaining_seconds=remaining_seconds,
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           subsystem_icon=SUBSYSTEM_ICON,
                                           blueprint_name=BLUEPRINT_NAME,
                                           hub_route='portal.hr_hub')
                else:
                    flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
        else:
            # Check if user exists in ANY subsystem to provide better feedback
            try:
                other_user = User.get_by_username(username)
                if other_user:
                    sub = other_user.subsystem.upper()
                    flash(f'Account found in {sub} department. Please log in through the correct portal.', 'warning')
                else:
                    flash('Invalid credentials.', 'danger')
            except:
                flash('Invalid credentials.', 'danger')
            
            # Register failed attempt even for non-existent users
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
            
            if is_now_locked:
                return render_template('subsystems/hr/hr3/login.html', 
                                       remaining_seconds=remaining_seconds,
                                       subsystem_name=SUBSYSTEM_NAME,
                                       accent_color=ACCENT_COLOR,
                                       subsystem_icon=SUBSYSTEM_ICON,
                                       blueprint_name=BLUEPRINT_NAME,
                                       hub_route='portal.hr_hub')
            
    return render_template('subsystems/hr/hr3/login.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           subsystem_icon=SUBSYSTEM_ICON,
                           blueprint_name=BLUEPRINT_NAME,
                           hub_route='portal.hr_hub')

@hr3_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            # Create user with 'Pending' status
            new_user = User.create(
                username=username,
                email=email,
                password=password,
                subsystem=BLUEPRINT_NAME,
                department='HR',
                status='Pending'
            )
            
            if new_user:
                flash('Registration successful! Your account is awaiting approval from HR3 Admin.', 'success')
                return redirect(url_for('hr3.login'))
            else:
                flash('Registration failed. Please try again.', 'danger')
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')
            
    return render_template('shared/register.html', 
                           subsystem_name=SUBSYSTEM_NAME, 
                           blueprint_name=BLUEPRINT_NAME,
                           hub_route='portal.hr_hub',
                           accent_color=ACCENT_COLOR)

@hr3_bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    expired_user_id = session.get('expired_user_id')
    expired_subsystem = session.get('expired_subsystem')
    is_expired = expired_user_id is not None and expired_subsystem == BLUEPRINT_NAME
    
    if is_expired:
        user = User.get_by_id(expired_user_id)
        if not user:
            session.pop('expired_user_id', None)
            session.pop('expired_subsystem', None)
            flash('Session expired. Please login again.', 'danger')
            return redirect(url_for('hr3.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('hr3.login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not is_expired:
            if not user.check_password(current_password):
                flash('Current password is incorrect.', 'danger')
                return render_template('shared/change_password.html',
                    subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR,
                    blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('shared/change_password.html',
                subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR,
                blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)
        
        try:
            user.set_password(new_password)
            session.pop('expired_user_id', None)
            session.pop('expired_subsystem', None)
            flash('Password updated successfully! Please login with your new password.', 'success')
            if current_user.is_authenticated:
                logout_user()
            return redirect(url_for('hr3.login'))
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html',
        subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@hr3_bp.route('/dashboard')
@login_required
@policy_required(BLUEPRINT_NAME)
def dashboard():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Check if user is currently clocked in
    is_clocked_in = False
    current_log = None
    try:
        active_log_resp = client.table('attendance_logs').select('*').eq('user_id', current_user.id).is_('clock_out', 'null').execute()
        if active_log_resp.data:
            is_clocked_in = True
            current_log = active_log_resp.data[0]
    except Exception as e:
        print(f"Error checking clock-in status: {e}")

    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    
    # Get Workforce stats
    try:
        # Get active vs pending users (from all subsystems since HR3 is Admin)
        all_users = User.get_all()
        active_count = len([u for u in all_users if u.status == 'Active'])
        pending_count = len([u for u in all_users if u.status == 'Pending'])
        
        # Today's Attendance (simplified count)
        today = datetime.now().strftime('%Y-%m-%d')
        # Filter for entries starting with today's date in clock_in
        attendance_resp = client.table('attendance_logs').select('id', count='exact').gte('clock_in', today).execute()
        today_attendance = attendance_resp.count if attendance_resp.count is not None else 0
        
        # Pending Leave Requests
        leave_resp = client.table('leave_requests').select('id', count='exact').eq('status', 'Pending').execute()
        pending_leaves = leave_resp.count if leave_resp.count is not None else 0
        
        # Recent activity - Mix of new users and leave requests
        recent_leaves = client.table('leave_requests').select('*, users:users!leave_requests_user_id_fkey(username)').order('created_at', desc=True).limit(3).execute().data or []
        
    except Exception as e:
        print(f"Error fetching HR3 stats: {e}")
        active_count = 0
        pending_count = 0
        today_attendance = 0
        pending_leaves = 0
        recent_leaves = []
    
    return render_template('subsystems/hr/hr3/dashboard.html', 
                          now=datetime.utcnow, 
                          active_count=active_count,
                          pending_count=pending_count,
                          today_attendance=today_attendance,
                          pending_leaves=pending_leaves,
                          recent_leaves=recent_leaves,
                          is_clocked_in=is_clocked_in,
                          current_log=current_log,
                          subsystem_name=SUBSYSTEM_NAME,
                          accent_color=ACCENT_COLOR,
                          blueprint_name=BLUEPRINT_NAME)

# Attendance & Leave for Current User
@hr3_bp.route('/attendance/clock-in', methods=['POST'])
@login_required
def clock_in():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Check if already clocked in
    active_log = client.table('attendance_logs').select('*').eq('user_id', current_user.id).is_('clock_out', 'null').execute()
    if active_log.data:
        flash('You are already clocked in.', 'warning')
        return redirect(url_for('hr3.dashboard'))
    
    now = datetime.now()
    # Logic for Late status (assuming 9 AM start)
    status = 'On-time'
    if now.hour >= 9 and now.minute > 0:
        status = 'Late'
        
    try:
        data = {
            'user_id': current_user.id,
            'clock_in': now.isoformat(),
            'status': status,
            'remarks': request.form.get('remarks')
        }
        client.table('attendance_logs').insert(data).execute()
        flash(f'Clocked in successfully at {now.strftime("%H:%M")}. Status: {status}', 'success')
    except Exception as e:
        flash(f'Error during clock-in: {str(e)}', 'danger')
        
    return redirect(url_for('hr3.dashboard'))

@hr3_bp.route('/attendance/clock-out', methods=['POST'])
@login_required
def clock_out():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    active_log = client.table('attendance_logs').select('*').eq('user_id', current_user.id).is_('clock_out', 'null').execute()
    if not active_log.data:
        flash('No active clock-in found.', 'warning')
        return redirect(url_for('hr3.dashboard'))
    
    try:
        log_id = active_log.data[0]['id']
        client.table('attendance_logs').update({
            'clock_out': datetime.now().isoformat()
        }).eq('id', log_id).execute()
        flash('Clocked out successfully.', 'success')
    except Exception as e:
        flash(f'Error during clock-out: {str(e)}', 'danger')
        
    return redirect(url_for('hr3.dashboard'))

@hr3_bp.route('/leaves/request', methods=['GET', 'POST'])
@login_required
def request_leave():
    if request.method == 'POST':
        leave_type = request.form.get('leave_type')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        remarks = request.form.get('remarks')
        
        from utils.supabase_client import get_supabase_client
        client = get_supabase_client()
        
        try:
            data = {
                'user_id': current_user.id,
                'leave_type': leave_type,
                'start_date': start_date,
                'end_date': end_date,
                'status': 'Pending',
                'remarks': remarks
            }
            client.table('leave_requests').insert(data).execute()
            flash('Leave request submitted successfully!', 'success')
            return redirect(url_for('hr3.dashboard'))
        except Exception as e:
            flash(f'Error submitting leave request: {str(e)}', 'danger')
            
    return render_template('subsystems/hr/hr3/leave_request_form.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

# Admin: User Management & Approvals
@hr3_bp.route('/admin/users')
@login_required
def user_list():
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    users = User.get_all()
    return render_template('subsystems/hr/hr3/admin/user_list.html', 
                           users=users, 
                           subsystem_name=SUBSYSTEM_NAME, 
                           accent_color=ACCENT_COLOR,
                           subsystem_config=SUBSYSTEM_CONFIG,
                           blueprint_name=BLUEPRINT_NAME)

@hr3_bp.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        subsystem = request.form.get('subsystem')
        role = request.form.get('role')
        status = request.form.get('status')
        
        config = SUBSYSTEM_CONFIG.get(subsystem)
        if not config:
            flash('Invalid subsystem selected.', 'danger')
            return render_template('subsystems/hr/hr3/admin/user_form.html', 
                                   subsystem_name=SUBSYSTEM_NAME, 
                                   subsystem_config=SUBSYSTEM_CONFIG,
                                   user=None,
                                   blueprint_name=BLUEPRINT_NAME)
        
        try:
            new_user = User.create(
                username=username,
                email=email,
                password=password,
                subsystem=subsystem,
                department=config['department'],
                role=role,
                status=status
            )
            
            if new_user:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'status': 'success', 'message': f'User {username} created successfully.'})
                flash(f'User {username} created successfully.', 'success')
                return redirect(url_for('hr3.user_list'))
            else:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'status': 'error', 'message': 'Failed to create user.'}), 400
                flash('Failed to create user.', 'danger')
        except PasswordValidationError as e:
            error_msg = ', '.join(e.errors)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': error_msg}), 400
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            error_msg = format_db_error(e)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': error_msg}), 400
            flash(error_msg, 'danger')
            
    return render_template('subsystems/hr/hr3/admin/user_form.html', 
                           subsystem_name=SUBSYSTEM_NAME, 
                           subsystem_config=SUBSYSTEM_CONFIG,
                           user=None,
                           blueprint_name=BLUEPRINT_NAME)

@hr3_bp.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('hr3.user_list'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        subsystem = request.form.get('subsystem')
        role = request.form.get('role')
        status = request.form.get('status')
        password = request.form.get('password')
        
        config = SUBSYSTEM_CONFIG.get(subsystem)
        if not config:
            flash('Invalid subsystem selected.', 'danger')
            return redirect(url_for('hr3.user_list'))
        
        update_data = {
            'username': username,
            'email': email,
            'subsystem': subsystem,
            'department': config['department'],
            'role': role,
            'status': status,
            'is_active': status == 'Active'
        }
        
        try:
            if password:
                user.set_password(password)
                flash('Password updated.', 'info')
            
            if user.update(**update_data):
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'status': 'success', 'message': f'User {username} updated successfully.'})
                flash(f'User {username} updated successfully.', 'success')
            else:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'status': 'error', 'message': 'Failed to update user.'}), 400
                flash('Failed to update user.', 'danger')
            
            return redirect(url_for('hr3.user_list'))
        except PasswordValidationError as e:
            error_msg = ', '.join(e.errors)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': error_msg}), 400
            for error in e.errors:
                flash(error, 'danger')
            return redirect(url_for('hr3.user_list'))
        except Exception as e:
            error_msg = format_db_error(e)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': error_msg}), 400
            flash(error_msg, 'danger')
            return redirect(url_for('hr3.user_list'))
            
    return render_template('subsystems/hr/hr3/admin/user_form.html', 
                           subsystem_name=SUBSYSTEM_NAME, 
                           subsystem_config=SUBSYSTEM_CONFIG,
                           user=user,
                           blueprint_name=BLUEPRINT_NAME)

@hr3_bp.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('hr3.user_list'))
    
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('hr3.user_list'))
        
    if user.delete():
        flash(f'User {user.username} deleted successfully.', 'success')
    else:
        flash('Failed to delete user.', 'danger')
        
    return redirect(url_for('hr3.user_list'))

@hr3_bp.route('/admin/approvals')
@login_required
def pending_approvals():
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    # Filter for pending users
    all_users = User.get_all()
    pending_users = [u for u in all_users if u.status == 'Pending']
    
    # Calculate stats for the dashboard
    from datetime import datetime
    today = datetime.utcnow().date()
    
    # Count approved today (using created_at as a proxy if we don't have updated_at)
    # or just count total approved/rejected if we want accurate total counts
    approved_today = len([u for u in all_users if u.status == 'Active' and u.role != 'Administrator'])
    rejected_today = len([u for u in all_users if u.status == 'Rejected'])
    
    return render_template('subsystems/hr/hr3/admin/approvals.html', 
                          users=pending_users,
                          approved_count=approved_today,
                          rejected_count=rejected_today,
                          subsystem_name=SUBSYSTEM_NAME, 
                          accent_color=ACCENT_COLOR,
                          blueprint_name=BLUEPRINT_NAME)

@hr3_bp.route('/admin/approvals/<int:user_id>/<action>')
@login_required
def process_approval(user_id, action):
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('hr3.pending_approvals'))
    
    try:
        if action == 'approve':
            user.update(status='Active', is_active=True)
            flash(f'User {user.username} has been approved.', 'success')
        elif action == 'deny':
            user.update(status='Rejected', is_active=False)
            flash(f'User {user.username} has been rejected.', 'warning')
    except Exception as e:
        flash(format_db_error(e), 'danger')
    
    return redirect(url_for('hr3.pending_approvals'))

@hr3_bp.route('/admin/users/<int:user_id>/toggle')
@login_required
def toggle_user_status(user_id):
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('hr3.user_list'))
    
    try:
        # Toggle the status
        if user.status == 'Active':
            user.update(status='Rejected', is_active=False)
            flash(f'User {user.username} has been deactivated.', 'warning')
        else:
            user.update(status='Active', is_active=True)
            flash(f'User {user.username} has been activated.', 'success')
    except Exception as e:
        flash(format_db_error(e), 'danger')
    
    return redirect(url_for('hr3.user_list'))

@hr3_bp.route('/admin/users/<int:user_id>/reset-password')
@login_required
def reset_user_password(user_id):
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('hr3.user_list'))
    
    try:
        # Reset to default password
        default_pw = "HMSPassword@123"
        user.set_password(default_pw, skip_validation=True)
        flash(f'Password for {user.username} has been reset to: {default_pw}', 'success')
    except Exception as e:
        flash(format_db_error(e), 'danger')
    return redirect(url_for('hr3.user_list'))

@hr3_bp.route('/admin/users/<int:user_id>/change-password', methods=['POST'])
@login_required
def admin_change_password(user_id):
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('hr3.user_list'))
    
    new_password = request.form.get('new_password')
    if not new_password or len(new_password) < 8:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters long.'}), 400
        flash('Password must be at least 8 characters long.', 'warning')
        return redirect(url_for('hr3.user_list'))
    
    try:
        user.set_password(new_password, skip_validation=True)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'success', 'message': f'Password for {user.username} has been updated.'})
        flash(f'Password for {user.username} has been updated.', 'success')
    except Exception as e:
        error_msg = format_db_error(e)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': error_msg}), 400
        flash(error_msg, 'danger')
    return redirect(url_for('hr3.user_list'))

@hr3_bp.route('/analytics')
@login_required
def analytics():
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # 1. Attendance Analytics
    try:
        attendance_data = client.table('attendance_logs').select('*').execute().data or []
    except:
        attendance_data = []
        
    # 2. Leave Analytics
    try:
        leave_data = client.table('leave_requests').select('*').execute().data or []
    except:
        leave_data = []

    # 3. User distribution
    all_users = User.get_all()
    
    # Process attendance stats
    attendance_stats = {
        'On-time': 0,
        'Late': 0,
        'Absent': 0
    }
    for entry in attendance_data:
        status = entry.get('status')
        if status in attendance_stats:
            attendance_stats[status] += 1
            
    # Process leave stats
    leave_stats = {
        'Pending': 0,
        'Approved': 0,
        'Rejected': 0
    }
    leave_types = {}
    for entry in leave_data:
        status = entry.get('status')
        if status in leave_stats:
            leave_stats[status] += 1
        
        ltype = entry.get('leave_type')
        if ltype:
            leave_types[ltype] = leave_types.get(ltype, 0) + 1

    # Subsystem distribution
    subsystem_dist = {}
    for u in all_users:
        sub = u.subsystem.upper()
        subsystem_dist[sub] = subsystem_dist.get(sub, 0) + 1

    # Today's late logs
    today_str = datetime.now().strftime('%Y-%m-%d')
    late_today = []
    try:
        late_resp = client.table('attendance_logs').select('*, users(username)').gte('clock_in', today_str).eq('status', 'Late').execute()
        late_today = late_resp.data or []
    except Exception as e:
        print(f"Error fetching late logs: {e}")

    return render_template('subsystems/hr/hr3/analytics.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME,
                           attendance_stats=attendance_stats,
                           leave_stats=leave_stats,
                           leave_types=leave_types,
                           subsystem_dist=subsystem_dist,
                           late_today=late_today,
                           total_users=len(all_users),
                           datetime=datetime)

@hr3_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            try:
                current_user.update(email=email)
                flash('Settings updated successfully.', 'success')
            except Exception as e:
                flash(f'Update failed: {str(e)}', 'danger')
        return redirect(url_for(f'{BLUEPRINT_NAME}.settings'))
        
    return render_template('shared/settings.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr3_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hr3.login'))

@hr3_bp.route('/attendance')
@login_required
def list_attendance():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    query = client.table('attendance_logs').select('*, users(username)')
    
    # Non-admins only see their own logs
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        query = query.eq('user_id', current_user.id)
        
    response = query.order('clock_in', desc=True).execute()
    logs = response.data if response.data else []
    
    return render_template('subsystems/hr/hr3/attendance.html',
                           logs=logs,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr3_bp.route('/leaves')
@login_required
def list_leaves():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    query = client.table('leave_requests').select('*, users:users!leave_requests_user_id_fkey(username)')
    
    # Non-admins only see their own requests
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        query = query.eq('user_id', current_user.id)
        
    response = query.order('created_at', desc=True).execute()
    leaves = response.data if response.data else []
    
    return render_template('subsystems/hr/hr3/leaves.html',
                           leaves=leaves,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr3_bp.route('/leaves/approve', methods=['POST'])
@login_required
def approve_leave():
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    leave_id = request.form.get('leave_id')
    status = request.form.get('status') # 'Approved' or 'Rejected'
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('leave_requests').update({'status': status, 'approved_by': current_user.id}).eq('id', leave_id).execute()
        flash(f'Leave request {status.lower()} successfully!', 'success')
    except Exception as e:
        flash(f'Error updating leave request: {str(e)}', 'danger')
        
    return redirect(url_for('hr3.list_leaves'))
