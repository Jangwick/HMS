from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_wtf.csrf import generate_csrf
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, SUBSYSTEM_CONFIG, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from datetime import datetime

hr3_bp = Blueprint('hr3', __name__)

# Subsystem configuration
SUBSYSTEM_NAME = 'HR3 - Benefits Administration'
ACCENT_COLOR = '[#6366F1]'
BLUEPRINT_NAME = 'hr3'

@hr3_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/hr/hr3/login.html', remaining_seconds=remaining_seconds)
    
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
                    return render_template('subsystems/hr/hr3/login.html')

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
                    return render_template('subsystems/hr/hr3/login.html')
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/hr/hr3/login.html', remaining_seconds=remaining_seconds)
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
                return render_template('subsystems/hr/hr3/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/hr/hr3/login.html')

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
def dashboard():
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    
    # Get stats for the dashboard
    all_users = User.get_all()
    active_count = len([u for u in all_users if u.status == 'Active'])
    pending_count = len([u for u in all_users if u.status == 'Pending'])
    
    return render_template('subsystems/hr/hr3/dashboard.html', 
                          now=datetime.utcnow, 
                          active_count=active_count,
                          pending_count=pending_count,
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
                           subsystem_config=SUBSYSTEM_CONFIG)

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
                                   user=None)
        
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
                           user=None)

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
                           user=user)

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
                          accent_color=ACCENT_COLOR)

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
