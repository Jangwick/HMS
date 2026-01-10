from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_wtf.csrf import generate_csrf
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User
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
                login_user(user)
                
                days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                if days_left <= 7:
                    flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    
                return redirect(url_for('hr3.dashboard'))
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/hr/hr3/login.html', remaining_seconds=remaining_seconds)
                else:
                    flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
        else:
            # Register failed attempt even for non-existent users
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
            
            if is_now_locked:
                flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                return render_template('subsystems/hr/hr3/login.html', remaining_seconds=remaining_seconds)
            else:
                flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
            
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
                           blueprint_name=BLUEPRINT_NAME)

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
    return render_template('subsystems/hr/hr3/dashboard.html', now=datetime.utcnow)

# Admin: User Management & Approvals
@hr3_bp.route('/admin/users')
@login_required
def user_list():
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    users = User.get_all()
    return render_template('subsystems/hr/hr3/admin/user_list.html', 
                           users=users, subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR)

@hr3_bp.route('/admin/approvals')
@login_required
def pending_approvals():
    if current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3':
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    # Filter for pending users
    all_users = User.get_all()
    pending_users = [u for u in all_users if u.status == 'Pending']
    
    return render_template('subsystems/hr/hr3/admin/approvals.html', 
                           users=pending_users, subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR)

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
    
    if action == 'approve':
        user.update(status='Active', is_active=True)
        flash(f'User {user.username} has been approved.', 'success')
    elif action == 'deny':
        user.update(status='Rejected', is_active=False)
        flash(f'User {user.username} has been rejected.', 'warning')
    
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
    
    # Toggle the status
    if user.status == 'Active':
        user.update(status='Rejected', is_active=False)
        flash(f'User {user.username} has been deactivated.', 'warning')
    else:
        user.update(status='Active', is_active=True)
        flash(f'User {user.username} has been activated.', 'success')
    
    return redirect(url_for('hr3.user_list'))

@hr3_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hr3.login'))
