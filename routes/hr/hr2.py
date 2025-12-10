from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from models.hr_user import HR2User
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import validate_password, PasswordValidationError
from datetime import datetime

hr2_bp = Blueprint('hr2', __name__, template_folder='templates')

# Subsystem configuration
SUBSYSTEM_NAME = 'HR2 - Payroll Management'
ACCENT_COLOR = '[#6366F1]'
BLUEPRINT_NAME = 'hr2'

@hr2_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/hr/hr2/login.html', remaining_seconds=remaining_seconds)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = HR2User.query.filter_by(username=username).first()
        
        if user:
            now_utc = datetime.utcnow()
            
            if user.check_password(password):
                # Check for password expiration - redirect to change password
                if user.password_expires_at and user.password_expires_at < now_utc:
                    session['expired_user_id'] = user.id
                    session['expired_subsystem'] = BLUEPRINT_NAME
                    flash('Your password has expired. Please set a new password to continue.', 'warning')
                    return redirect(url_for('hr2.change_password'))

                # Clear IP lockout attempts on successful login
                register_successful_login()
                user.last_login = now_utc
                db.session.commit()
                login_user(user)
                
                days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                if days_left <= 7:
                    flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    
                return redirect(url_for('hr2.dashboard'))
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/hr/hr2/login.html', remaining_seconds=remaining_seconds)
                else:
                    flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
        else:
            # Register failed attempt even for non-existent users
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
            
            if is_now_locked:
                flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                return render_template('subsystems/hr/hr2/login.html', remaining_seconds=remaining_seconds)
            else:
                flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
            
    return render_template('subsystems/hr/hr2/login.html')

@hr2_bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    expired_user_id = session.get('expired_user_id')
    expired_subsystem = session.get('expired_subsystem')
    is_expired = expired_user_id is not None and expired_subsystem == BLUEPRINT_NAME
    
    if is_expired:
        user = HR2User.query.get(expired_user_id)
        if not user:
            session.pop('expired_user_id', None)
            session.pop('expired_subsystem', None)
            flash('Session expired. Please login again.', 'danger')
            return redirect(url_for('hr2.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('hr2.login'))
    
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
            db.session.commit()
            session.pop('expired_user_id', None)
            session.pop('expired_subsystem', None)
            flash('Password updated successfully! Please login with your new password.', 'success')
            if current_user.is_authenticated:
                logout_user()
            return redirect(url_for('hr2.login'))
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html',
        subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@hr2_bp.route('/dashboard')
@login_required
def dashboard():
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    return render_template('subsystems/hr/hr2/dashboard.html', now=datetime.utcnow)

@hr2_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hr2.login'))
