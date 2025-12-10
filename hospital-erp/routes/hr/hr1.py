from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db, login_manager
from models.hr_user import HR1User
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from datetime import datetime

hr1_bp = Blueprint('hr1', __name__, template_folder='templates')

@hr1_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/hr/hr1/login.html', remaining_seconds=remaining_seconds)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = HR1User.query.filter_by(username=username).first()
        
        if user:
            now_utc = datetime.utcnow()

            if user.check_password(password):
                if user.password_expires_at and user.password_expires_at < now_utc:
                    flash('Your password has expired. Please contact IT to reset it.', 'warning')
                    return render_template('subsystems/hr/hr1/login.html')

                # Clear IP lockout attempts on successful login
                register_successful_login()
                user.last_login = now_utc
                db.session.commit()
                login_user(user)
                
                days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                if days_left <= 10:
                    flash(f'Warning: Your password will expire in {days_left} days.', 'warning')
                    
                return redirect(url_for('hr1.dashboard'))
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/hr/hr1/login.html', remaining_seconds=remaining_seconds)
                else:
                    flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
        else:
            # Register failed attempt even for non-existent users (prevents user enumeration)
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
            
            if is_now_locked:
                flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                return render_template('subsystems/hr/hr1/login.html', remaining_seconds=remaining_seconds)
            else:
                flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
            
    return render_template('subsystems/hr/hr1/login.html')

@hr1_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('subsystems/hr/hr1/dashboard.html', now=datetime.utcnow)

@hr1_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hr1.login'))
