from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required
from app import db
from models.fin_users import FIN5User
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from datetime import datetime

fin5_bp = Blueprint('fin5', __name__, template_folder='templates')

@fin5_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/financials/fin5/login.html', remaining_seconds=remaining_seconds)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = FIN5User.query.filter_by(username=username).first()
        
        if user:
            if user.check_password(password):
                # Check for password expiration
                if user.password_expires_at and user.password_expires_at < datetime.utcnow():
                    flash('Your password has expired. Please contact IT to reset it.', 'warning')
                    return render_template('subsystems/financials/fin5/login.html')

                # Clear IP lockout attempts on successful login
                register_successful_login()
                user.last_login = datetime.utcnow()
                db.session.commit()
                login_user(user)
                
                # Check if password is about to expire (e.g., within 10 days)
                days_left = (user.password_expires_at - datetime.utcnow()).days
                if days_left <= 10:
                    flash(f'Warning: Your password will expire in {days_left} days.', 'warning')
                    
                return redirect(url_for('fin5.dashboard'))
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/financials/fin5/login.html', remaining_seconds=remaining_seconds)
                else:
                    flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
        else:
            # Register failed attempt even for non-existent users
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
            
            if is_now_locked:
                flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                return render_template('subsystems/financials/fin5/login.html', remaining_seconds=remaining_seconds)
            else:
                flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
            
    return render_template('subsystems/financials/fin5/login.html')
@fin5_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('subsystems/financials/fin5/dashboard.html', now=datetime.utcnow)

@fin5_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('fin5.login'))
