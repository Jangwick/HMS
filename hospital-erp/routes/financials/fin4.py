from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required
from app import db
from models.fin_users import FIN4User
from datetime import datetime
import pytz

fin4_bp = Blueprint('fin4', __name__, template_folder='templates')

@fin4_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = FIN4User.query.filter_by(username=username).first()
        
        if user:
            # Check for lockout
            if user.is_locked():
                 remaining_seconds = int((user.account_locked_until - datetime.utcnow()).total_seconds())
                 
                 # Convert to Manila time for display
                 tz_manila = pytz.timezone('Asia/Manila')
                 # Ensure account_locked_until is treated as UTC (since we store it as naive UTC)
                 locked_until_utc = pytz.utc.localize(user.account_locked_until)
                 unlock_time_manila = locked_until_utc.astimezone(tz_manila)
                 unlock_time_str = unlock_time_manila.strftime("%I:%M%p").lower()
                 
                 flash(f'Account locked. Try again at {unlock_time_str}', 'danger')
                 return render_template('subsystems/financials/fin4/login.html', remaining_seconds=remaining_seconds)

            if user.check_password(password):
                # Check for password expiration
                if user.password_expires_at and user.password_expires_at < datetime.utcnow():
                    flash('Your password has expired. Please contact IT to reset it.', 'warning')
                    return render_template('subsystems/financials/fin4/login.html')

                user.register_successful_login()
                db.session.commit()
                login_user(user)
                
                # Check if password is about to expire (e.g., within 10 days)
                days_left = (user.password_expires_at - datetime.utcnow()).days
                if days_left <= 10:
                    flash(f'Warning: Your password will expire in {days_left} days.', 'warning')
                    
                return redirect(url_for('fin4.dashboard'))
            else:
                user.register_failed_login()
                db.session.commit()
                
                if user.is_locked():
                     remaining_seconds = int((user.account_locked_until - datetime.utcnow()).total_seconds())
                     
                     # Convert to Manila time for display
                     tz_manila = pytz.timezone('Asia/Manila')
                     locked_until_utc = pytz.utc.localize(user.account_locked_until)
                     unlock_time_manila = locked_until_utc.astimezone(tz_manila)
                     unlock_time_str = unlock_time_manila.strftime("%I:%M%p").lower()
                     
                     flash(f'Account locked. Try again at {unlock_time_str}', 'danger')
                     return render_template('subsystems/financials/fin4/login.html', remaining_seconds=remaining_seconds)
                else:
                    remaining = 5 - user.failed_login_attempts
                    if remaining > 0:
                        flash(f'Invalid credentials. {remaining} attempts remaining before lockout.', 'danger')
                    else:
                        flash('Account locked due to too many failed attempts.', 'danger')
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('subsystems/financials/fin4/login.html')
@fin4_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('subsystems/financials/fin4/dashboard.html', now=datetime.utcnow)

@fin4_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('fin4.login'))
