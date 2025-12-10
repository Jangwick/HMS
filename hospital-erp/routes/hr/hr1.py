from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db, login_manager
from models.hr_user import HR1User
from datetime import datetime
import pytz

hr1_bp = Blueprint('hr1', __name__, template_folder='templates')

# Custom Login Manager for HR1? 
# For simplicity in this phase, we'll use the global one but we might need to separate sessions later
# or use a custom user loader that checks the blueprint.

@hr1_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = HR1User.query.filter_by(username=username).first()
        
        if user:
            now_utc = datetime.utcnow()
            if user.is_locked():
                locked_until_utc = user.account_locked_until
                if locked_until_utc > now_utc:
                    remaining_seconds = (locked_until_utc - now_utc).total_seconds()
                    # Convert to Manila time for display
                    manila_tz = pytz.timezone('Asia/Manila')
                    locked_until_manila = locked_until_utc.replace(tzinfo=pytz.utc).astimezone(manila_tz)
                    unlock_time_manila = locked_until_manila.strftime("%I:%M%p").lower()
                    
                    flash(f'Account locked. Try again at {unlock_time_manila}', 'danger')
                    return render_template('subsystems/hr/hr1/login.html', remaining_seconds=remaining_seconds)
                else:
                    user.failed_login_attempts = 0
                    user.account_locked_until = None
                    db.session.commit()

            if user.check_password(password):
                if user.password_expires_at and user.password_expires_at < now_utc:
                    flash('Your password has expired. Please contact IT to reset it.', 'warning')
                    return render_template('subsystems/hr/hr1/login.html')

                user.register_successful_login()
                db.session.commit()
                login_user(user)
                
                days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                if days_left <= 10:
                    flash(f'Warning: Your password will expire in {days_left} days.', 'warning')
                    
                return redirect(url_for('hr1.dashboard'))
            else:
                user.register_failed_login()
                db.session.commit()
                
                locked_until_utc = user.account_locked_until
                if locked_until_utc and locked_until_utc > now_utc:
                    remaining_seconds = (locked_until_utc - now_utc).total_seconds()
                    manila_tz = pytz.timezone('Asia/Manila')
                    locked_until_manila = locked_until_utc.replace(tzinfo=pytz.utc).astimezone(manila_tz)
                    unlock_time_manila = locked_until_manila.strftime("%I:%M%p").lower()
                    
                    flash(f'Account locked. Try again at {unlock_time_manila}', 'danger')
                    return render_template('subsystems/hr/hr1/login.html', remaining_seconds=remaining_seconds)
                else:
                    remaining_attempts = 5 - (user.failed_login_attempts % 5 if user.failed_login_attempts >= 5 else user.failed_login_attempts)
                    if remaining_attempts > 0 and user.failed_login_attempts < 5:
                         flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
                    elif user.failed_login_attempts >= 5:
                         flash(f'Invalid credentials. Account will lock again on next failure.', 'danger')
                    else:
                         flash('Invalid credentials.', 'danger')
        else:
            flash('Invalid username or password', 'danger')
            
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
