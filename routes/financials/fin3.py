from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from datetime import datetime

fin3_bp = Blueprint('fin3', __name__, template_folder='templates')

# Subsystem configuration
SUBSYSTEM_NAME = 'FIN3 - Accounts Receivable'
ACCENT_COLOR = '[#EF4444]'
BLUEPRINT_NAME = 'fin3'

@fin3_bp.route('/login', methods=['GET', 'POST'])
def login():
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/financials/fin3/login.html', remaining_seconds=remaining_seconds)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.get_by_username(username, BLUEPRINT_NAME)
        
        if user:
            now_utc = datetime.utcnow()
            if user.check_password(password):
                if user.password_expires_at and user.password_expires_at < now_utc:
                    session['expired_user_id'] = user.id
                    session['expired_subsystem'] = BLUEPRINT_NAME
                    flash('Your password has expired. Please set a new password to continue.', 'warning')
                    return redirect(url_for('fin3.change_password'))
                register_successful_login()
                user.register_successful_login()
                login_user(user)
                days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                if days_left <= 7:
                    flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                return redirect(url_for('fin3.dashboard'))
            else:
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/financials/fin3/login.html', remaining_seconds=remaining_seconds)
                else:
                    flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
        else:
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
            if is_now_locked:
                flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                return render_template('subsystems/financials/fin3/login.html', remaining_seconds=remaining_seconds)
            else:
                flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
    return render_template('subsystems/financials/fin3/login.html')

@fin3_bp.route('/register', methods=['GET', 'POST'])
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
                department='Financials',
                status='Pending'
            )
            
            if new_user:
                flash('Registration successful! Your account is awaiting approval from HR3 Admin.', 'success')
                return redirect(url_for('fin3.login'))
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
                           hub_route='portal.financials_hub',
                           accent_color=ACCENT_COLOR)

@fin3_bp.route('/change-password', methods=['GET', 'POST'])
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
            return redirect(url_for('fin3.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('fin3.login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not is_expired and not user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('shared/change_password.html', subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('shared/change_password.html', subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)
        
        try:
            user.set_password(new_password)
            session.pop('expired_user_id', None)
            session.pop('expired_subsystem', None)
            flash('Password updated successfully! Please login with your new password.', 'success')
            if current_user.is_authenticated:
                logout_user()
            return redirect(url_for('fin3.login'))
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html', subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@fin3_bp.route('/dashboard')
@login_required
def dashboard():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Get total receivables (Sum of open receivables)
        response = client.table('receivables').select('amount_due').eq('status', 'Open').execute()
        amounts = [r['amount_due'] for r in response.data] if response.data else []
        total_receivables = sum(amounts)
        
        # Get overdue count
        today = datetime.utcnow().strftime('%Y-%m-%d')
        response = client.table('receivables').select('id', count='exact').eq('status', 'Open').lt('due_date', today).execute()
        overdue_count = response.count if response.count is not None else 0
        
        # Get collected this month
        now = datetime.utcnow()
        first_day = now.replace(day=1).strftime('%Y-%m-%d')
        response = client.table('collections').select('amount').gte('collection_date', first_day).execute()
        collected_amounts = [r['amount'] for r in response.data] if response.data else []
        collected_this_month = sum(collected_amounts)
        
    except Exception as e:
        print(f"Error fetching stats: {e}")
        total_receivables = 0.0
        overdue_count = 0
        collected_this_month = 0.0
    
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    return render_template('subsystems/financials/fin3/dashboard.html', 
                           now=datetime.utcnow,
                           total_receivables=total_receivables,
                           overdue_count=overdue_count,
                           collected_this_month=collected_this_month,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@fin3_bp.route('/receivables')
@login_required
def receivables_list():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Fetch receivables
        response = client.table('receivables').select('*').order('due_date').execute()
        receivables = response.data if response.data else []
        
        # Enrich with billing/patient info (simplified)
        for rec in receivables:
            if rec.get('billing_record_id'):
                bill_resp = client.table('billing_records').select('patient_id').eq('id', rec['billing_record_id']).single().execute()
                if bill_resp.data:
                    # Get patient name
                    pat_resp = client.table('patients').select('first_name, last_name').eq('id', bill_resp.data['patient_id']).single().execute()
                    if pat_resp.data:
                        rec['patient_name'] = f"{pat_resp.data['first_name']} {pat_resp.data['last_name']}"
                    else:
                        rec['patient_name'] = 'Unknown Patient'
            else:
                rec['patient_name'] = 'N/A'
                
    except Exception as e:
        print(f"Error fetching receivables: {e}")
        receivables = []
        
    return render_template('subsystems/financials/fin3/receivables.html',
                           receivables=receivables,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@fin3_bp.route('/collections')
@login_required
def collections():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Fetch collections
        response = client.table('collections').select('*').order('collection_date', desc=True).execute()
        collections = response.data if response.data else []
        
        # Enrich with receivable info
        for col in collections:
            if col.get('receivable_id'):
                # In a real app, we'd fetch more details
                col['reference'] = f"REC-{col['receivable_id']}"
            else:
                col['reference'] = 'N/A'
                
    except Exception as e:
        print(f"Error fetching collections: {e}")
        collections = []
        
    return render_template('subsystems/financials/fin3/collections.html',
                           collections=collections,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@fin3_bp.route('/settings', methods=['GET', 'POST'])
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

@fin3_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('fin3.login'))

