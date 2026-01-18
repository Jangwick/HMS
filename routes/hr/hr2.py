from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from datetime import datetime

hr2_bp = Blueprint('hr2', __name__)

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
                    return render_template('subsystems/hr/hr2/login.html')

                # Check for password expiration - redirect to change password
                if user.password_expires_at and user.password_expires_at < now_utc:
                    session['expired_user_id'] = user.id
                    session['expired_subsystem'] = BLUEPRINT_NAME
                    flash('Your password has expired. Please set a new password to continue.', 'warning')
                    return redirect(url_for('hr2.change_password'))

                # Clear IP lockout attempts on successful login
                register_successful_login()
                user.register_successful_login()
                
                if login_user(user):
                    days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                    if days_left <= 7:
                        flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    return redirect(url_for('hr2.dashboard'))
                else:
                    flash('Login failed. Your account may be deactivated.', 'danger')
                    return render_template('subsystems/hr/hr2/login.html')
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/hr/hr2/login.html', remaining_seconds=remaining_seconds)
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
                return render_template('subsystems/hr/hr2/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/hr/hr2/login.html')

@hr2_bp.route('/register', methods=['GET', 'POST'])
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
                return redirect(url_for('hr2.login'))
            else:
                flash('Registration failed. Please try again.', 'danger')
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            flash(format_db_error(e), 'danger')
            
    return render_template('shared/register.html', 
                           subsystem_name=SUBSYSTEM_NAME, 
                           blueprint_name=BLUEPRINT_NAME,
                           hub_route='portal.hr_hub',
                           accent_color=ACCENT_COLOR)

@hr2_bp.route('/change-password', methods=['GET', 'POST'])
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
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Get payroll stats
    try:
        # Get total active employees
        response = client.table('users').select('id', count='exact').eq('status', 'Active').execute()
        total_employees = response.count if response.count is not None else 0
        
        # Get pending payrolls
        response = client.table('payroll_records').select('id', count='exact').eq('status', 'Pending').execute()
        pending_payroll = response.count if response.count is not None else 0
        
        # Get processed this month
        now = datetime.utcnow()
        first_day = now.replace(day=1).strftime('%Y-%m-%d')
        response = client.table('payroll_records').select('id', count='exact').gte('processed_date', first_day).execute()
        processed_this_month = response.count if response.count is not None else 0
        
    except Exception as e:
        print(f"Error fetching stats: {e}")
        total_employees = 0
        pending_payroll = 0
        processed_this_month = 0
    
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    return render_template('subsystems/hr/hr2/dashboard.html', 
                           now=datetime.utcnow,
                           total_employees=total_employees,
                           pending_payroll=pending_payroll,
                           processed_this_month=processed_this_month,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/payroll')
@login_required
def payroll_list():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Get all active employees
    all_users = User.get_all()
    employees = [u for u in all_users if u.status == 'Active']
    
    # Get latest payroll status for each employee (simplified)
    # In a real app, we'd join tables or do a batch query
    
    return render_template('subsystems/hr/hr2/payroll_list.html',
                           employees=employees,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/payroll/process', methods=['GET', 'POST'])
@login_required
def process_payroll():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    if request.method == 'POST':
        selected_employees = request.form.getlist('employee_ids')
        pay_period_start = request.form.get('start_date')
        pay_period_end = request.form.get('end_date')
        
        if not selected_employees:
            flash('Please select at least one employee.', 'warning')
            return redirect(url_for('hr2.process_payroll'))
            
        try:
            records = []
            for emp_id in selected_employees:
                # Placeholder calculations
                base_salary = 5000.00 
                deductions = 500.00
                bonuses = 0.00
                net_pay = base_salary - deductions + bonuses
                
                records.append({
                    'user_id': int(emp_id),
                    'pay_period_start': pay_period_start,
                    'pay_period_end': pay_period_end,
                    'base_salary': base_salary,
                    'deductions': deductions,
                    'bonuses': bonuses,
                    'net_pay': net_pay,
                    'status': 'Processed',
                    'processed_date': datetime.utcnow().isoformat()
                })
            
            if records:
                client.table('payroll_records').insert(records).execute()
                flash(f'Successfully processed payroll for {len(records)} employees.', 'success')
            
        except Exception as e:
            flash(f'Error processing payroll: {format_db_error(e)}', 'danger')
            
        return redirect(url_for('hr2.payroll_list'))
    
    # Get active employees
    all_users = User.get_all()
    employees = [u for u in all_users if u.status == 'Active']
    
    return render_template('subsystems/hr/hr2/process_payroll.html',
                           employees=employees,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/settings', methods=['GET', 'POST'])
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

@hr2_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hr2.login'))

@hr2_bp.route('/onboarding')
@login_required
def onboarding_pipeline():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch records from onboarding joined with applicants
    response = client.table('onboarding').select('*, applicants(*)').execute()
    onboarding_list = response.data if response.data else []
    
    return render_template('subsystems/hr/hr2/onboarding.html',
                           onboarding_list=onboarding_list,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/onboarding/complete', methods=['POST'])
@login_required
def complete_onboarding():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    onboarding_id = request.form.get('onboarding_id')
    
    try:
        # Update onboarding status
        client.table('onboarding').update({'status': 'Completed'}).eq('id', onboarding_id).execute()
        flash('Onboarding completed successfully!', 'success')
    except Exception as e:
        flash(f'Error finishing onboarding: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.onboarding_pipeline'))

@hr2_bp.route('/payslips')
@login_required
def list_payslips():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch all processed payroll records joined with user info
    response = client.table('payroll_records').select('*, users(username, email, role)').execute()
    payslips = response.data if response.data else []
    
    return render_template('subsystems/hr/hr2/payslips.html',
                           payslips=payslips,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/payslips/<int:record_id>')
@login_required
def view_payslip(record_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch specific payroll record
    response = client.table('payroll_records').select('*, users(*)').eq('id', record_id).single().execute()
    if not response.data:
        flash('Payslip not found.', 'danger')
        return redirect(url_for('hr2.list_payslips'))
    
    payslip = response.data
    return render_template('subsystems/hr/hr2/view_payslip.html',
                           payslip=payslip,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

