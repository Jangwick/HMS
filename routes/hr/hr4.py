from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error, get_supabase_client
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from datetime import datetime

hr4_bp = Blueprint('hr4', __name__)

# Subsystem configuration
SUBSYSTEM_NAME = 'HR4 - Compensation & Analytics'
ACCENT_COLOR = '#6366F1'
BLUEPRINT_NAME = 'hr4'

@hr4_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/hr/hr4/login.html', remaining_seconds=remaining_seconds)
    
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
                    return render_template('subsystems/hr/hr4/login.html')

                # Check for password expiration - redirect to change password
                if user.password_expires_at and user.password_expires_at < now_utc:
                    session['expired_user_id'] = user.id
                    session['expired_subsystem'] = BLUEPRINT_NAME
                    flash('Your password has expired. Please set a new password to continue.', 'warning')
                    return redirect(url_for('hr4.change_password'))

                # Clear IP lockout attempts on successful login
                register_successful_login()
                user.register_successful_login()
                
                if login_user(user):
                    days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                    if days_left <= 7:
                        flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    return redirect(url_for('hr4.dashboard'))
                else:
                    flash('Login failed. Your account may be deactivated.', 'danger')
                    return render_template('subsystems/hr/hr4/login.html')
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/hr/hr4/login.html', remaining_seconds=remaining_seconds)
                else:
                    flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
        else:
            try:
                other_user = User.get_by_username(username)
                if other_user:
                    sub = other_user.subsystem.upper()
                    flash(f'Account found in {sub} department. Please log in through the correct portal.', 'warning')
                else:
                    flash('Invalid credentials.', 'danger')
            except:
                flash('Invalid credentials.', 'danger')
                
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
            if is_now_locked:
                return render_template('subsystems/hr/hr4/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/hr/hr4/login.html')

@hr4_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Successfully logged out.', 'success')
    return redirect(url_for('hr4.login'))

@hr4_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
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
                return redirect(url_for('hr4.login'))
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

@hr4_bp.route('/change-password', methods=['GET', 'POST'])
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
            return redirect(url_for('hr4.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('hr4.login'))
    
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
            return redirect(url_for('hr4.login'))
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html',
        subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@hr4_bp.route('/dashboard')
@login_required
@policy_required(BLUEPRINT_NAME)
def dashboard():
    client = get_supabase_client()
    try:
        response = client.table('compensation_records').select('base_salary, allowances, bonuses').eq('status', 'Active').execute()
        raw_data = response.data if response.data else []
        
        salaries = [float(r['base_salary']) for r in raw_data]
        total = sum(float(r['base_salary']) + float(r.get('allowances', 0)) + float(r.get('bonuses', 0)) for r in raw_data)
        
        avg_salary = sum(salaries) / len(salaries) if salaries else 0
        total_payroll = total
        
        grades_resp = client.table('salary_grades').select('id', count='exact').execute()
        total_grades = grades_resp.count if grades_resp.count is not None else 0
        
        # New: Pending payroll check
        now = datetime.utcnow()
        month_str = now.strftime('%m-%Y')
        payroll_resp = client.table('payroll_records').select('id').gte('pay_period_start', now.replace(day=1).strftime('%Y-%m-%d')).execute()
        payroll_processed = len(payroll_resp.data) > 0
        
        recent_updates = client.table('compensation_records').select('*, users(username)').order('effective_date', desc=True).limit(5).execute().data or []
    except Exception as e:
        print(f"Error fetching HR4 stats: {e}")
        avg_salary = 0
        total_payroll = 0
        total_grades = 0
        payroll_processed = False
        recent_updates = []
    
    return render_template('subsystems/hr/hr4/dashboard.html', 
                           now=datetime.utcnow,
                           avg_salary=avg_salary,
                           total_payroll=total_payroll,
                           total_grades=total_grades,
                           payroll_processed=payroll_processed,
                           recent_updates=recent_updates,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr4_bp.route('/compensation')
@login_required
def compensation():
    client = get_supabase_client()
    try:
        response = client.table('compensation_records').select('*, users(username, email, department)').order('effective_date', desc=True).execute()
        comp_records = response.data if response.data else []
        all_users = User.get_all()
    except Exception as e:
        print(f"Error fetching compensation: {e}")
        comp_records = []
        all_users = []

    return render_template('subsystems/hr/hr4/compensation.html',
                           comp_records=comp_records,
                           all_users=all_users,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr4_bp.route('/compensation/add', methods=['POST'])
@login_required
def add_compensation():
    client = get_supabase_client()
    try:
        data = {
            'user_id': int(request.form.get('user_id')),
            'base_salary': float(request.form.get('base_salary') or 0),
            'allowances': float(request.form.get('allowances') or 0),
            'bonuses': float(request.form.get('bonuses') or 0),
            'deductions': float(request.form.get('deductions') or 0),
            'effective_date': datetime.utcnow().strftime('%Y-%m-%d'),
            'status': 'Active'
        }
        client.table('compensation_records').insert(data).execute()
        flash('Compensation record added successfully.', 'success')
    except Exception as e:
        flash(f'Error adding record: {str(e)}', 'danger')
    return redirect(url_for('hr4.compensation'))

@hr4_bp.route('/compensation/edit/<int:record_id>', methods=['POST'])
@login_required
def edit_compensation(record_id):
    client = get_supabase_client()
    try:
        data = {
            'base_salary': float(request.form.get('base_salary') or 0),
            'allowances': float(request.form.get('allowances') or 0),
            'bonuses': float(request.form.get('bonuses') or 0),
            'deductions': float(request.form.get('deductions') or 0),
            'status': request.form.get('status', 'Active')
        }
        client.table('compensation_records').update(data).eq('id', record_id).execute()
        flash('Compensation record updated.', 'success')
    except Exception as e:
        flash(f'Error updating record: {str(e)}', 'danger')
    return redirect(url_for('hr4.compensation'))

@hr4_bp.route('/compensation/delete/<int:record_id>', methods=['POST'])
@login_required
def delete_compensation(record_id):
    client = get_supabase_client()
    try:
        client.table('compensation_records').delete().eq('id', record_id).execute()
        flash('Record deleted.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr4.compensation'))

@hr4_bp.route('/salary-grades')
@login_required
def salary_grades():
    client = get_supabase_client()
    try:
        response = client.table('salary_grades').select('*').order('grade_name').execute()
        grades = response.data if response.data else []
    except Exception as e:
        print(f"Error fetching grades: {e}")
        grades = []
        
    return render_template('subsystems/hr/hr4/salary_grades.html',
                           grades=grades,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr4_bp.route('/salary-grades/add', methods=['POST'])
@login_required
def add_salary_grade():
    client = get_supabase_client()
    try:
        min_salary = float(request.form.get('min_salary') or 0)
        max_salary = float(request.form.get('max_salary') or 0)
        
        if min_salary >= max_salary:
            flash('Minimum salary must be less than maximum salary.', 'danger')
            return redirect(url_for('hr4.salary_grades'))

        data = {
            'grade_name': request.form.get('grade_name'),
            'min_salary': min_salary,
            'max_salary': max_salary
        }
        client.table('salary_grades').insert(data).execute()
        flash('Salary grade created.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr4.salary_grades'))

@hr4_bp.route('/salary-grades/edit/<int:grade_id>', methods=['POST'])
@login_required
def edit_salary_grade(grade_id):
    client = get_supabase_client()
    try:
        min_salary = float(request.form.get('min_salary') or 0)
        max_salary = float(request.form.get('max_salary') or 0)
        
        if min_salary >= max_salary:
            flash('Minimum salary must be less than maximum salary.', 'danger')
            return redirect(url_for('hr4.salary_grades'))

        data = {
            'grade_name': request.form.get('grade_name'),
            'min_salary': min_salary,
            'max_salary': max_salary
        }
        client.table('salary_grades').update(data).eq('id', grade_id).execute()
        flash('Salary grade updated.', 'success')
    except Exception as e:
        flash(f'Error updating grade: {str(e)}', 'danger')
    return redirect(url_for('hr4.salary_grades'))

@hr4_bp.route('/salary-grades/delete/<int:grade_id>', methods=['POST'])
@login_required
def delete_salary_grade(grade_id):
    client = get_supabase_client()
    try:
        client.table('salary_grades').delete().eq('id', grade_id).execute()
        flash('Salary grade deleted.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr4.salary_grades'))

@hr4_bp.route('/payroll')
@login_required
def payroll():
    client = get_supabase_client()
    try:
        # Get payroll records for the current month
        now = datetime.utcnow()
        first_day = now.replace(day=1).strftime('%Y-%m-%d')
        last_day = now.strftime('%Y-%m-%d') # Simplified for current state
        
        response = client.table('payroll_records').select('*, users(username, department)').order('processed_date', desc=True).limit(50).execute()
        payroll_history = response.data if response.data else []
        
        # Check if current month is already processed
        # For simplicity, we'll just check if any record exists for this month
        month_str = now.strftime('%m-%Y')
        is_processed = any(datetime.strptime(r['pay_period_end'], '%Y-%m-%d').strftime('%m-%Y') == month_str for r in payroll_history)
        
    except Exception as e:
        print(f"Error fetching payroll: {e}")
        payroll_history = []
        is_processed = False
        
    return render_template('subsystems/hr/hr4/payroll.html',
                           payroll_history=payroll_history,
                           is_processed=is_processed,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr4_bp.route('/payroll/process', methods=['POST'])
@login_required
def process_payroll():
    client = get_supabase_client()
    try:
        # 1. Get all active compensation records
        res = client.table('compensation_records').select('*').eq('status', 'Active').execute()
        comp_records = res.data or []
        
        if not comp_records:
            flash('No active compensation records found to process.', 'warning')
            return redirect(url_for('hr4.payroll'))
            
        now = datetime.utcnow()
        pay_period_start = now.replace(day=1).strftime('%Y-%m-%d')
        # Last day of month (simple calculation)
        import calendar
        last_day_num = calendar.monthrange(now.year, now.month)[1]
        pay_period_end = now.replace(day=last_day_num).strftime('%Y-%m-%d')
        
        processed_count = 0
        for rec in comp_records:
            net_pay = float(rec['base_salary']) + float(rec['allowances']) + float(rec['bonuses']) - float(rec['deductions'])
            
            payroll_data = {
                'user_id': rec['user_id'],
                'pay_period_start': pay_period_start,
                'pay_period_end': pay_period_end,
                'base_salary': rec['base_salary'],
                'bonuses': rec['bonuses'],
                'deductions': rec['deductions'],
                'net_pay': net_pay,
                'status': 'Processed'
            }
            client.table('payroll_records').insert(payroll_data).execute()
            processed_count += 1
            
        flash(f'Successfully processed payroll for {processed_count} employees.', 'success')
    except Exception as e:
        flash(f'Error processing payroll: {str(e)}', 'danger')
        
    return redirect(url_for('hr4.payroll'))

@hr4_bp.route('/analytics')
@login_required
def analytics():
    client = get_supabase_client()
    try:
        # Get all active compensation records joined with users
        res = client.table('compensation_records').select('*, users(username, department)').eq('status', 'Active').execute()
        records = res.data or []
        
        total_salary = sum(float(r.get('base_salary') or 0) for r in records)
        total_allowances = sum(float(r.get('allowances') or 0) for r in records)
        total_bonuses = sum(float(r.get('bonuses') or 0) for r in records)
        total_deductions = sum(float(r.get('deductions') or 0) for r in records)
        
        # 1. Department spending distribution
        dept_data = {}
        for r in records:
            dept = r.get('users', {}).get('department', 'Unassigned') or 'Unassigned'
            amount = float(r.get('base_salary') or 0) + float(r.get('allowances') or 0) + float(r.get('bonuses') or 0)
            dept_data[dept] = dept_data.get(dept, 0) + amount
            
        # 2. Salary range frequency
        ranges = {"0-30k": 0, "30k-60k": 0, "60k-100k": 0, "100k+": 0}
        for r in records:
            val = float(r.get('base_salary') or 0)
            if val < 30000: ranges["0-30k"] += 1
            elif val < 60000: ranges["30k-60k"] += 1
            elif val < 100000: ranges["60k-100k"] += 1
            else: ranges["100k+"] += 1

        # 3. Overall compensation structure
        structure = {
            'Base Salary': total_salary,
            'Allowances': total_allowances,
            'Bonuses': total_bonuses
        }

        # 4. Top 5 Highest Paid (Total Package)
        sorted_records = sorted(records, key=lambda x: float(x.get('base_salary', 0)) + float(x.get('allowances', 0)) + float(x.get('bonuses', 0)), reverse=True)
        top_earners = []
        for r in sorted_records[:5]:
            top_earners.append({
                'name': r.get('users', {}).get('username', 'Unknown'),
                'department': r.get('users', {}).get('department', 'N/A'),
                'total': float(r.get('base_salary', 0)) + float(r.get('allowances', 0)) + float(r.get('bonuses', 0))
            })

        metrics = {
            'total_annual_budget': total_salary + total_allowances + total_bonuses,
            'avg_salary': total_salary / len(records) if records else 0,
            'total_allowances': total_allowances,
            'total_bonuses': total_bonuses,
            'total_deductions': total_deductions,
            'count': len(records),
            'dept_distribution': {
                'labels': list(dept_data.keys()),
                'data': list(dept_data.values())
            },
            'salary_ranges': {
                'labels': list(ranges.keys()),
                'data': list(ranges.values())
            },
            'structure': {
                'labels': list(structure.keys()),
                'data': list(structure.values())
            },
            'top_earners': top_earners
        }
    except Exception as e:
        print(f"Error calculating analytics: {e}")
        metrics = {'total_annual_budget': 0, 'avg_salary': 0, 'total_allowances': 0, 'total_bonuses': 0, 'count': 0, 'dept_distribution': {'labels': [], 'data': []}, 'salary_ranges': {'labels': [], 'data': []}, 'structure': {'labels': [], 'data': []}, 'top_earners': []}

    return render_template('subsystems/hr/hr4/analytics.html',
                           metrics=metrics,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME,
                           datetime=datetime)

@hr4_bp.route('/reports')
@login_required
def reports():
    return render_template('subsystems/hr/hr4/reports.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr4_bp.route('/reports/view/<report_type>')
@login_required
def view_report(report_type):
    client = get_supabase_client()
    data = []
    headers = []
    row_keys = []
    title = ""

    if report_type == 'compensation':
        title = "Annual Compensation Summary"
        try:
            res = client.table('compensation_records').select('*, users(username, department)').execute()
            raw_data = res.data or []
            for r in raw_data:
                data.append({
                    'employee': r.get('users', {}).get('username', 'N/A'),
                    'department': r.get('users', {}).get('department', 'N/A'),
                    'base_salary': r.get('base_salary', 0),
                    'allowances': r.get('allowances', 0),
                    'bonuses': r.get('bonuses', 0),
                    'effective_date': r.get('effective_date'),
                    'status': r.get('status')
                })
            headers = ['Employee', 'Department', 'Base Salary', 'Allowances', 'Bonuses', 'Effective Date', 'Status']
            row_keys = ['employee', 'department', 'base_salary', 'allowances', 'bonuses', 'effective_date', 'status']
        except Exception as e: 
            flash(f"Error loading compensation data: {str(e)}", "danger")

    elif report_type == 'budget':
        title = "Departmental Budget Allocation"
        try:
            res = client.table('compensation_records').select('*, users(department)').execute()
            raw_data = res.data or []
            dept_totals = {}
            for r in raw_data:
                dept = r.get('users', {}).get('department', 'Unknown')
                if dept not in dept_totals:
                    dept_totals[dept] = {'count': 0, 'total': 0.0}
                dept_totals[dept]['count'] += 1
                dept_totals[dept]['total'] += float(r.get('base_salary') or 0) + float(r.get('allowances') or 0)

            for dept, stats in dept_totals.items():
                data.append({
                    'department': dept,
                    'staff_count': stats['count'],
                    'total_budget': stats['total'],
                    'status': 'Active'
                })
            headers = ['Department', 'Staff count', 'Total Budget', 'Status']
            row_keys = ['department', 'staff_count', 'total_budget', 'status']
        except Exception as e: 
            flash(f"Error calculating budget data: {str(e)}", "danger")

    elif report_type == 'payroll':
        title = "Recent Payroll Transactions"
        try:
            res = client.table('payroll_records').select('*, users(username, department)').order('processed_date', desc=True).limit(50).execute()
            raw_data = res.data or []
            for r in raw_data:
                data.append({
                    'employee': r.get('users', {}).get('username', 'N/A'),
                    'department': r.get('users', {}).get('department', 'N/A'),
                    'net_pay': r.get('net_pay', 0),
                    'period': f"{r.get('pay_period_start')} - {r.get('pay_period_end')}",
                    'status': r.get('status'),
                    'date': r.get('processed_date')[:10] if r.get('processed_date') else 'N/A'
                })
            headers = ['Employee', 'Department', 'Net Pay', 'Pay Period', 'Status', 'Processed Date']
            row_keys = ['employee', 'department', 'net_pay', 'period', 'status', 'date']
        except Exception as e: 
            flash(f"Error loading payroll data: {str(e)}", "danger")

    if not title:
        flash('Report type not found.', 'warning')
        return redirect(url_for('hr4.reports'))

    return render_template('subsystems/hr/hr4/report_view.html',
                           title=title, data=data, headers=headers, row_keys=row_keys,
                           report_type=report_type, subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME,
                           datetime=datetime)

@hr4_bp.route('/reports/export/<report_type>')
@login_required
def export_report(report_type):
    import io
    import csv
    from flask import Response, request
    
    export_format = request.args.get('format', 'csv').lower()
    client = get_supabase_client()
    
    data = []
    headers = []
    
    try:
        # Fetch Data based on report type
        if report_type == 'compensation':
            res = client.table('compensation_records').select('*, users(username, department)').execute()
            raw_data = res.data or []
            headers = ['Employee', 'Department', 'Base Salary', 'Allowances', 'Bonuses', 'Effective Date', 'Status']
            for r in raw_data:
                data.append([
                    r.get('users', {}).get('username'),
                    r.get('users', {}).get('department'),
                    r.get('base_salary'),
                    r.get('allowances'),
                    r.get('bonuses'),
                    r.get('effective_date'),
                    r.get('status')
                ])
        elif report_type == 'budget':
            res = client.table('compensation_records').select('*, users(department)').execute()
            raw_data = res.data or []
            dept_totals = {}
            for r in raw_data:
                dept = r.get('users', {}).get('department', 'Unknown')
                if dept not in dept_totals:
                    dept_totals[dept] = {'count': 0, 'total': 0.0}
                dept_totals[dept]['count'] += 1
                dept_totals[dept]['total'] += float(r.get('base_salary') or 0) + float(r.get('allowances') or 0)
            
            headers = ['Department', 'Staff Count', 'Total Budget Allocation']
            for dept, stats in dept_totals.items():
                data.append([dept, stats['count'], stats['total']])
        elif report_type == 'payroll':
            res = client.table('payroll_records').select('*, users(username, department)').order('processed_date', desc=True).execute()
            raw_data = res.data or []
            headers = ['Employee', 'Department', 'Net Pay', 'Pay Period Start', 'Pay Period End', 'Status', 'Processed Date']
            for r in raw_data:
                data.append([
                    r.get('users', {}).get('username'),
                    r.get('users', {}).get('department'),
                    r.get('net_pay'),
                    r.get('pay_period_start'),
                    r.get('pay_period_end'),
                    r.get('status'),
                    r.get('processed_date')
                ])

        if not data:
            flash("No data found for this report type to export.", "warning")
            return redirect(url_for('hr4.view_report', report_type=report_type))

        # Format handling
        if export_format == 'csv':
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(headers)
            writer.writerows(data)
            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-disposition": f"attachment; filename=hr_report_{report_type}.csv"}
            )

        elif export_format == 'excel':
            from openpyxl import Workbook
            wb = Workbook()
            ws = wb.active
            ws.append(headers)
            for row in data:
                ws.append(row)
            
            output = io.BytesIO()
            wb.save(output)
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={"Content-disposition": f"attachment; filename=hr_report_{report_type}.xlsx"}
            )

        elif export_format == 'pdf':
            from reportlab.lib.pagesizes import letter, landscape
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet

            output = io.BytesIO()
            doc = SimpleDocTemplate(output, pagesize=landscape(letter))
            elements = []
            
            styles = getSampleStyleSheet()
            elements.append(Paragraph(f"HR Report: {report_type.replace('_', ' ').capitalize()}", styles['Title']))
            elements.append(Spacer(1, 20))
            
            # Convert all data to string for PDF Table compatibility
            pdf_data = [headers]
            for row in data:
                pdf_data.append([str(item) if item is not None else "" for item in row])
            
            t = Table(pdf_data)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.indigo),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
            ]))
            elements.append(t)
            doc.build(elements)
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype="application/pdf",
                headers={"Content-disposition": f"attachment; filename=hr_report_{report_type}.pdf"}
            )

    except Exception as e:
        flash(f"Export failed: {str(e)}", "danger")
        return redirect(url_for('hr4.reports'))

@hr4_bp.route('/settings', methods=['GET', 'POST'])
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
		return redirect(url_for('hr4.settings'))
		
	return render_template('shared/settings.html',
						   subsystem_name=SUBSYSTEM_NAME,
						   accent_color=ACCENT_COLOR,
						   blueprint_name=BLUEPRINT_NAME)

