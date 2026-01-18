from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
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
                return render_template('subsystems/hr/hr4/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/hr/hr4/login.html')

@hr4_bp.route('/register', methods=['GET', 'POST'])
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
def dashboard():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Get compensation & analytics stats
    try:
        # Calculate average salary
        response = client.table('compensation_records').select('base_salary').execute()
        salaries = [r['base_salary'] for r in response.data] if response.data else []
        avg_salary = sum(salaries) / len(salaries) if salaries else 0
        
        # Calculate total compensation (monthly)
        total_compensation = sum(salaries)
        
        # Count reports (placeholder for now as we don't have a specific table for HR reports)
        analytics_reports = 12 
        
    except Exception as e:
        print(f"Error fetching stats: {e}")
        avg_salary = 0
        total_compensation = 0
        analytics_reports = 0
    
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    return render_template('subsystems/hr/hr4/dashboard.html', 
                           now=datetime.utcnow,
                           avg_salary=avg_salary,
                           total_compensation=total_compensation,
                           analytics_reports=analytics_reports,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr4_bp.route('/compensation')
@login_required
def compensation():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Fetch compensation records with user details
        # Note: Supabase-py might not support complex joins easily in one go without foreign keys set up perfectly
        # So we might need to do it in two steps or use a view
        
        # Step 1: Get compensation records
        comp_response = client.table('compensation_records').select('*').execute()
        compensation_data = comp_response.data if comp_response.data else []
        
        # Step 2: Enrich with user data (simplified)
        for record in compensation_data:
            user = User.get_by_id(record['user_id'])
            if user:
                record['employee_name'] = user.username
                record['department'] = user.department
            else:
                record['employee_name'] = 'Unknown'
                record['department'] = 'N/A'
                
        # Step 3: Get all users for the "Add" modal
        all_users = User.get_all()
                
    except Exception as e:
        print(f"Error fetching compensation: {e}")
        compensation_data = []
        all_users = []

    return render_template('subsystems/hr/hr4/compensation.html',
                           compensation_data=compensation_data,
                           all_users=all_users,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr4_bp.route('/compensation/add', methods=['POST'])
@login_required
def add_compensation():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    user_id = request.form.get('user_id')
    base_salary = float(request.form.get('base_salary') or 0)
    allowances = float(request.form.get('allowances') or 0)
    bonuses = float(request.form.get('bonuses') or 0)
    deductions = float(request.form.get('deductions') or 0)
    
    try:
        data = {
            'user_id': int(user_id),
            'base_salary': base_salary,
            'allowances': allowances,
            'bonuses': bonuses,
            'deductions': deductions,
            'effective_date': datetime.utcnow().strftime('%Y-%m-%d'),
            'status': 'Active'
        }
        client.table('compensation_records').insert(data).execute()
        flash('Compensation record added successfully.', 'success')
    except Exception as e:
        flash(f'Error adding record: {str(e)}', 'danger')
    
    return redirect(url_for('hr4.compensation'))

@hr4_bp.route('/compensation/delete/<int:record_id>', methods=['POST'])
@login_required
def delete_compensation(record_id):
    from utils.supabase_client import get_supabase_client
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
    from utils.supabase_client import get_supabase_client
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
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    grade_name = request.form.get('grade_name')
    min_salary = float(request.form.get('min_salary') or 0)
    max_salary = float(request.form.get('max_salary') or 0)
    
    try:
        data = {
            'grade_name': grade_name,
            'min_salary': min_salary,
            'max_salary': max_salary
        }
        client.table('salary_grades').insert(data).execute()
        flash('Salary grade created.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    
    return redirect(url_for('hr4.salary_grades'))

@hr4_bp.route('/salary-grades/delete/<int:grade_id>', methods=['POST'])
@login_required
def delete_salary_grade(grade_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        client.table('salary_grades').delete().eq('id', grade_id).execute()
        flash('Salary grade deleted.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr4.salary_grades'))

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
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    data = []
    headers = []
    row_keys = []
    title = ""

    if report_type == 'compensation':
        title = "Annual Compensation Summary"
        try:
            res = client.table('compensation_records').select('*, users(username, department)').execute()
            raw_data = res.data
            for r in raw_data:
                data.append({
                    'employee': r.get('users', {}).get('username', 'N/A'),
                    'department': r.get('users', {}).get('department', 'N/A'),
                    'base_salary': r.get('base_salary'),
                    'allowances': r.get('allowances'),
                    'bonuses': r.get('bonuses'),
                    'effective_date': r.get('effective_date'),
                    'status': r.get('status')
                })
            headers = ['Employee', 'Department', 'Base Salary', 'Allowances', 'Bonuses', 'Effective Date', 'Status']
            row_keys = ['employee', 'department', 'base_salary', 'allowances', 'bonuses', 'effective_date', 'status']
        except Exception as e:
            print(f"Error: {e}")

    elif report_type == 'payroll':
        title = "Payroll Register Report"
        try:
            res = client.table('payroll_records').select('*, users(username)').execute()
            raw_data = res.data
            for r in raw_data:
                data.append({
                    'employee': r.get('users', {}).get('username', 'N/A'),
                    'period_start': r.get('pay_period_start'),
                    'period_end': r.get('pay_period_end'),
                    'net_pay': r.get('net_pay'),
                    'status': r.get('status'),
                    'processed_date': r.get('processed_date')
                })
            headers = ['Employee', 'Period Start', 'Period End', 'Net Pay', 'Status', 'Processed Date']
            row_keys = ['employee', 'period_start', 'period_end', 'net_pay', 'status', 'processed_date']
        except Exception as e:
            print(f"Error: {e}")

    elif report_type == 'budget':
        title = "Departmental Budget Allocation"
        try:
            res = client.table('compensation_records').select('*, users(department)').execute()
            raw_data = res.data
            
            dept_totals = {}
            for r in raw_data:
                dept = r.get('users', {}).get('department', 'Unknown')
                if dept not in dept_totals:
                    dept_totals[dept] = {'count': 0, 'total': 0.0, 'allowances': 0.0}
                
                dept_totals[dept]['count'] += 1
                dept_totals[dept]['total'] += float(r.get('base_salary') or 0)
                dept_totals[dept]['allowances'] += float(r.get('allowances') or 0)

            for dept, stats in dept_totals.items():
                data.append({
                    'department': dept,
                    'staff_count': stats['count'],
                    'base_payroll': stats['total'],
                    'total_allowances': stats['allowances'],
                    'total_budget': stats['total'] + stats['allowances'],
                    'status': 'Active'
                })
            
            headers = ['Department', 'Staff count', 'Base Payroll', 'Allowances', 'Total Budget', 'Status']
            row_keys = ['department', 'staff_count', 'base_payroll', 'total_allowances', 'total_budget', 'status']
        except Exception as e:
            print(f"Error: {e}")

    if not title:
        flash('Report type not found.', 'warning')
        return redirect(url_for('hr4.reports'))

    return render_template('subsystems/hr/hr4/report_view.html',
                           title=title,
                           data=data,
                           headers=headers,
                           row_keys=row_keys,
                           report_type=report_type,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME,
                           datetime=datetime)

@hr4_bp.route('/reports/export/<report_type>')
@login_required
def export_report(report_type):
    from utils.supabase_client import get_supabase_client
    import io
    import csv
    from flask import Response

    client = get_supabase_client()
    
    if report_type == 'compensation':
        # ...existing code...
        try:
            res = client.table('compensation_records').select('*, users(username, department)').execute()
            data = res.data
        except:
            data = []
            
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Employee', 'Department', 'Base Salary', 'Allowances', 'Bonuses', 'Effective Date', 'Status'])
        
        for r in data:
            username = r.get('users', {}).get('username', 'N/A')
            dept = r.get('users', {}).get('department', 'N/A')
            writer.writerow([
                username, dept, r.get('base_salary'), 
                r.get('allowances'), r.get('bonuses'), 
                r.get('effective_date'), r.get('status')
            ])
        
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=compensation_summary_2026.csv"}
        )

    elif report_type == 'payroll':
        # ...existing code...
        try:
            res = client.table('payroll_records').select('*, users(username)').execute()
            data = res.data
        except:
            data = []
            
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Employee', 'Period Start', 'Period End', 'Net Pay', 'Status', 'Processed Date'])
        
        for r in data:
            username = r.get('users', {}).get('username', 'N/A')
            writer.writerow([
                username, r.get('pay_period_start'), 
                r.get('pay_period_end'), r.get('net_pay'), 
                r.get('status'), r.get('processed_date')
            ])
            
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=payroll_register.csv"}
        )

    elif report_type == 'budget':
        try:
            res = client.table('compensation_records').select('*, users(department)').execute()
            raw_data = res.data
            dept_totals = {}
            for r in raw_data:
                dept = r.get('users', {}).get('department', 'Unknown')
                if dept not in dept_totals:
                    dept_totals[dept] = {'count': 0, 'total': 0.0}
                dept_totals[dept]['count'] += 1
                dept_totals[dept]['total'] += float(r.get('base_salary') or 0) + float(r.get('allowances') or 0)

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Department', 'Staff count', 'Total Budget Allocation'])
            for dept, stats in dept_totals.items():
                writer.writerow([dept, stats['count'], stats['total']])
            
            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-disposition": "attachment; filename=budget_allocation.csv"}
            )
        except:
            pass

    flash('Report generation for this type is not yet fully configured.', 'info')
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
        return redirect(url_for(f'{BLUEPRINT_NAME}.settings'))
        
    return render_template('shared/settings.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr4_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hr4.login'))

@hr4_bp.route('/analytics')
@login_required
def analytics():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Fetch all compensation records with user info
        comp_res = client.table('compensation_records').select('*, users(department)').execute()
        comp_data = comp_res.data or []
        
        # Calculate base metrics
        total_annual = sum((float(r['base_salary'] or 0) + float(r.get('allowances', 0) or 0)) * 12 for r in comp_data)
        avg_monthly = sum(float(r['base_salary'] or 0) for r in comp_data) / len(comp_data) if comp_data else 0
        total_allowances = sum(float(r.get('allowances', 0) or 0) for r in comp_data)
        total_bonuses = sum(float(r.get('bonuses', 0) or 0) for r in comp_data)
        
        # Department Distribution
        dept_map = {}
        for r in comp_data:
            dept = r.get('users', {}).get('department', 'Other')
            budget = float(r['base_salary'] or 0) + float(r.get('allowances', 0) or 0)
            dept_map[dept] = dept_map.get(dept, 0) + budget
            
        dept_dist = {
            'labels': list(dept_map.keys()),
            'data': list(dept_map.values())
        }
        
        # Salary Ranges
        ranges = {"0-50k": 0, "50k-100k": 0, "100k-150k": 0, "150k+": 0}
        for r in comp_data:
            sal = float(r['base_salary'] or 0) * 12
            if sal < 50000: ranges["0-50k"] += 1
            elif sal < 100000: ranges["50k-100k"] += 1
            elif sal < 150000: ranges["100k-150k"] += 1
            else: ranges["150k+"] += 1
            
        salary_ranges = {
            'labels': list(ranges.keys()),
            'data': list(ranges.values())
        }

        metrics = {
            'total_annual_budget': total_annual,
            'avg_salary': avg_monthly,
            'total_allowances': total_allowances,
            'total_bonuses': total_bonuses,
            'dept_distribution': dept_dist,
            'salary_ranges': salary_ranges
        }
            
    except Exception as e:
        print(f"Analytics error: {e}")
        metrics = {
            'total_annual_budget': 0, 'avg_salary': 0, 'total_allowances': 0, 'total_bonuses': 0,
            'dept_distribution': {'labels': [], 'data': []},
            'salary_ranges': {'labels': [], 'data': []}
        }

    return render_template('subsystems/hr/hr4/analytics.html',
                           metrics=metrics,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME,
                           active_page='analytics')


