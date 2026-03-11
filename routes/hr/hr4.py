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
    locked, remaining_seconds, unlock_time_str = is_ip_locked(subsystem=BLUEPRINT_NAME)
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
                        flash('Your account is awaiting approval from HR2 Admin.', 'info')
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
                register_successful_login(subsystem=BLUEPRINT_NAME)
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
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt(subsystem=BLUEPRINT_NAME)
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/hr/hr4/login.html', remaining_seconds=remaining_seconds)
                else:
                    flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
        else:
            try:
                matching_subs = User.find_subsystems_by_username(username)
                if matching_subs:
                    subs_display = ', '.join(s.upper() for s in matching_subs)
                    flash(f'Account found in {subs_display} portal(s). Please log in through the correct portal.', 'warning')
                else:
                    flash('Invalid credentials.', 'danger')
            except:
                flash('Invalid credentials.', 'danger')
                
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt(subsystem=BLUEPRINT_NAME)
            if is_now_locked:
                return render_template('subsystems/hr/hr4/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/hr/hr4/login.html')

@hr4_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Successfully logged out.', 'success')
    return redirect(url_for('hr4.login'))


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

        # Benefits summary
        benefits_res = client.table('employee_benefits').select('id, status').execute()
        benefits_data = benefits_res.data or []
        active_benefits = sum(1 for b in benefits_data if b.get('status') == 'Active')

        claims_res = client.table('benefit_claims').select('id, status').eq('status', 'Pending').execute()
        pending_claims = len(claims_res.data or [])
    except Exception as e:
        print(f"Error fetching HR4 stats: {e}")
        avg_salary = 0
        total_payroll = 0
        total_grades = 0
        payroll_processed = False
        recent_updates = []
        active_benefits = 0
        pending_claims = 0

    return render_template('subsystems/hr/hr4/dashboard.html',
                           now=datetime.utcnow,
                           avg_salary=avg_salary,
                           total_payroll=total_payroll,
                           total_grades=total_grades,
                           payroll_processed=payroll_processed,
                           recent_updates=recent_updates,
                           active_benefits=active_benefits,
                           pending_claims=pending_claims,
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
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr4.compensation'))
        
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
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr4.compensation'))
        
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
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr4.compensation'))
        
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
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr4.salary_grades'))
        
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
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr4.salary_grades'))
        
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
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr4.salary_grades'))
        
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

        # Pending reimbursements queued for payroll
        reimb_res = client.table('reimbursement_claims') \
            .select('id, user_id, claim_type, amount, users(username)') \
            .eq('payment_method', 'Payroll').eq('payroll_included', False) \
            .eq('workflow_step', 'Completed').execute()
        pending_reimbursements = reimb_res.data or []
        
    except Exception as e:
        print(f"Error fetching payroll: {e}")
        payroll_history = []
        is_processed = False
        pending_reimbursements = []
        
    return render_template('subsystems/hr/hr4/payroll.html',
                           payroll_history=payroll_history,
                           is_processed=is_processed,
                           pending_reimbursements=pending_reimbursements,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr4_bp.route('/payroll/process', methods=['POST'])
@login_required
def process_payroll():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr4.payroll'))
        
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
            # Base net pay from compensation record
            reimbursement_bonus = 0.0
            # Add approved payroll reimbursements for this employee
            try:
                reimb_res = client.table('reimbursement_claims') \
                    .select('id, amount') \
                    .eq('user_id', rec['user_id']) \
                    .eq('payment_method', 'Payroll') \
                    .eq('payroll_included', False) \
                    .eq('workflow_step', 'Completed').execute()
                pending_reimbs = reimb_res.data or []
                reimbursement_bonus = sum(float(r['amount']) for r in pending_reimbs)
                # Mark them as included
                for r in pending_reimbs:
                    client.table('reimbursement_claims').update({'payroll_included': True}).eq('id', r['id']).execute()
            except Exception:
                pass

            net_pay = float(rec['base_salary']) + float(rec['allowances']) + float(rec['bonuses']) + reimbursement_bonus - float(rec['deductions'])
            
            payroll_data = {
                'user_id': rec['user_id'],
                'pay_period_start': pay_period_start,
                'pay_period_end': pay_period_end,
                'base_salary': rec['base_salary'],
                'bonuses': float(rec['bonuses']) + reimbursement_bonus,
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
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr4.dashboard'))
        
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

        # 5. Compliance / Statutory Contributions (Philippine law)
        def compute_sss(monthly_salary):
            """SSS contribution table — simplified tiered brackets (employee share)."""
            if monthly_salary < 4250: return 180.0
            elif monthly_salary < 4750: return 202.5
            elif monthly_salary < 5250: return 225.0
            elif monthly_salary < 5750: return 247.5
            elif monthly_salary < 6250: return 270.0
            elif monthly_salary < 6750: return 292.5
            elif monthly_salary < 7250: return 315.0
            elif monthly_salary < 7750: return 337.5
            elif monthly_salary < 8250: return 360.0
            elif monthly_salary < 8750: return 382.5
            elif monthly_salary < 9250: return 405.0
            elif monthly_salary < 9750: return 427.5
            elif monthly_salary < 10250: return 450.0
            elif monthly_salary < 10750: return 472.5
            elif monthly_salary < 11250: return 495.0
            elif monthly_salary < 11750: return 517.5
            elif monthly_salary < 12250: return 540.0
            elif monthly_salary < 12750: return 562.5
            elif monthly_salary < 13250: return 585.0
            elif monthly_salary < 13750: return 607.5
            elif monthly_salary < 14250: return 630.0
            elif monthly_salary < 14750: return 652.5
            elif monthly_salary < 15250: return 675.0
            elif monthly_salary < 15750: return 697.5
            elif monthly_salary < 16250: return 720.0
            elif monthly_salary < 16750: return 742.5
            elif monthly_salary < 17250: return 765.0
            elif monthly_salary < 17750: return 787.5
            elif monthly_salary < 18250: return 810.0
            elif monthly_salary < 18750: return 832.5
            elif monthly_salary < 19250: return 855.0
            elif monthly_salary < 19750: return 877.5
            elif monthly_salary < 20250: return 900.0
            else: return min(monthly_salary * 0.045, 1350.0)

        def compute_philhealth(monthly_salary):
            """PhilHealth: 5% total, 2.5% employee share, capped at ₱2,500."""
            return min(monthly_salary * 0.025, 2500.0)

        def compute_pagibig(monthly_salary):
            """Pag-IBIG: 2% employee share of salary credit up to ₱5,000, max ₱100."""
            return min(monthly_salary * 0.02, 100.0)

        def compute_bir(monthly_salary):
            """BIR withholding tax — TRAIN law monthly brackets."""
            annual = monthly_salary * 12
            if annual <= 250000: return 0.0
            elif annual <= 400000: return ((annual - 250000) * 0.15) / 12
            elif annual <= 800000: return ((22500 + (annual - 400000) * 0.20)) / 12
            elif annual <= 2000000: return ((102500 + (annual - 800000) * 0.25)) / 12
            elif annual <= 8000000: return ((402500 + (annual - 2000000) * 0.30)) / 12
            else: return ((2202500 + (annual - 8000000) * 0.35)) / 12

        compliance_by_employee = []
        total_sss = total_philhealth = total_pagibig = total_bir = 0.0
        for r in records:
            base = float(r.get('base_salary') or 0)
            sss = round(compute_sss(base), 2)
            ph = round(compute_philhealth(base), 2)
            pi = round(compute_pagibig(base), 2)
            bir = round(compute_bir(base), 2)
            total_sss += sss; total_philhealth += ph
            total_pagibig += pi; total_bir += bir
            compliance_by_employee.append({
                'name': r.get('users', {}).get('username', 'Unknown'),
                'department': r.get('users', {}).get('department', 'N/A'),
                'base_salary': base,
                'sss': sss,
                'philhealth': ph,
                'pagibig': pi,
                'bir': bir,
                'total_contributions': sss + ph + pi + bir
            })

        compliance_totals = {
            'sss': round(total_sss, 2),
            'philhealth': round(total_philhealth, 2),
            'pagibig': round(total_pagibig, 2),
            'bir': round(total_bir, 2),
            'grand_total': round(total_sss + total_philhealth + total_pagibig + total_bir, 2)
        }

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
            'top_earners': top_earners,
            'compliance_totals': compliance_totals,
            'compliance_by_employee': compliance_by_employee
        }
    except Exception as e:
        print(f"Error calculating analytics: {e}")
        metrics = {'total_annual_budget': 0, 'avg_salary': 0, 'total_allowances': 0, 'total_bonuses': 0, 'count': 0, 'dept_distribution': {'labels': [], 'data': []}, 'salary_ranges': {'labels': [], 'data': []}, 'structure': {'labels': [], 'data': []}, 'top_earners': [], 'compliance_totals': {'sss': 0, 'philhealth': 0, 'pagibig': 0, 'bir': 0, 'grand_total': 0}, 'compliance_by_employee': []}

    return render_template('subsystems/hr/hr4/analytics.html',
                           metrics=metrics,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME,
                           datetime=datetime)

@hr4_bp.route('/reports')
@login_required
def reports():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr4.dashboard'))
        
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
    
    from utils.hms_models import AuditLog
    AuditLog.log(current_user.id, "Export HR Report", BLUEPRINT_NAME, {"report_type": report_type, "format": export_format})
    
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

@hr4_bp.route('/reimbursements', methods=['GET'])
@login_required
def reimbursements():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    filter_step = request.args.get('step', 'all')
    show_archived = filter_step in ('Completed', 'Rejected')

    try:
        query = client.table('reimbursement_claims').select(
            '*, users:users!reimbursement_claims_user_id_fkey(username, full_name)'
        )
        if filter_step != 'all':
            query = query.eq('workflow_step', filter_step)
        if show_archived:
            query = query.eq('is_archived', True)
        else:
            query = query.eq('is_archived', False)
        resp = query.order('created_at', desc=True).execute()
        claims = resp.data or []
    except Exception as e:
        print(f"HR4 reimbursements fetch error: {e}")
        claims = []

    # Build counts across all steps
    try:
        all_resp = client.table('reimbursement_claims').select('workflow_step').execute()
        counts = {}
        for row in (all_resp.data or []):
            s = row.get('workflow_step', '')
            counts[s] = counts.get(s, 0) + 1
    except Exception:
        counts = {}

    return render_template('subsystems/hr/hr4/reimbursements.html',
                           claims=claims,
                           counts=counts,
                           filter_step=filter_step,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr4_bp.route('/reimbursements/<int:claim_id>/decide', methods=['POST'])
@login_required
def decide_reimbursement(claim_id):
    if not current_user.is_super_admin() and \
       not (current_user.is_admin() and current_user.subsystem == 'hr4'):
        flash('Unauthorized.', 'danger')
        return redirect(url_for('hr4.reimbursements'))

    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()

    decision = request.form.get('decision')
    notes = request.form.get('notes', '').strip()

    if decision not in ('Approve', 'Reject'):
        flash('Invalid decision.', 'danger')
        return redirect(url_for('hr4.reimbursements'))

    try:
        resp = client.table('reimbursement_claims').select('*').eq('id', claim_id).limit(1).execute()
        if not resp.data:
            flash('Claim not found.', 'danger')
            return redirect(url_for('hr4.reimbursements'))

        claim = resp.data[0]
        now_iso = datetime.now().isoformat()

        if claim.get('workflow_step') != 'HR Review':
            flash('This claim is not at the HR Review stage.', 'warning')
            return redirect(url_for('hr4.reimbursements'))

        if decision == 'Approve':
            client.table('reimbursement_claims').update({
                'workflow_step': 'Finance Review',
                'status': 'HR Approved',
                'hr_approved_by': current_user.id,
                'hr_approved_at': now_iso,
                'hr_notes': notes
            }).eq('id', claim_id).execute()

            # Notify Finance admins
            try:
                fin_admins = client.table('users').select('id').eq('subsystem', 'financials').in_('role', ['Admin', 'Administrator']).eq('status', 'Active').execute()
                for a in (fin_admins.data or []):
                    Notification.create(user_id=a['id'],
                        title='Reimbursement Claim — Finance Review Needed',
                        message=f"A ₱{float(claim['amount']):,.2f} {claim['claim_type']} claim is awaiting Finance approval.",
                        n_type='info', sender_subsystem=BLUEPRINT_NAME,
                        target_url=url_for('financials.list_reimbursements'))
            except Exception:
                pass

            flash('Claim forwarded to Finance for approval.', 'success')
        else:
            client.table('reimbursement_claims').update({
                'workflow_step': 'Rejected',
                'status': 'Rejected',
                'hr_approved_by': current_user.id,
                'hr_approved_at': now_iso,
                'hr_notes': notes,
                'is_archived': True,
                'archived_at': now_iso
            }).eq('id', claim_id).execute()

            Notification.create(user_id=claim['user_id'],
                title='Reimbursement Claim Rejected',
                message=f"Your {claim['claim_type']} claim of ₱{float(claim['amount']):,.2f} was rejected by HR." +
                        (f" Reason: {notes}" if notes else ""),
                n_type='danger', sender_subsystem=BLUEPRINT_NAME)
            flash('Claim rejected.', 'info')

    except Exception as e:
        flash(f'Error processing decision: {str(e)}', 'danger')

    return redirect(url_for('hr4.reimbursements'))


# ─────────────────────────────────────────────
#  BENEFITS & HMO ADMINISTRATION
# ─────────────────────────────────────────────

@hr4_bp.route('/benefits')
@login_required
def benefits():
    if not current_user.is_staff():
        flash('Unauthorized.', 'danger')
        return redirect(url_for('hr4.dashboard'))

    client = get_supabase_client()

    # --- Users query is independent so it always loads even if benefits tables are missing ---
    try:
        users_res = client.table('users').select(
            'id, username, full_name, department, role, status, is_active'
        ).order('username').execute()
        all_users = users_res.data or []
        active_users = [
            u for u in all_users
            if (u.get('status') == 'Active' or u.get('is_active') is True)
            and u.get('role') not in ('Applicant', 'Patient', None)
            and u.get('department') not in ('PATIENT_PORTAL',)
        ]
    except Exception as e:
        import traceback
        print(f"Error loading users for benefits dropdown: {e}")
        traceback.print_exc()
        active_users = []

    # --- Benefits & claims tables (may not exist yet) ---
    try:
        benefits_res = client.table('employee_benefits').select('*').order('created_at', desc=True).execute()
        benefit_records = benefits_res.data or []

        claims_res = client.table('benefit_claims').select('*').order('submitted_at', desc=True).execute()
        claim_records = claims_res.data or []

        # Enrich with user info using the already-fetched all_users list
        users_map = {u['id']: u for u in all_users} if all_users else {}
        for b in benefit_records:
            uid = b.get('user_id')
            gid = b.get('granted_by')
            b['users'] = users_map.get(uid, {})
            b['granter'] = users_map.get(gid, {})
        for c in claim_records:
            uid = c.get('user_id')
            rid = c.get('reviewed_by')
            bid = c.get('benefit_id')
            c['users'] = users_map.get(uid, {})
            c['reviewer'] = users_map.get(rid, {})
            c['benefit'] = next((b for b in benefit_records if b.get('id') == bid), {})
    except Exception as e:
        import traceback
        print(f"Error loading benefits/claims (tables may not exist yet): {e}")
        traceback.print_exc()
        benefit_records = []
        claim_records = []

    # --- Compute stats from loaded data ---
    try:
        # Benefit status breakdown
        status_counts = {}
        for b in benefit_records:
            s = b.get('status', 'Unknown')
            status_counts[s] = status_counts.get(s, 0) + 1

        # Benefit type breakdown with coverage totals
        type_breakdown = {}
        for b in benefit_records:
            if b.get('status') != 'Active':
                continue
            bt = b.get('benefit_type', 'Other')
            if bt not in type_breakdown:
                type_breakdown[bt] = {'count': 0, 'total_coverage': 0.0}
            type_breakdown[bt]['count'] += 1
            type_breakdown[bt]['total_coverage'] += float(b.get('coverage_amount') or 0)

        # HMO-specific stats
        hmo_records = [b for b in benefit_records if b.get('benefit_type') in ('HMO', 'Health Card')]
        active_hmo = [b for b in hmo_records if b.get('status') == 'Active']
        hmo_providers = {}
        for b in active_hmo:
            p = b.get('provider') or 'Unknown'
            hmo_providers[p] = hmo_providers.get(p, 0) + 1

        total_coverage = sum(float(b.get('coverage_amount') or 0) for b in benefit_records if b.get('status') == 'Active')
        pending_claims = sum(1 for c in claim_records if c.get('status') == 'Pending')

        hmo_stats = {
            'enrollee_count': len(active_hmo),
            'avg_coverage': (sum(float(b.get('coverage_amount') or 0) for b in active_hmo) / len(active_hmo)) if active_hmo else 0,
            'total_coverage': sum(float(b.get('coverage_amount') or 0) for b in active_hmo),
            'providers': hmo_providers
        }
    except Exception as e:
        print(f"Error computing benefit stats: {e}")
        status_counts = {}
        type_breakdown = {}
        total_coverage = 0
        pending_claims = 0
        hmo_stats = {'enrollee_count': 0, 'avg_coverage': 0, 'total_coverage': 0, 'providers': {}}

    return render_template('subsystems/hr/hr4/benefits.html',
                           benefit_records=benefit_records,
                           claim_records=claim_records,
                           active_users=active_users,
                           status_counts=status_counts,
                           type_breakdown=type_breakdown,
                           total_coverage=total_coverage,
                           pending_claims=pending_claims,
                           hmo_stats=hmo_stats,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr4_bp.route('/benefits/assign', methods=['POST'])
@login_required
def assign_benefit():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr4.benefits'))

    client = get_supabase_client()
    try:
        user_id = int(request.form.get('user_id'))
        benefit_type = request.form.get('benefit_type', '').strip()
        provider = request.form.get('provider', '').strip()
        coverage_amount = float(request.form.get('coverage_amount') or 0)
        start_date = request.form.get('start_date') or datetime.utcnow().strftime('%Y-%m-%d')
        end_date = request.form.get('end_date') or None
        notes = request.form.get('notes', '').strip()

        payload = {
            'user_id': user_id,
            'benefit_type': benefit_type,
            'provider': provider or None,
            'coverage_amount': coverage_amount,
            'start_date': start_date,
            'status': 'Active',
            'notes': notes or None,
            'granted_by': current_user.id
        }
        if end_date:
            payload['end_date'] = end_date
        client.table('employee_benefits').insert(payload).execute()
        flash('Benefit assigned successfully.', 'success')
    except Exception as e:
        flash(f'Error assigning benefit: {str(e)}', 'danger')

    return redirect(url_for('hr4.benefits'))


@hr4_bp.route('/benefits/<int:benefit_id>/edit', methods=['POST'])
@login_required
def edit_benefit(benefit_id):
    if not current_user.is_admin():
        flash('Unauthorized.', 'danger')
        return redirect(url_for('hr4.benefits'))

    client = get_supabase_client()
    try:
        end_date_val = request.form.get('end_date') or None
        updates = {
            'benefit_type': request.form.get('benefit_type', '').strip(),
            'provider': request.form.get('provider', '').strip() or None,
            'coverage_amount': float(request.form.get('coverage_amount') or 0),
            'start_date': request.form.get('start_date'),
            'status': request.form.get('status', 'Active'),
            'notes': request.form.get('notes', '').strip() or None,
            'updated_at': datetime.utcnow().isoformat()
        }
        if end_date_val:
            updates['end_date'] = end_date_val
        client.table('employee_benefits').update(updates).eq('id', benefit_id).execute()
        flash('Benefit updated.', 'success')
    except Exception as e:
        flash(f'Error updating benefit: {str(e)}', 'danger')

    return redirect(url_for('hr4.benefits'))


@hr4_bp.route('/benefits/<int:benefit_id>/delete', methods=['POST'])
@login_required
def delete_benefit(benefit_id):
    if not current_user.is_admin():
        flash('Unauthorized.', 'danger')
        return redirect(url_for('hr4.benefits'))

    client = get_supabase_client()
    try:
        client.table('employee_benefits').delete().eq('id', benefit_id).execute()
        flash('Benefit record deleted.', 'info')
    except Exception as e:
        flash(f'Error deleting benefit: {str(e)}', 'danger')

    return redirect(url_for('hr4.benefits'))


@hr4_bp.route('/benefits/claims/submit', methods=['POST'])
@login_required
def submit_benefit_claim():
    client = get_supabase_client()
    try:
        benefit_id = request.form.get('benefit_id')
        claim_type = request.form.get('claim_type', '').strip()
        amount = float(request.form.get('amount') or 0)
        description = request.form.get('description', '').strip()

        client.table('benefit_claims').insert({
            'user_id': current_user.id,
            'benefit_id': int(benefit_id) if benefit_id else None,
            'claim_type': claim_type,
            'amount': amount,
            'description': description,
            'status': 'Pending',
            'submitted_at': datetime.utcnow().isoformat()
        }).execute()
        flash('Benefit claim submitted successfully.', 'success')
    except Exception as e:
        flash(f'Error submitting claim: {str(e)}', 'danger')

    return redirect(url_for('hr4.benefits'))


@hr4_bp.route('/benefits/claims/<int:claim_id>/decide', methods=['POST'])
@login_required
def decide_benefit_claim(claim_id):
    if not current_user.is_admin():
        flash('Unauthorized.', 'danger')
        return redirect(url_for('hr4.benefits'))

    client = get_supabase_client()
    decision = request.form.get('decision')
    notes = request.form.get('notes', '').strip()

    if decision not in ('Approve', 'Reject'):
        flash('Invalid decision.', 'danger')
        return redirect(url_for('hr4.benefits'))

    try:
        status = 'Approved' if decision == 'Approve' else 'Rejected'
        client.table('benefit_claims').update({
            'status': status,
            'reviewed_by': current_user.id,
            'reviewed_at': datetime.utcnow().isoformat(),
            'review_notes': notes
        }).eq('id', claim_id).execute()
        flash(f'Claim {status.lower()}.', 'success' if status == 'Approved' else 'info')
    except Exception as e:
        flash(f'Error processing claim: {str(e)}', 'danger')

    return redirect(url_for('hr4.benefits'))


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



