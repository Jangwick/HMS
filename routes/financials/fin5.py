from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from datetime import datetime

fin5_bp = Blueprint('fin5', __name__, template_folder='templates')

# Subsystem configuration
SUBSYSTEM_NAME = 'FIN5 - Financial Reports'
ACCENT_COLOR = '[#6D28D9]'
BLUEPRINT_NAME = 'fin5'

@fin5_bp.route('/login', methods=['GET', 'POST'])
def login():
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/financials/fin5/login.html', remaining_seconds=remaining_seconds)
    
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
                    return redirect(url_for('fin5.change_password'))
                register_successful_login()
                user.register_successful_login()
                login_user(user)
                days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                if days_left <= 7:
                    flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                return redirect(url_for('fin5.dashboard'))
            else:
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/financials/fin5/login.html', remaining_seconds=remaining_seconds)
                else:
                    flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
        else:
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
            if is_now_locked:
                flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                return render_template('subsystems/financials/fin5/login.html', remaining_seconds=remaining_seconds)
            else:
                flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
    return render_template('subsystems/financials/fin5/login.html')

@fin5_bp.route('/register', methods=['GET', 'POST'])
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
                return redirect(url_for('fin5.login'))
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

@fin5_bp.route('/change-password', methods=['GET', 'POST'])
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
            return redirect(url_for('fin5.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('fin5.login'))
    
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
            return redirect(url_for('fin5.login'))
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html', subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@fin5_bp.route('/dashboard')
@login_required
def dashboard():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Get reports count
        response = client.table('generated_reports').select('id', count='exact').execute()
        reports_generated = response.count if response.count is not None else 0
        
        pending_reports = 0 # Placeholder
        
    except Exception as e:
        print(f"Error fetching stats: {e}")
        reports_generated = 0
        pending_reports = 0
    
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    return render_template('subsystems/financials/fin5/dashboard.html', 
                           now=datetime.utcnow,
                           reports_generated=reports_generated,
                           pending_reports=pending_reports,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@fin5_bp.route('/reports')
@login_required
def reports_list():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        response = client.table('generated_reports').select('*').order('generated_at', desc=True).execute()
        reports = response.data if response.data else []
    except Exception as e:
        print(f"Error fetching reports: {e}")
        reports = []
        
    return render_template('subsystems/financials/fin5/reports.html',
                           reports=reports,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@fin5_bp.route('/reports/income-statement')
@login_required
def income_statement():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Simplified Cash Basis Income Statement
        # Revenue = Total Collections (Inflows)
        # Expenses = Total Payments (Outflows)
        
        # Get Revenue (Collections)
        col_resp = client.table('collections').select('amount').execute()
        revenue = sum([r['amount'] for r in col_resp.data]) if col_resp.data else 0.0
        
        # Get Expenses (Vendor Payments + Payroll)
        pay_resp = client.table('vendor_payments').select('amount').execute()
        vendor_payments = sum([r['amount'] for r in pay_resp.data]) if pay_resp.data else 0.0
        
        # Payroll (Net Pay)
        payroll_resp = client.table('payroll_records').select('net_pay').eq('status', 'Paid').execute()
        payroll_expenses = sum([r['net_pay'] for r in payroll_resp.data]) if payroll_resp.data else 0.0
        
        total_expenses = vendor_payments + payroll_expenses
        net_income = revenue - total_expenses
        
        data = {
            'revenue': revenue,
            'expenses': {
                'vendor_payments': vendor_payments,
                'payroll': payroll_expenses
            },
            'total_expenses': total_expenses,
            'net_income': net_income
        }
        
    except Exception as e:
        print(f"Error generating income statement: {e}")
        data = {'revenue': 0, 'expenses': {}, 'total_expenses': 0, 'net_income': 0}
    
    return render_template('subsystems/financials/fin5/income_statement.html',
                           data=data,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@fin5_bp.route('/reports/balance-sheet')
@login_required
def balance_sheet():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Simplified Balance Sheet
        # Assets = Cash + Receivables
        # Liabilities = Payables
        # Equity = Assets - Liabilities
        
        # Cash
        cash_resp = client.table('bank_accounts').select('current_balance').execute()
        cash = sum([r['current_balance'] for r in cash_resp.data]) if cash_resp.data else 0.0
        
        # Receivables
        rec_resp = client.table('receivables').select('amount_due').eq('status', 'Open').execute()
        receivables = sum([r['amount_due'] for r in rec_resp.data]) if rec_resp.data else 0.0
        
        total_assets = cash + receivables
        
        # Payables
        pay_resp = client.table('vendor_invoices').select('amount').eq('status', 'Unpaid').execute()
        payables = sum([r['amount'] for r in pay_resp.data]) if pay_resp.data else 0.0
        
        total_liabilities = payables
        
        equity = total_assets - total_liabilities
        
        data = {
            'assets': {
                'cash': cash,
                'receivables': receivables
            },
            'total_assets': total_assets,
            'liabilities': {
                'payables': payables
            },
            'total_liabilities': total_liabilities,
            'equity': equity
        }
        
    except Exception as e:
        print(f"Error generating balance sheet: {e}")
        data = {'assets': {}, 'total_assets': 0, 'liabilities': {}, 'total_liabilities': 0, 'equity': 0}
        
    return render_template('subsystems/financials/fin5/balance_sheet.html',
                           data=data,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@fin5_bp.route('/settings', methods=['GET', 'POST'])
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

@fin5_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('fin5.login'))

