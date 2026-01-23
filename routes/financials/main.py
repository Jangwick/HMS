from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, get_supabase_client
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from datetime import datetime, timedelta

financials_bp = Blueprint('financials', __name__, template_folder='templates')

# Configuration
SUBSYSTEM_NAME = 'Financial Management System'
ACCENT_COLOR = '#8B5CF6'
BLUEPRINT_NAME = 'financials'

@financials_bp.route('/login', methods=['GET', 'POST'])
def login():
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/financials/login.html', remaining_seconds=remaining_seconds)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Try to find user in any financial subsystem for backward compatibility
        user = User.get_by_username(username)
        if user and (user.subsystem == BLUEPRINT_NAME or user.subsystem.startswith('fin')):
            now_utc = datetime.utcnow()
            
            if user.check_password(password):
                if user.password_expires_at and user.password_expires_at < now_utc:
                    session['expired_user_id'] = user.id
                    session['expired_subsystem'] = BLUEPRINT_NAME
                    flash('Your password has expired. Please set a new password to continue.', 'warning')
                    return redirect(url_for('financials.change_password'))

                if user.status != 'Active':
                    if user.status == 'Pending':
                        flash('Your account is awaiting approval from HR3 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('subsystems/financials/login.html')

                register_successful_login()
                user.register_successful_login()
                
                if login_user(user):
                    days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                    if days_left <= 7:
                        flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    return redirect(url_for('financials.dashboard'))
                else:
                    flash('Login failed. Your account may be deactivated.', 'danger')
            else:
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                else:
                    flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
        else:
            flash('Invalid credentials or account not in Financials department.', 'danger')
            register_failed_attempt()
            
    return render_template('subsystems/financials/login.html')

@financials_bp.route('/register', methods=['GET', 'POST'])
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
                department='FINANCIALS',
                status='Pending'
            )
            
            if new_user:
                flash('Registration successful! Your account is awaiting approval from HR3 Admin.', 'success')
                return redirect(url_for('financials.login'))
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

@financials_bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    expired_user_id = session.get('expired_user_id')
    expired_subsystem = session.get('expired_subsystem')
    is_expired = expired_user_id is not None and expired_subsystem == BLUEPRINT_NAME
    
    if is_expired:
        user = User.get_by_id(expired_user_id)
        if not user:
            session.pop('expired_user_id', None)
            session.pop('expired_subsystem', None)
            return redirect(url_for('financials.login'))
    elif current_user.is_authenticated:
        user = current_user
    else:
        return redirect(url_for('financials.login'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
        else:
            try:
                user.set_password(new_password)
                session.pop('expired_user_id', None)
                session.pop('expired_subsystem', None)
                flash('Password updated successfully! Please login with your new password.', 'success')
                if current_user.is_authenticated:
                    logout_user()
                return redirect(url_for('financials.login'))
            except PasswordValidationError as e:
                for error in e.errors: flash(error, 'danger')
            except Exception:
                flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html', subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@financials_bp.route('/dashboard')
@login_required
def dashboard():
    client = get_supabase_client()
    
    # Combined stats from all modules
    stats = {}
    try:
        # FIN1 Stats
        total_billing = client.table('billing_records').select('total_amount').execute()
        stats['revenue'] = sum([r['total_amount'] for r in total_billing.data]) if total_billing.data else 0
        
        # FIN2 Stats
        response = client.table('vendor_invoices').select('amount').eq('status', 'Unpaid').execute()
        stats['payables'] = sum([r['amount'] for r in response.data]) if response.data else 0
        
        # FIN3 Stats
        stats['receivables'] = client.table('receivables').select('id', count='exact').eq('status', 'Unpaid').execute().count or 0
        
        # FIN4 Stats
        bank_resp = client.table('bank_accounts').select('balance').execute()
        stats['cash_on_hand'] = sum([r['balance'] for r in bank_resp.data]) if bank_resp.data else 0
        
    except Exception as e:
        print(f"Error fetching stats: {e}")

    return render_template('subsystems/financials/dashboard.html', 
                           stats=stats,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

# --- FIN1 MODULE: BILLING ---
@financials_bp.route('/billing')
@login_required
def list_billing():
    client = get_supabase_client()
    response = client.table('billing_records').select('*, patients(*)').execute()
    records = response.data if response.data else []
    return render_template('subsystems/financials/fin1/billing.html',
                           records=records, 
                           subsystem_name="Billing Management", 
                           accent_color="#8B5CF6", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/billing/create', methods=['GET', 'POST'])
@login_required
def create_bill():
    if request.method == 'POST':
        client = get_supabase_client()
        data = {
            'patient_id': request.form.get('patient_id'),
            'total_amount': float(request.form.get('amount')),
            'status': 'Unpaid',
            'billing_date': datetime.now().isoformat()
        }
        client.table('billing_records').insert(data).execute()
        flash('Invoice created successfully!', 'success')
        return redirect(url_for('financials.list_billing'))
    
    from utils.hms_models import Patient
    patients = Patient.get_all()
    return render_template('subsystems/financials/fin1/create_bill.html', 
                           patients=patients, 
                           subsystem_name="Billing Management", 
                           accent_color="#8B5CF6", 
                           blueprint_name=BLUEPRINT_NAME)

# --- FIN2 MODULE: ACCOUNTS PAYABLE ---
@financials_bp.route('/payables')
@login_required
def vendor_invoices():
    client = get_supabase_client()
    try:
        response = client.table('vendor_invoices').select('*, vendors(name)').order('due_date').execute()
        invoices = response.data if response.data else []
        for inv in invoices:
            inv['vendor_name'] = inv.get('vendors', {}).get('name', 'Unknown')
    except Exception as e:
        print(f"Error: {e}")
        invoices = []
    return render_template('subsystems/financials/fin2/invoices.html', 
                           invoices=invoices, 
                           subsystem_name="Accounts Payable", 
                           accent_color="#A855F7", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/payables/add', methods=['GET', 'POST'])
@login_required
def add_invoice():
    client = get_supabase_client()
    if request.method == 'POST':
        try:
            data = {
                'vendor_id': int(request.form.get('vendor_id')),
                'invoice_number': request.form.get('invoice_number'),
                'invoice_date': request.form.get('invoice_date'),
                'due_date': request.form.get('due_date'),
                'amount': float(request.form.get('amount')),
                'status': 'Unpaid',
                'description': request.form.get('description')
            }
            client.table('vendor_invoices').insert(data).execute()
            flash('Invoice recorded successfully!', 'success')
            return redirect(url_for('financials.vendor_invoices'))
        except Exception as e:
            flash(f'Error adding invoice: {str(e)}', 'danger')
    
    vendors = client.table('vendors').select('id, name').eq('status', 'Active').order('name').execute().data or []
    return render_template('subsystems/financials/fin2/add_invoice.html', 
                           vendors=vendors, 
                           subsystem_name="Accounts Payable", 
                           accent_color="#A855F7", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/payables/payments')
@login_required
def payments():
    client = get_supabase_client()
    payments = client.table('vendor_payments').select('*, vendor_invoices(*, vendors(name))').order('payment_date', desc=True).execute().data or []
    for pay in payments:
        pay['vendor_name'] = pay.get('vendor_invoices', {}).get('vendors', {}).get('name', 'Unknown')
    return render_template('subsystems/financials/fin2/payments.html', 
                           payments=payments, 
                           subsystem_name="Accounts Payable", 
                           accent_color="#A855F7", 
                           blueprint_name=BLUEPRINT_NAME)

# --- FIN3 MODULE: ACCOUNTS RECEIVABLE ---
@financials_bp.route('/receivables')
@login_required
def receivables_list():
    client = get_supabase_client()
    receivables = client.table('receivables').select('*, billing_records(patients(first_name, last_name))').order('due_date').execute().data or []
    for rec in receivables:
        patient = rec.get('billing_records', {}).get('patients', {})
        rec['patient_name'] = f"{patient.get('first_name', '')} {patient.get('last_name', '')}".strip() or 'Unknown'
    return render_template('subsystems/financials/fin3/receivables.html', 
                           receivables=receivables, 
                           subsystem_name="Accounts Receivable", 
                           accent_color="#9333EA", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/receivables/collections')
@login_required
def collections():
    client = get_supabase_client()
    collections = client.table('collections').select('*').order('collection_date', desc=True).execute().data or []
    return render_template('subsystems/financials/fin3/collections.html', 
                           collections=collections, 
                           subsystem_name="Accounts Receivable", 
                           accent_color="#9333EA", 
                           blueprint_name=BLUEPRINT_NAME)

# --- FIN4 MODULE: CASH MANAGEMENT ---
@financials_bp.route('/cash')
@login_required
def transactions():
    client = get_supabase_client()
    transactions = client.table('cash_transactions').select('*, bank_accounts(bank_name, account_number)').order('transaction_date', desc=True).execute().data or []
    return render_template('subsystems/financials/fin4/transactions.html', 
                           transactions=transactions, 
                           subsystem_name="Cash Management", 
                           accent_color="#7C3AED", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/cash/accounts')
@login_required
def bank_accounts():
    client = get_supabase_client()
    accounts = client.table('bank_accounts').select('*').execute().data or []
    return render_template('subsystems/financials/fin4/bank_accounts.html', 
                           accounts=accounts, 
                           subsystem_name="Cash Management", 
                           accent_color="#7C3AED", 
                           blueprint_name=BLUEPRINT_NAME)

# --- FIN5 MODULE: FINANCIAL REPORTS ---
@financials_bp.route('/reports')
@login_required
def reports_list():
    client = get_supabase_client()
    reports = client.table('generated_reports').select('*').order('timestamp', desc=True).execute().data or []
    return render_template('subsystems/financials/fin5/reports.html', 
                           reports=reports, 
                           subsystem_name="Financial Intel", 
                           accent_color="#6D28D9", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/reports/income-statement')
@login_required
def income_statement():
    client = get_supabase_client()
    revenue = sum([r['amount'] for r in client.table('collections').select('amount').execute().data or []])
    expenses = sum([r['amount'] for r in client.table('vendor_payments').select('amount').execute().data or []])
    payroll = sum([r['gross_salary'] for r in client.table('payroll_records').select('gross_salary').eq('status', 'Paid').execute().data or []])
    total_expenses = expenses + payroll
    net_income = revenue - total_expenses
    return render_template('subsystems/financials/fin5/income_statement.html', 
                           revenue=revenue, expenses=expenses, payroll=payroll, 
                           total_expenses=total_expenses, net_income=net_income,
                           subsystem_name="Financial Intel", accent_color="#6D28D9", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/reports/balance-sheet')
@login_required
def balance_sheet():
    client = get_supabase_client()
    cash = sum([r['balance'] for r in client.table('bank_accounts').select('balance').execute().data or []])
    receivables = sum([r['amount_due'] for r in client.table('receivables').select('amount_due').eq('status', 'Open').execute().data or []])
    payables = sum([r['amount'] for r in client.table('vendor_invoices').select('amount').eq('status', 'Unpaid').execute().data or []])
    assets = cash + receivables
    liabilities = payables
    equity = assets - liabilities
    return render_template('subsystems/financials/fin5/balance_sheet.html', 
                           cash=cash, receivables=receivables, payables=payables,
                           assets=assets, liabilities=liabilities, equity=equity,
                           subsystem_name="Financial Intel", accent_color="#6D28D9", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/settings', methods=['GET', 'POST'])
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
        return redirect(url_for('financials.settings'))
    return render_template('shared/settings.html', subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('financials.login'))
