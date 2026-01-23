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
        
        # Try to find user in the unified financial subsystem
        user = User.get_by_username(username)
        if user and user.subsystem == BLUEPRINT_NAME:
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
    recent_activity = []
    try:
        # FIN1 Stats
        total_billing = client.table('billing_records').select('total_amount').execute()
        stats['revenue'] = sum([float(r.get('total_amount', 0)) for r in total_billing.data]) if total_billing.data else 0
        
        # FIN2 Stats
        response = client.table('vendor_invoices').select('amount').eq('status', 'Unpaid').execute()
        stats['payables'] = sum([float(r.get('amount', 0)) for r in response.data]) if response.data else 0
        
        # FIN3 Stats
        stats['receivables_count'] = client.table('receivables').select('id', count='exact').eq('status', 'Unpaid').execute().count or 0
        stats['receivables_amount'] = sum([float(r.get('amount_due', 0)) for r in client.table('receivables').select('amount_due').eq('status', 'Unpaid').execute().data or []])
        
        # FIN4 Stats
        bank_resp = client.table('bank_accounts').select('balance').execute()
        stats['cash_on_hand'] = sum([float(r.get('balance', 0)) for r in bank_resp.data]) if bank_resp.data else 0
        
        # Vendor Count
        stats['vendor_count'] = client.table('vendors').select('id', count='exact').execute().count or 0
        
        # Recent Activity (Combined from multiple sources)
        col_activity = client.table('collections').select('*, receivables(billing_id)').order('collection_date', desc=True).limit(3).execute().data or []
        for c in col_activity:
            recent_activity.append({
                'type': 'Collection',
                'amount': c['amount'],
                'date': c['collection_date'],
                'status': 'Completed',
                'icon': 'bi-arrow-down-left-circle',
                'color': 'text-green-600'
            })
            
        pay_activity = client.table('vendor_payments').select('*, vendor_invoices(invoice_number)').order('payment_date', desc=True).limit(3).execute().data or []
        for p in pay_activity:
            recent_activity.append({
                'type': 'Vendor Payment',
                'amount': p['amount'],
                'date': p['payment_date'],
                'status': 'Paid',
                'icon': 'bi-arrow-up-right-circle',
                'color': 'text-red-600'
            })
            
        recent_activity = sorted(recent_activity, key=lambda x: x['date'], reverse=True)[:5]
        
    except Exception as e:
        print(f"Error fetching stats: {e}")

    return render_template('subsystems/financials/dashboard.html', 
                           stats=stats,
                           recent_activity=recent_activity,
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
        total_amount = request.form.get('total_amount', 0)
        try:
            total_amount = float(total_amount)
        except (TypeError, ValueError):
            total_amount = 0.0

        data = {
            'patient_id': request.form.get('patient_id'),
            'total_amount': total_amount,
            'status': request.form.get('status', 'Unpaid'),
            'billing_date': datetime.now().isoformat(),
            'description': request.form.get('description', '')
        }
        bill_resp = client.table('billing_records').insert(data).execute()
        
        # Automatically create a receivable record if not already paid
        if bill_resp.data and data['status'] != 'Paid':
            bill_id = bill_resp.data[0]['id']
            receivable_data = {
                'billing_id': bill_id,
                'amount_due': total_amount,
                'due_date': (datetime.now() + timedelta(days=30)).date().isoformat(),
                'status': 'Unpaid'
            }
            client.table('receivables').insert(receivable_data).execute()

        flash('Invoice created successfully!', 'success')
        return redirect(url_for('financials.list_billing'))
    
    from utils.hms_models import Patient
    patients = Patient.get_all()
    return render_template('subsystems/financials/fin1/create_bill.html', 
                           patients=patients, 
                           subsystem_name="Billing Management", 
                           accent_color="#8B5CF6", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/billing/pay/<int:bill_id>', methods=['POST'])
@login_required
def pay_bill(bill_id):
    client = get_supabase_client()
    # 1. Update billing record status
    client.table('billing_records').update({'status': 'Paid'}).eq('id', bill_id).execute()
    
    # 2. Update receivable if exists
    rec_resp = client.table('receivables').select('id, amount_due').eq('billing_id', bill_id).execute()
    if rec_resp.data:
        rec_id = rec_resp.data[0]['id']
        amount = rec_resp.data[0]['amount_due']
        client.table('receivables').update({'status': 'Paid'}).eq('id', rec_id).execute()
        
        # 3. Record collection
        collection_data = {
            'receivable_id': rec_id,
            'amount': amount,
            'payment_method': request.form.get('payment_method', 'Cash'),
            'collection_date': datetime.now().isoformat(),
            'collected_by': current_user.get_id()
        }
        client.table('collections').insert(collection_data).execute()
    else:
        # If no receivable, maybe it was already paid or direct payment
        # Still record a collection if we want, but usually it goes through receivables
        pass

    flash(f'Payment processed for Invoice #INV-{bill_id}', 'success')
    return redirect(url_for('financials.list_billing'))

@financials_bp.route('/billing/void/<int:bill_id>', methods=['POST'])
@login_required
def void_bill(bill_id):
    client = get_supabase_client()
    client.table('billing_records').update({'status': 'Voided'}).eq('id', bill_id).execute()
    client.table('receivables').update({'status': 'Voided'}).eq('billing_id', bill_id).execute()
    flash(f'Invoice #INV-{bill_id} has been voided.', 'info')
    return redirect(url_for('financials.list_billing'))

@financials_bp.route('/billing/delete/<int:bill_id>', methods=['POST'])
@login_required
def delete_bill(bill_id):
    client = get_supabase_client()
    client.table('billing_records').delete().eq('id', bill_id).execute()
    flash(f'Invoice #INV-{bill_id} deleted successfully.', 'warning')
    return redirect(url_for('financials.list_billing'))

@financials_bp.route('/billing/view/<int:bill_id>')
@login_required
def view_bill(bill_id):
    client = get_supabase_client()
    bill = client.table('billing_records').select('*, patients(*)').eq('id', bill_id).single().execute().data
    if not bill:
        flash('Invoice not found.', 'danger')
        return redirect(url_for('financials.list_billing'))
    
    return render_template('subsystems/financials/fin1/view_bill.html', 
                           bill=bill,
                           subsystem_name="Billing Management", 
                           accent_color="#8B5CF6", 
                           blueprint_name=BLUEPRINT_NAME)

# --- FIN2 MODULE: ACCOUNTS PAYABLE ---
@financials_bp.route('/payables')
@login_required
def vendor_invoices():
    client = get_supabase_client()
    vendor_id = request.args.get('vendor_id')
    
    query = client.table('vendor_invoices').select('*, vendors(name)')
    if vendor_id:
        query = query.eq('vendor_id', vendor_id)
    
    invoices = query.order('due_date').execute().data or []
    for inv in invoices:
        inv['vendor_name'] = inv.get('vendors', {}).get('name', 'Unknown')
    
    bank_accounts = client.table('bank_accounts').select('*').execute().data or []
    
    return render_template('subsystems/financials/fin2/invoices.html', 
                           invoices=invoices, 
                           bank_accounts=bank_accounts,
                           subsystem_name="Accounts Payable", 
                           accent_color="#A855F7", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/payables/pay/<int:invoice_id>', methods=['POST'])
@login_required
def pay_invoice(invoice_id):
    client = get_supabase_client()
    invoice = client.table('vendor_invoices').select('*').eq('id', invoice_id).single().execute().data
    if not invoice:
        flash('Invoice not found.', 'danger')
        return redirect(url_for('financials.vendor_invoices'))
    
    # 1. Update invoice status
    client.table('vendor_invoices').update({'status': 'Paid'}).eq('id', invoice_id).execute()
    
    # 2. Record payment
    payment_data = {
        'invoice_id': invoice_id,
        'payment_date': datetime.now().date().isoformat(),
        'amount': invoice['amount'],
        'payment_method': request.form.get('payment_method', 'Bank Transfer'),
        'reference_number': request.form.get('reference_number', '')
    }
    client.table('vendor_payments').insert(payment_data).execute()
    
    # 3. Update bank account if selected
    account_id = request.form.get('account_id')
    if account_id:
        acc = client.table('bank_accounts').select('balance').eq('id', account_id).single().execute().data
        if acc:
            new_balance = float(acc['balance']) - float(invoice['amount'])
            client.table('bank_accounts').update({'balance': new_balance}).eq('id', account_id).execute()
            
            # Record cash transaction
            client.table('cash_transactions').insert({
                'account_id': account_id,
                'transaction_type': 'WITHDRAWAL',
                'amount': invoice['amount'],
                'description': f"Payment for Invoice #INV-{invoice_id}",
                'performed_by': current_user.get_id()
            }).execute()

    flash(f'Payment recorded for Invoice #{invoice.get("invoice_number", invoice_id)}', 'success')
    return redirect(url_for('financials.vendor_invoices'))

@financials_bp.route('/vendors')
@login_required
def vendors_list():
    client = get_supabase_client()
    vendors = client.table('vendors').select('*').order('name').execute().data or []
    return render_template('subsystems/financials/fin2/vendors.html', 
                           vendors=vendors, 
                           subsystem_name="Accounts Payable", 
                           accent_color="#A855F7", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/vendors/add', methods=['GET', 'POST'])
@login_required
def add_vendor():
    if request.method == 'POST':
        client = get_supabase_client()
        data = {
            'name': request.form.get('name'),
            'contact_person': request.form.get('contact_person'),
            'email': request.form.get('email'),
            'phone': request.form.get('phone'),
            'status': 'Active'
        }
        client.table('vendors').insert(data).execute()
        flash('Vendor added successfully!', 'success')
        return redirect(url_for('financials.vendors_list'))
    
    return render_template('subsystems/financials/fin2/add_vendor.html', 
                           subsystem_name="Accounts Payable", 
                           accent_color="#A855F7", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/payables/add', methods=['GET', 'POST'])
@login_required
def add_invoice():
    client = get_supabase_client()
    if request.method == 'POST':
        try:
            vendor_id = request.form.get('vendor_id')
            amount = request.form.get('amount', 0)
            
            try:
                amount = float(amount)
            except (TypeError, ValueError):
                amount = 0.0

            data = {
                'vendor_id': int(vendor_id) if vendor_id else None,
                'invoice_number': request.form.get('invoice_number'),
                'invoice_date': request.form.get('invoice_date'),
                'due_date': request.form.get('due_date'),
                'amount': amount,
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
    receivables = client.table('receivables').select('*, billing_records(id, total_amount, patients(first_name, last_name))').order('due_date').execute().data or []
    for rec in receivables:
        patient = rec.get('billing_records', {}).get('patients', {})
        rec['patient_name'] = f"{patient.get('first_name', '')} {patient.get('last_name', '')}".strip() or 'Unknown'
        rec['display_id'] = rec.get('billing_records', {}).get('id', 'N/A')
    
    bank_accounts = client.table('bank_accounts').select('*').execute().data or []

    return render_template('subsystems/financials/fin3/receivables.html', 
                           receivables=receivables, 
                           bank_accounts=bank_accounts,
                           subsystem_name="Accounts Receivable", 
                           accent_color="#9333EA", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/receivables/collect/<int:receivable_id>', methods=['POST'])
@login_required
def collect_receivable(receivable_id):
    client = get_supabase_client()
    rec = client.table('receivables').select('*').eq('id', receivable_id).single().execute().data
    if not rec:
        flash('Receivable record not found.', 'danger')
        return redirect(url_for('financials.receivables_list'))
    
    amount = float(request.form.get('amount', rec['amount_due']))
    
    # 1. Update receivable status
    client.table('receivables').update({'status': 'Paid'}).eq('id', receivable_id).execute()
    
    # 2. Update linked billing if exists
    if rec.get('billing_id'):
        client.table('billing_records').update({'status': 'Paid'}).eq('id', rec['billing_id']).execute()
    
    # 3. Record collection
    collection_data = {
        'receivable_id': receivable_id,
        'amount': amount,
        'collection_date': datetime.now().isoformat(),
        'payment_method': request.form.get('payment_method', 'Cash'),
        'collected_by': current_user.get_id()
    }
    client.table('collections').insert(collection_data).execute()
    
    # 4. Update bank balance if selected
    account_id = request.form.get('account_id')
    if account_id:
        acc = client.table('bank_accounts').select('balance').eq('id', account_id).single().execute().data
        if acc:
            new_balance = float(acc['balance']) + amount
            client.table('bank_accounts').update({'balance': new_balance}).eq('id', account_id).execute()
            
            # Record cash transaction
            client.table('cash_transactions').insert({
                'account_id': account_id,
                'transaction_type': 'DEPOSIT',
                'amount': amount,
                'description': f"Collection from Receivable #{receivable_id}",
                'performed_by': current_user.get_id()
            }).execute()

    flash(f'Collection of ${amount:.2f} recorded successfully.', 'success')
    return redirect(url_for('financials.receivables_list'))

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

@financials_bp.route('/bank-accounts/add', methods=['POST'])
@login_required
def add_bank_account():
    client = get_supabase_client()
    data = {
        'bank_name': request.form.get('bank_name'),
        'account_number': request.form.get('account_number'),
        'account_type': request.form.get('account_type'),
        'balance': float(request.form.get('initial_balance', 0))
    }
    client.table('bank_accounts').insert(data).execute()
    flash('Bank account added successfully!', 'success')
    return redirect(url_for('financials.bank_accounts'))

# --- FIN5 MODULE: FINANCIAL REPORTS ---
@financials_bp.route('/reports')
@login_required
def reports_list():
    client = get_supabase_client()
    try:
        # Fallback to id if created_at is not yet sync'd in the DB
        reports = client.table('generated_reports').select('*').order('id', desc=True).execute().data or []
    except Exception:
        reports = []
    
    return render_template('subsystems/financials/fin5/reports.html', 
                           reports=reports, 
                           subsystem_name="Financial Intel", 
                           accent_color="#6D28D9", 
                           blueprint_name=BLUEPRINT_NAME)

@financials_bp.route('/reports/income-statement')
@login_required
def income_statement():
    client = get_supabase_client()
    revenue = sum([float(r.get('amount', 0)) for r in client.table('collections').select('amount').execute().data or []])
    expenses = sum([float(r.get('amount', 0)) for r in client.table('vendor_payments').select('amount').execute().data or []])
    # Fallback to net_pay as gross_salary might not exist in all environments
    payroll_data = client.table('payroll_records').select('net_pay').eq('status', 'Paid').execute().data or []
    payroll = sum([float(r.get('net_pay', 0)) for r in payroll_data])
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
    try:
        # Robust fetch: handle missing 'balance' column
        bank_data = client.table('bank_accounts').select('*').execute().data or []
        cash = sum([float(r.get('balance', 0)) for r in bank_data])
    except Exception:
        cash = 0
        
    receivables = sum([r['amount_due'] for r in client.table('receivables').select('amount_due').eq('status', 'Open').execute().data or []])
    payables = sum([r['amount'] for r in client.table('vendor_invoices').select('amount').eq('status', 'Unpaid').execute().data or []])
    total_assets = cash + receivables
    total_liabilities = payables
    equity = total_assets - total_liabilities
    return render_template('subsystems/financials/fin5/balance_sheet.html', 
                           cash=cash, receivables=receivables, payables=payables,
                           total_assets=total_assets, total_liabilities=total_liabilities, equity=equity,
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
