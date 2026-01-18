from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from datetime import datetime

fin2_bp = Blueprint('fin2', __name__, template_folder='templates')

# Subsystem configuration
SUBSYSTEM_NAME = 'FIN2 - Accounts Payable'
ACCENT_COLOR = '[#EF4444]'
BLUEPRINT_NAME = 'fin2'

@fin2_bp.route('/login', methods=['GET', 'POST'])
def login():
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/financials/fin2/login.html', remaining_seconds=remaining_seconds)
    
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
                    return redirect(url_for('fin2.change_password'))
                # Check if account is approved
                if user.status != 'Active':
                    if user.status == 'Pending':
                        flash('Your account is awaiting approval from HR3 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('subsystems/financials/fin2/login.html')

                # Clear IP lockout attempts on successful login
                register_successful_login()
                user.register_successful_login()
                
                if login_user(user):
                    days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                    if days_left <= 7:
                        flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    return redirect(url_for('fin2.dashboard'))
                else:
                    flash('Login failed. Your account may be deactivated.', 'danger')
                    return render_template('subsystems/financials/fin2/login.html')
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/financials/fin2/login.html', remaining_seconds=remaining_seconds)
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
                return render_template('subsystems/financials/fin2/login.html', remaining_seconds=remaining_seconds)
    return render_template('subsystems/financials/fin2/login.html')

@fin2_bp.route('/register', methods=['GET', 'POST'])
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
                department='FINANCIALS',
                status='Pending'
            )
            
            if new_user:
                flash('Registration successful! Your account is awaiting approval from HR3 Admin.', 'success')
                return redirect(url_for('fin2.login'))
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

@fin2_bp.route('/change-password', methods=['GET', 'POST'])
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
            return redirect(url_for('fin2.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('fin2.login'))
    
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
            return redirect(url_for('fin2.login'))
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html', subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@fin2_bp.route('/dashboard')
@login_required
def dashboard():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Get total payables (Sum of unpaid invoices)
        response = client.table('vendor_invoices').select('amount').eq('status', 'Unpaid').execute()
        amounts = [r['amount'] for r in response.data] if response.data else []
        total_payables = sum(amounts)
        
        # Get pending invoices count
        pending_invoices = len(amounts)
        
        # Get due this week
        now = datetime.utcnow()
        next_week = (now + timedelta(days=7)).strftime('%Y-%m-%d')
        today = now.strftime('%Y-%m-%d')
        response = client.table('vendor_invoices').select('id', count='exact').eq('status', 'Unpaid').lte('due_date', next_week).gte('due_date', today).execute()
        due_this_week = response.count if response.count is not None else 0
        
    except Exception as e:
        print(f"Error fetching stats: {e}")
        total_payables = 0.0
        pending_invoices = 0
        due_this_week = 0
    
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    return render_template('subsystems/financials/fin2/dashboard.html', 
                           now=datetime.utcnow,
                           total_payables=total_payables,
                           pending_invoices=pending_invoices,
                           due_this_week=due_this_week,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@fin2_bp.route('/invoices')
@login_required
def vendor_invoices():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Fetch invoices
        response = client.table('vendor_invoices').select('*').order('due_date').execute()
        invoices = response.data if response.data else []
        
        # Enrich with vendor names
        for inv in invoices:
            if inv.get('vendor_id'):
                v_resp = client.table('vendors').select('name').eq('id', inv['vendor_id']).single().execute()
                if v_resp.data:
                    inv['vendor_name'] = v_resp.data['name']
            else:
                inv['vendor_name'] = 'Unknown'
                
    except Exception as e:
        print(f"Error fetching invoices: {e}")
        invoices = []
        
    return render_template('subsystems/financials/fin2/invoices.html',
                           invoices=invoices,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@fin2_bp.route('/invoices/add', methods=['GET', 'POST'])
@login_required
def add_invoice():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    if request.method == 'POST':
        vendor_id = request.form.get('vendor_id')
        invoice_number = request.form.get('invoice_number')
        invoice_date = request.form.get('invoice_date')
        due_date = request.form.get('due_date')
        amount = request.form.get('amount')
        description = request.form.get('description')
        
        try:
            data = {
                'vendor_id': int(vendor_id),
                'invoice_number': invoice_number,
                'invoice_date': invoice_date,
                'due_date': due_date,
                'amount': float(amount),
                'status': 'Unpaid',
                'description': description
            }
            
            client.table('vendor_invoices').insert(data).execute()
            flash('Invoice recorded successfully!', 'success')
            return redirect(url_for('fin2.vendor_invoices'))
            
        except Exception as e:
            flash(f'Error adding invoice: {format_db_error(e)}', 'danger')
    
    # Fetch vendors for dropdown
    try:
        response = client.table('vendors').select('id, name').eq('status', 'Active').order('name').execute()
        vendors = response.data if response.data else []
    except:
        vendors = []
    
    return render_template('subsystems/financials/fin2/add_invoice.html',
                           vendors=vendors,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@fin2_bp.route('/payments')
@login_required
def payments():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Fetch payments
        response = client.table('vendor_payments').select('*').order('payment_date', desc=True).execute()
        payments = response.data if response.data else []
        
        # Enrich with invoice and vendor details
        for pay in payments:
            if pay.get('invoice_id'):
                inv_resp = client.table('vendor_invoices').select('invoice_number, vendor_id').eq('id', pay['invoice_id']).single().execute()
                if inv_resp.data:
                    pay['invoice_number'] = inv_resp.data['invoice_number']
                    # Get vendor name
                    v_resp = client.table('vendors').select('name').eq('id', inv_resp.data['vendor_id']).single().execute()
                    if v_resp.data:
                        pay['vendor_name'] = v_resp.data['name']
            else:
                pay['invoice_number'] = 'N/A'
                pay['vendor_name'] = 'Unknown'
                
    except Exception as e:
        print(f"Error fetching payments: {e}")
        payments = []
        
    return render_template('subsystems/financials/fin2/payments.html',
                           payments=payments,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@fin2_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('fin2.login'))

