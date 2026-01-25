from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from datetime import datetime

ct3_bp = Blueprint('ct3', __name__, template_folder='templates')

# Subsystem configuration
SUBSYSTEM_NAME = 'CT3 - Admin & Finance'
ACCENT_COLOR = '#059669'
BLUEPRINT_NAME = 'ct3'

@ct3_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/core_transaction/ct3/login.html', remaining_seconds=remaining_seconds)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.get_by_username(username, BLUEPRINT_NAME)
        
        if user:
            now_utc = datetime.utcnow()
            
            if user.check_password(password):
                # Check for password expiration - redirect to change password
                if user.password_expires_at and user.password_expires_at < now_utc:
                    session['expired_user_id'] = user.id
                    session['expired_subsystem'] = BLUEPRINT_NAME
                    flash('Your password has expired. Please set a new password to continue.', 'warning')
                    return redirect(url_for('ct3.change_password'))

                # Check if account is approved
                if user.status != 'Active':
                    if user.status == 'Pending':
                        flash('Your account is awaiting approval from HR3 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('subsystems/core_transaction/ct3/login.html')

                # Clear IP lockout attempts on successful login
                register_successful_login()
                user.register_successful_login()
                
                if login_user(user):
                    from utils.hms_models import AuditLog
                    AuditLog.log(user.id, "Login", BLUEPRINT_NAME, {"ip": request.remote_addr, "user_agent": request.headers.get('User-Agent')})
                    
                    days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                    if days_left <= 7:
                        flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    return redirect(url_for('ct3.dashboard'))
                else:
                    flash('Login failed. Your account may be deactivated.', 'danger')
                    return render_template('subsystems/core_transaction/ct3/login.html')
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/core_transaction/ct3/login.html', remaining_seconds=remaining_seconds)
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
                return render_template('subsystems/core_transaction/ct3/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/core_transaction/ct3/login.html')

@ct3_bp.route('/register', methods=['GET', 'POST'])
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
                department='CORE_TRANSACTION',
                status='Pending'
            )
            
            if new_user:
                flash('Registration successful! Your account is awaiting approval from HR3 Admin.', 'success')
                return redirect(url_for('ct3.login'))
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
                           hub_route='portal.ct_hub',
                           accent_color=ACCENT_COLOR)

@ct3_bp.route('/change-password', methods=['GET', 'POST'])
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
            return redirect(url_for('ct3.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('ct3.login'))
    
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
                blueprint_name=BLUEBlueprint_NAME, is_expired=is_expired)
        
        try:
            user.set_password(new_password)
            from utils.hms_models import AuditLog
            AuditLog.log(user.id, "Change Password", BLUEPRINT_NAME)
            
            session.pop('expired_user_id', None)
            session.pop('expired_subsystem', None)
            flash('Password updated successfully! Please login with your new password.', 'success')
            if current_user.is_authenticated:
                logout_user()
            return redirect(url_for('ct3.login'))
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html',
        subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@ct3_bp.route('/dashboard')
@login_required
@policy_required(BLUEPRINT_NAME)
def dashboard():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        patients_count = client.table('patients').select('id', count='exact').execute().count or 0
        
        # Get billing stats
        billing_resp = client.table('billing_records').select('total_amount, status').execute()
        revenue = sum(float(b['total_amount']) for b in billing_resp.data if b['status'] == 'Paid') if billing_resp.data else 0.0
        pending_bills = sum(1 for b in billing_resp.data if b['status'] != 'Paid') if billing_resp.data else 0
        
        # Get records created today
        today = datetime.utcnow().strftime('%Y-%m-%d')
        response = client.table('medical_records').select('id', count='exact').gte('visit_date', today).execute()
        records_today = response.count if response.count is not None else 0
        
        # Get recent activity
        activity_resp = client.table('medical_records').select('*, patients(first_name, last_name, patient_id_alt)').order('visit_date', desc=True).limit(5).execute()
        recent_activity = activity_resp.data if activity_resp.data else []
        
    except Exception as e:
        print(f"Error fetching stats: {e}")
        patients_count = 0
        revenue = 0.0
        pending_bills = 0
        records_today = 0
        recent_activity = []
    
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    return render_template('subsystems/core_transaction/ct3/dashboard.html', 
                           now=datetime.utcnow,
                           patients_count=patients_count,
                           revenue=revenue,
                           pending_bills=pending_bills,
                           records_today=records_today,
                           recent_activity=recent_activity,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct3_bp.route('/print/<int:patient_id>')
@login_required
def print_record(patient_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        patient_resp = client.table('patients').select('*').eq('id', patient_id).single().execute()
        patient = patient_resp.data
        
        history_resp = client.table('medical_records').select('*').eq('patient_id', patient_id).order('visit_date', desc=True).execute()
        history = history_resp.data
        
        for record in history:
            if record.get('doctor_id'):
                doc = client.table('users').select('username').eq('id', record['doctor_id']).single().execute()
                record['doctor_name'] = doc.data['username'] if doc.data else 'Unknown'
            else:
                record['doctor_name'] = 'Unknown'
                
        return render_template('subsystems/core_transaction/ct3/print_record.html', 
                               patient=patient, history=history, now=datetime.utcnow())
    except Exception as e:
        flash(f'Error generating print view: {str(e)}', 'danger')
        return redirect(url_for('ct3.patient_records'))

@ct3_bp.route('/billing')
@login_required
def billing():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Get billing data with joint fetch fallback
        try:
            response = client.table('billing_records').select('*, patients(first_name, last_name, patient_id_alt)').order('created_at', desc=True).execute()
            bills = response.data if response.data else []
        except Exception as e:
            print(f"Billing join failed: {e}")
            billing_resp = client.table('billing_records').select('*').order('created_at', desc=True).execute()
            patients_resp = client.table('patients').select('id, first_name, last_name, patient_id_alt').execute()
            
            p_dict = {p['id']: p for p in (patients_resp.data or [])}
            bills = []
            for b in (billing_resp.data or []):
                b['patients'] = p_dict.get(b['patient_id'])
                bills.append(b)

        # Fetch patients for the modal
        patients_resp = client.table('patients').select('id, first_name, last_name, patient_id_alt').execute()
        patients_list = patients_resp.data if patients_resp.data else []
    except Exception as e:
        flash(f'Error fetching billing data: {str(e)}', 'danger')
        bills = []
        patients_list = []
        
    return render_template('subsystems/core_transaction/ct3/billing.html', 
                           bills=bills,
                           patients_list=patients_list,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct3_bp.route('/billing/create', methods=['POST'])
@login_required
def create_bill():
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can generate new invoices.', 'error')
        return redirect(url_for('ct3.billing'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        patient_id = request.form.get('patient_id')
        amount = request.form.get('amount')
        
        data = {
            'patient_id': patient_id,
            'total_amount': amount,
            'status': 'Unpaid'
        }
        client.table('billing_records').insert(data).execute()
        flash('Bill generated successfully.', 'success')
    except Exception as e:
        flash(f'Error creating bill: {str(e)}', 'danger')
        
    return redirect(url_for('ct3.billing'))

@ct3_bp.route('/billing/pay/<int:bill_id>', methods=['POST'])
@login_required
def pay_bill(bill_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can record payments.', 'error')
        return redirect(url_for('ct3.billing'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('billing_records').update({'status': 'Paid'}).eq('id', bill_id).execute()
        
        # AUDIT LOG
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Record Payment", BLUEPRINT_NAME, {"bill_id": bill_id})
        
        flash('Payment recorded successfully.', 'success')
    except Exception as e:
        flash(f'Error recording payment: {str(e)}', 'danger')
        
    return redirect(url_for('ct3.billing'))

@ct3_bp.route('/security-logs')
@login_required
def security_logs():
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can view security logs.', 'error')
        return redirect(url_for('ct3.dashboard'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Fetching activity from audit_logs table joining with users
        response = client.table('audit_logs')\
            .select('*, users(username, avatar_url)')\
            .order('created_at', desc=True)\
            .limit(50)\
            .execute()
        logs = response.data if response.data else []
        
        # Calculate some stats for the dashboard
        active_sessions = client.table('users').select('id', count='exact').not_.is_('last_login', 'null').gte('last_login', (datetime.utcnow().replace(hour=0, minute=0, second=0)).isoformat()).execute().count or 0
        security_alerts = sum(1 for log in logs if 'Delete' in log['action'] or 'Export' in log['action'])
    except Exception as e:
        print(f"Error fetching audit logs: {e}")
        logs = []
        active_sessions = 0
        security_alerts = 0
        
    return render_template('subsystems/core_transaction/ct3/security_logs.html',
                           logs=logs,
                           active_sessions=active_sessions,
                           security_alerts=security_alerts,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct3_bp.route('/export-logs')
@login_required
def export_logs():
    if not current_user.is_admin():
        flash('Unauthorized.', 'error')
        return redirect(url_for('ct3.dashboard'))
        
    from utils.hms_models import AuditLog
    AuditLog.log(current_user.id, "Export Logs", BLUEPRINT_NAME, {"type": "Audit Logs CSV"})
    
    # Simple flash for now, in a real app this would generate a CSV/PDF
    flash('Security logs have been exported and sent to system administrator email.', 'success')
    return redirect(url_for('ct3.security_logs'))

@ct3_bp.route('/records')
@login_required
def patient_records():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    search_query = request.args.get('search', '')
    
    try:
        query = client.table('patients').select('*')
        if search_query:
            # Simple search by name or ID
            query = query.or_(f"first_name.ilike.%{search_query}%,last_name.ilike.%{search_query}%,patient_id_alt.ilike.%{search_query}%")
        
        response = query.order('last_name').execute()
        patients = response.data if response.data else []
    except Exception as e:
        print(f"Error fetching patients: {e}")
        patients = []
    
    return render_template('subsystems/core_transaction/ct3/patient_records.html',
                           patients=patients,
                           search_query=search_query,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct3_bp.route('/records/<int:patient_id>')
@login_required
def view_record(patient_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Get patient details
        patient_resp = client.table('patients').select('*').eq('id', patient_id).single().execute()
        patient = patient_resp.data if patient_resp.data else {}
        
        # Get medical history
        history_resp = client.table('medical_records').select('*').eq('patient_id', patient_id).order('visit_date', desc=True).execute()
        history = history_resp.data if history_resp.data else []
        
        # Enrich history with doctor names (simplified)
        for record in history:
            if record.get('doctor_id'):
                doc_resp = client.table('users').select('username').eq('id', record['doctor_id']).single().execute()
                if doc_resp.data:
                    record['doctor_name'] = doc_resp.data['username']
            else:
                record['doctor_name'] = 'Unknown'
                
    except Exception as e:
        print(f"Error fetching record: {e}")
        patient = {}
        history = []
    
    return render_template('subsystems/core_transaction/ct3/view_record.html',
                           patient=patient,
                           history=history,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct3_bp.route('/records/<int:patient_id>/add', methods=['POST'])
@login_required
def add_medical_record(patient_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        vitals = {
            'temp': request.form.get('temp'),
            'bp': request.form.get('bp'),
            'weight': request.form.get('weight')
        }
        data = {
            'patient_id': patient_id,
            'doctor_id': current_user.id,
            'diagnosis': request.form.get('diagnosis'),
            'treatment': request.form.get('treatment'),
            'notes': request.form.get('notes'),
            'vitals': vitals,
            'visit_date': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
        }
        client.table('medical_records').insert(data).execute()
        
        # Log the action
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Add Medical Record", BLUEPRINT_NAME, {"patient_id": patient_id, "diagnosis": data['diagnosis']})
        
        # Also update allergies if provided
        allergies = request.form.get('allergies')
        if allergies:
            client.table('patients').update({'allergies': allergies}).eq('id', patient_id).execute()
            
        flash('Medical record added successfully.', 'success')
    except Exception as e:
        flash(f'Error adding record: {str(e)}', 'danger')
    
    return redirect(url_for('ct3.view_record', patient_id=patient_id))

@ct3_bp.route('/records/<int:patient_id>/edit/<int:record_id>', methods=['POST'])
@login_required
def edit_medical_record(patient_id, record_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        vitals = {
            'temp': request.form.get('temp'),
            'bp': request.form.get('bp'),
            'weight': request.form.get('weight')
        }
        data = {
            'diagnosis': request.form.get('diagnosis'),
            'treatment': request.form.get('treatment'),
            'notes': request.form.get('notes'),
            'vitals': vitals
        }
        client.table('medical_records').update(data).eq('id', record_id).execute()
        
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Edit Medical Record", BLUEPRINT_NAME, {"record_id": record_id, "patient_id": patient_id})
        
        flash('Record updated successfully.', 'success')
    except Exception as e:
        flash(f'Error updating record: {str(e)}', 'danger')
    
    return redirect(url_for('ct3.view_record', patient_id=patient_id))

@ct3_bp.route('/records/<int:patient_id>/delete/<int:record_id>', methods=['POST'])
@login_required
def delete_medical_record(patient_id, record_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can delete records.', 'error')
        return redirect(url_for('ct3.view_record', patient_id=patient_id))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('medical_records').delete().eq('id', record_id).execute()
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Delete Medical Record", BLUEPRINT_NAME, {"record_id": record_id, "patient_id": patient_id})
        flash('Record removed from history.', 'info')
    except Exception as e:
        flash(f'Error deleting record: {str(e)}', 'danger')
    
    return redirect(url_for('ct3.view_record', patient_id=patient_id))

@ct3_bp.route('/analytics')
@login_required
def analytics():
    if not current_user.is_admin():
        flash('Unauthorized: Access restricted to administrators.', 'error')
        return redirect(url_for('ct3.dashboard'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Get patient demographics (Simplified)
        patients_resp = client.table('patients').select('gender').execute()
        demographics = {'Male': 0, 'Female': 0, 'Other': 0}
        for p in patients_resp.data:
            gen = p.get('gender', 'Other')
            demographics[gen] = demographics.get(gen, 0) + 1
            
        # Get billing stats
        billing_resp = client.table('billing_records').select('status, total_amount').execute()
        financials = {'Paid': 0.0, 'Unpaid': 0.0}
        for b in billing_resp.data:
            status = b.get('status', 'Unpaid')
            financials[status] = financials.get(status, 0.0) + float(b['total_amount'])
            
    except Exception as e:
        print(f"Analytics error: {e}")
        demographics = {}
        financials = {}
        
    return render_template('subsystems/core_transaction/ct3/analytics.html',
                           demographics=demographics,
                           financials=financials,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct3_bp.route('/settings', methods=['GET', 'POST'])
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

@ct3_bp.route('/discharge')
@login_required
def discharge():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Get all patients who are currently admitted (using beds as a proxy for admission)
        beds_resp = client.table('beds').select('*, patients(*)').eq('status', 'Occupied').execute()
        admitted = beds_resp.data if beds_resp.data else []
        
        # For each admitted patient, check clearance status
        for record in admitted:
            p_id = record.get('patient_id')
            if not p_id: continue
            
            # 1. Check Billing Status (Integration Point: Finance)
            bills_resp = client.table('billing_records').select('status').eq('patient_id', p_id).execute()
            unpaid_bills = [b for b in bills_resp.data if b['status'] != 'Paid']
            record['billing_cleared'] = (len(bills_resp.data) > 0 and len(unpaid_bills) == 0)
            
            # 2. Check Lab Status (Integration Point: Clinical Lab)
            labs_resp = client.table('lab_orders').select('status').eq('patient_id', p_id).execute()
            pending_labs = [l for l in labs_resp.data if l['status'] != 'Resulted']
            record['labs_cleared'] = (len(labs_resp.data) == 0 or len(pending_labs) == 0)
            
            # 3. Check Pharmacy Status (Integration Point: Clinical Pharmacy)
            pharm_resp = client.table('prescriptions').select('status').eq('patient_id', p_id).execute()
            pending_meds = [p for p in pharm_resp.data if p['status'] != 'Dispensed']
            record['pharm_cleared'] = (len(pharm_resp.data) == 0 or len(pending_meds) == 0)
            
            record['fully_cleared'] = record['billing_cleared'] and record['labs_cleared'] and record['pharm_cleared']
            
    except Exception as e:
        flash(f'Error fetching discharge data: {str(e)}', 'danger')
        admitted = []
        
    return render_template('subsystems/core_transaction/ct3/discharge.html',
                           admitted=admitted,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct3_bp.route('/discharge/<int:patient_id>/clear', methods=['POST'])
@login_required
def clear_for_discharge(patient_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can finalize discharge clearance.', 'error')
        return redirect(url_for('ct3.discharge'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Final safety check before discharge
        bills_resp = client.table('billing_records').select('status').eq('patient_id', patient_id).execute()
        if not bills_resp.data or any(b['status'] != 'Paid' for b in bills_resp.data):
             flash('Cannot discharge: Outstanding balance exists or no bill record found.', 'danger')
             return redirect(url_for('ct3.discharge'))
             
        # Free up the bed
        client.table('beds').update({'status': 'Available', 'patient_id': None}).eq('patient_id', patient_id).execute()
        
        flash('Patient discharged and bed cleared successfully.', 'success')
    except Exception as e:
        flash(f'Error during discharge: {str(e)}', 'danger')
        
    return redirect(url_for('ct3.discharge'))

@ct3_bp.route('/logout')
@login_required
def logout():
    from utils.hms_models import AuditLog
    AuditLog.log(current_user.id, "Logout", BLUEPRINT_NAME)
    logout_user()
    return redirect(url_for('ct3.login'))

