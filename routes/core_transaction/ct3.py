from flask import Blueprint, render_template, redirect, url_for, flash, request, session, send_from_directory
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from utils.supabase_client import User, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from datetime import datetime
import os
import uuid

ct3_bp = Blueprint('ct3', __name__, template_folder='templates')

# Subsystem configuration
SUBSYSTEM_NAME = 'CT3 - Admin & Finance'
ACCENT_COLOR = '#059669'
BLUEPRINT_NAME = 'ct3'

@ct3_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked(subsystem=BLUEPRINT_NAME)
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
                        flash('Your account is awaiting approval from HR2 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('subsystems/core_transaction/ct3/login.html')

                # Clear IP lockout attempts on successful login
                register_successful_login(subsystem=BLUEPRINT_NAME)
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
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt(subsystem=BLUEPRINT_NAME)
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/core_transaction/ct3/login.html', remaining_seconds=remaining_seconds)
                else:
                    flash(f'Invalid credentials. {remaining_attempts} attempts remaining before lockout.', 'danger')
        else:
            # Check if user exists in ANY subsystem to provide better feedback
            try:
                matching_subs = User.find_subsystems_by_username(username)
                if matching_subs:
                    subs_display = ', '.join(s.upper() for s in matching_subs)
                    flash(f'Account found in {subs_display} portal(s). Please log in through the correct portal.', 'warning')
                else:
                    flash('Invalid credentials.', 'danger')
            except:
                flash('Invalid credentials.', 'danger')
                
            # Register failed attempt even for non-existent users
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt(subsystem=BLUEPRINT_NAME)
            
            if is_now_locked:
                return render_template('subsystems/core_transaction/ct3/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/core_transaction/ct3/login.html')


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
                blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)
        
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
        
        # Patient status distribution for dashboard
        status_resp = client.table('patients').select('current_status').execute()
        status_counts = {}
        for p in (status_resp.data or []):
            s = p.get('current_status') or 'Registered'
            status_counts[s] = status_counts.get(s, 0) + 1

        admitted_count   = status_counts.get('Admitted', 0)
        waiting_count    = status_counts.get('Waiting', 0)
        in_surgery_count = status_counts.get('In Surgery / Procedure', 0)
        discharged_today = 0
        try:
            dt_resp = client.table('patients').select('id', count='exact').eq('current_status', 'Discharged').gte('discharge_date', today).execute()
            discharged_today = dt_resp.count or 0
        except Exception:
            pass

        # Get recent activity from new activity log, fallback to medical_records
        activity_resp = client.table('hospital_activity_log').select('*').order('created_at', desc=True).limit(8).execute()
        recent_activity = activity_resp.data if activity_resp.data else []
        if not recent_activity:
            fallback = client.table('medical_records').select('*, patients(first_name, last_name, patient_id_alt)').order('visit_date', desc=True).limit(5).execute()
            recent_activity = fallback.data if fallback.data else []
        
    except Exception as e:
        print(f"Error fetching stats: {e}")
        patients_count = 0
        revenue = 0.0
        pending_bills = 0
        records_today = 0
        recent_activity = []
        status_counts    = {}
        admitted_count   = 0
        waiting_count    = 0
        in_surgery_count = 0
        discharged_today = 0
    
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    return render_template('subsystems/core_transaction/ct3/dashboard.html', 
                           now=datetime.utcnow(),
                           patients_count=patients_count,
                           revenue=revenue,
                           pending_bills=pending_bills,
                           records_today=records_today,
                           recent_activity=recent_activity,
                           status_counts=status_counts,
                           admitted_count=admitted_count,
                           waiting_count=waiting_count,
                           in_surgery_count=in_surgery_count,
                           discharged_today=discharged_today,
                           status_colors=STATUS_COLORS,
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
                           now=datetime.utcnow(),
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
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct3_bp.route('/security-report')
@login_required
def security_report():
    if not current_user.is_admin():
        flash('Unauthorized.', 'error')
        return redirect(url_for('ct3.dashboard'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        response = client.table('audit_logs')\
            .select('*, users(username, avatar_url)')\
            .order('created_at', desc=True)\
            .execute()
        
        logs = response.data if response.data else []
        
        return render_template('subsystems/core_transaction/ct3/security_report.html',
                               logs=logs,
                               subsystem_name=SUBSYSTEM_NAME,
                               accent_color=ACCENT_COLOR,
                               blueprint_name=BLUEPRINT_NAME)
    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'danger')
        return redirect(url_for('ct3.security_logs'))

@ct3_bp.route('/export-logs')
@login_required
def export_logs():
    if not current_user.is_admin():
        flash('Unauthorized.', 'error')
        return redirect(url_for('ct3.dashboard'))
        
    import csv
    import io
    from flask import Response
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import AuditLog
    
    client = get_supabase_client()
    
    try:
        # Fetch all logs
        response = client.table('audit_logs')\
            .select('*, users(username)')\
            .order('created_at', desc=True)\
            .execute()
        
        logs = response.data if response.data else []
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Date', 'User', 'Action', 'Subsystem', 'Details'])
        
        for log in logs:
            username = log.get('users', {}).get('username', 'Unknown') if log.get('users') else 'System'
            writer.writerow([
                log.get('created_at'),
                username,
                log.get('action'),
                log.get('subsystem'),
                str(log.get('details', ''))
            ])
            
        output.seek(0)
        
        AuditLog.log(current_user.id, "Download Security Logs", BLUEPRINT_NAME, {"type": "Audit Logs CSV", "count": len(logs)})
        
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename=audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
        )
        
    except Exception as e:
        flash(f'Error exporting logs: {str(e)}', 'danger')
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
        print(f"Found {len(patients)} patients")
        if patients:
            print(f"First patient: {patients[0]}")
            print(f"Patient keys: {patients[0].keys()}")
            for i, p in enumerate(patients[:3]):  # Show first 3 patients
                print(f"Patient {i+1}: {p.get('first_name')} {p.get('last_name')} - ID: {p.get('id')} - All keys: {list(p.keys())}")
    except Exception as e:
        print(f"Error fetching patients: {e}")
        patients = []
    
    return render_template('subsystems/core_transaction/ct3/patient_records.html',
                           patients=patients,
                           search_query=search_query,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct3_bp.route('/records/<int:patient_id>')
@login_required
def view_record(patient_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    patient = {}
    history = []
    active_diet = None
    latest_assessment = None
    
    try:
        # Get patient details with comprehensive error handling
        print(f"\n{'='*60}")
        print(f"DEBUG: VIEW_RECORD - Looking for patient ID: {patient_id} (type: {type(patient_id).__name__})")
        
        # Primary lookup: Get patient by ID
        patient_resp = client.table('patients').select('*').eq('id', patient_id).execute()
        print(f"DEBUG: Primary lookup - Response count: {len(patient_resp.data) if patient_resp.data else 0}")
        print(f"DEBUG: Raw response data: {patient_resp.data}")
        
        if patient_resp.data and len(patient_resp.data) > 0:
            patient = patient_resp.data[0]
            print(f"DEBUG: SUCCESS - Found patient: {patient.get('first_name')} {patient.get('last_name')} (ID: {patient.get('id')})")
        else:
            print(f"DEBUG: FAILED - No patient found with ID {patient_id}")
            # Check the database has any patients at all
            all_patients = client.table('patients').select('id, first_name, last_name').limit(5).execute()
            print(f"DEBUG: First 5 patients in DB: {all_patients.data}")
            
            flash('Patient not found in database.', 'error')
            return redirect(url_for('ct3.patient_records'))
        
        # Get medical history
        print(f"DEBUG: Fetching medical records for patient ID: {patient_id}")
        history_resp = client.table('medical_records').select('*').eq('patient_id', patient_id).order('visit_date', desc=True).execute()
        history = history_resp.data if history_resp.data else []
        print(f"DEBUG: Found {len(history)} medical records")
        
        # Enrich history with doctor names
        for idx, record in enumerate(history):
            record['doctor_name'] = 'Unknown'
            if record.get('doctor_id'):
                try:
                    doc_resp = client.table('users').select('username').eq('id', record['doctor_id']).limit(1).execute()
                    if doc_resp.data and len(doc_resp.data) > 0:
                        record['doctor_name'] = doc_resp.data[0]['username']
                except Exception as doc_err:
                    print(f"DEBUG: Error fetching doctor name: {doc_err}")
        
        # Get active diet plan
        print(f"DEBUG: Fetching diet plans for patient ID: {patient_id}")
        try:
            diet_resp = client.table('diet_plans').select('*').eq('patient_id', patient_id).eq('status', 'Active').order('created_at', desc=True).limit(1).execute()
            if diet_resp.data and len(diet_resp.data) > 0:
                active_diet = diet_resp.data[0]
            print(f"DEBUG: Found diet plan: {active_diet is not None}")
        except Exception as diet_err:
            print(f"DEBUG: Error fetching diet plans: {diet_err}")
        
        # Get latest nutritional assessment
        print(f"DEBUG: Fetching nutritional assessments for patient ID: {patient_id}")
        try:
            assessment_resp = client.table('nutritional_assessments').select('*').eq('patient_id', patient_id).order('created_at', desc=True).limit(1).execute()
            if assessment_resp.data and len(assessment_resp.data) > 0:
                latest_assessment = assessment_resp.data[0]
            print(f"DEBUG: Found assessment: {latest_assessment is not None}")
        except Exception as assess_err:
            print(f"DEBUG: Error fetching nutritional assessments: {assess_err}")
        
        print(f"DEBUG: Successfully compiled all data for patient {patient_id}")
        print(f"{'='*60}\n")
                
    except Exception as e:
        import traceback
        print(f"ERROR in view_record: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        flash(f'Error loading patient record: {str(e)}', 'error')
    
    return render_template('subsystems/core_transaction/ct3/view_record.html',
                           patient=patient,
                           history=history,
                           active_diet=active_diet,
                           latest_assessment=latest_assessment,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct3_bp.route('/debug_patients')
@login_required  
def debug_patients():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Get first 3 patients to debug
        response = client.table('patients').select('*').limit(3).execute()
        patients = response.data if response.data else []
        
        debug_info = []
        for i, patient in enumerate(patients):
            debug_info.append({
                'index': i,
                'patient_data': patient,
                'id_field': patient.get('id'),
                'id_type': type(patient.get('id')),
                'all_fields': list(patient.keys())
            })
        
        # Test specific lookup
        if patients:
            test_id = patients[0].get('id')
            if test_id:
                test_resp = client.table('patients').select('*').eq('id', test_id).execute()
                debug_info.append({
                    'test_lookup': f'Looking for ID: {test_id}',
                    'test_result': test_resp.data,
                    'test_found': len(test_resp.data) if test_resp.data else 0
                })
        
        return f"<pre>{debug_info}</pre>"
        
    except Exception as e:
        return f"<pre>Error: {str(e)}</pre>"

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
@policy_required(BLUEPRINT_NAME)
def analytics():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        patients_resp = client.table('patients').select('gender, current_status').execute()
        all_patients = patients_resp.data or []

        demographics = {'Male': 0, 'Female': 0, 'Other': 0}
        status_dist  = {}
        for p in all_patients:
            gen = p.get('gender', 'Other') or 'Other'
            demographics[gen] = demographics.get(gen, 0) + 1
            s = p.get('current_status') or 'Registered'
            status_dist[s] = status_dist.get(s, 0) + 1

        billing_resp = client.table('billing_records').select('status, total_amount').execute()
        financials = {'Paid': 0.0, 'Unpaid': 0.0}
        for b in (billing_resp.data or []):
            status = b.get('status', 'Unpaid')
            financials[status] = financials.get(status, 0.0) + float(b.get('total_amount', 0))

        # Recent activity count
        activity_resp = client.table('hospital_activity_log').select('id', count='exact').execute()
        total_activities = activity_resp.count or 0

    except Exception as e:
        print(f"Analytics error: {e}")
        demographics   = {}
        financials     = {}
        status_dist    = {}
        total_activities = 0

    return render_template('subsystems/core_transaction/ct3/analytics.html',
                           demographics=demographics,
                           financials=financials,
                           status_dist=status_dist,
                           status_colors=STATUS_COLORS,
                           total_activities=total_activities,
                           now=datetime.utcnow(),
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
        # Get all occupied beds
        beds_resp = client.table('beds').select('*').eq('status', 'Occupied').execute()
        occupied_beds = beds_resp.data if beds_resp.data else []
        
        # Get all patients who have a current_bed_id in insurance_info
        patients_resp = client.table('patients').select('*').execute()
        all_patients = patients_resp.data if patients_resp.data else []
        
        # Build bed_id -> patient map from JSONB
        bed_to_patient = {}
        for p in all_patients:
            info = p.get('insurance_info') or {}
            b_id = info.get('current_bed_id')
            if b_id:
                bed_to_patient[int(b_id)] = p
        
        admitted = []
        for bed in occupied_beds:
            patient = bed_to_patient.get(bed['id'])
            if not patient:
                continue
            
            record = {**bed, 'patients': patient, 'patient_id': patient['id']}
            p_id = patient['id']
            
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
            admitted.append(record)
            
    except Exception as e:
        flash(f'Error fetching discharge data: {str(e)}', 'danger')
        admitted = []
        
    return render_template('subsystems/core_transaction/ct3/discharge.html',
                           admitted=admitted,
                           now=datetime.utcnow(),
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
             
        # Free up the bed - find it via JSONB workaround
        p_res = client.table('patients').select('id, insurance_info').eq('id', patient_id).single().execute()
        if p_res.data:
            insurance = p_res.data.get('insurance_info') or {}
            bed_id = insurance.get('current_bed_id')
            if bed_id:
                client.table('beds').update({'status': 'Available'}).eq('id', int(bed_id)).execute()
            # Clear the bed assignment from patient
            if 'current_bed_id' in insurance:
                del insurance['current_bed_id']
            client.table('patients').update({'insurance_info': insurance}).eq('id', patient_id).execute()
        
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


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — PATIENT STATUS ENGINE
# ─────────────────────────────────────────────────────────────────────────────

STATUS_COLORS = {
    'Registered':              '#6B7280',
    'Waiting':                 '#F59E0B',
    'Admitted':                '#3B82F6',
    'Under Consultation':      '#6366F1',
    'Under Treatment':         '#6366F1',
    'Under Observation':       '#06B6D4',
    'In Surgery / Procedure':  '#F97316',
    'Recovered / Stable':      '#22C55E',
    'Discharged':              '#14B8A6',
    'Transferred':             '#A855F7',
    'Deceased':                '#9F1239',
}

ALLOWED_TRANSITIONS = {
    'Registered':             ['Waiting'],
    'Waiting':                ['Under Consultation', 'Admitted'],
    'Admitted':               ['Under Consultation', 'Under Observation', 'In Surgery / Procedure'],
    'Under Consultation':     ['Under Observation', 'In Surgery / Procedure', 'Recovered / Stable', 'Discharged'],
    'Under Treatment':        ['Under Observation', 'In Surgery / Procedure', 'Recovered / Stable', 'Discharged'],
    'Under Observation':      ['Recovered / Stable', 'Under Consultation', 'Admitted'],
    'In Surgery / Procedure': ['Under Observation', 'Recovered / Stable'],
    'Recovered / Stable':     ['Discharged', 'Under Observation'],
    'Discharged':             [],
    'Transferred':            [],
    'Deceased':               [],
}
TERMINAL_STATUSES = {'Discharged', 'Transferred', 'Deceased'}
REQUIRES_REASON  = {'Discharged', 'Transferred', 'Deceased'}

# Any status → Transferred/Deceased is always allowed (with reason)
def get_allowed_transitions(current_status):
    base = list(ALLOWED_TRANSITIONS.get(current_status, []))
    if current_status not in TERMINAL_STATUSES:
        if 'Transferred' not in base:
            base.append('Transferred')
        if 'Deceased' not in base:
            base.append('Deceased')
    return base


@ct3_bp.route('/patients')
@login_required
@policy_required(BLUEPRINT_NAME)
def patient_census():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    status_filter = request.args.get('status', '')
    search = request.args.get('search', '')

    try:
        q = client.table('patients').select('*')
        if status_filter:
            q = q.eq('current_status', status_filter)
        if search:
            q = q.or_(
                f"first_name.ilike.%{search}%,"
                f"last_name.ilike.%{search}%,"
                f"patient_id_alt.ilike.%{search}%"
            )
        resp = q.order('last_name').execute()
        patients = resp.data or []
    except Exception as e:
        flash(f'Error fetching patient census: {e}', 'danger')
        patients = []

    status_counts = {}
    try:
        all_resp = client.table('patients').select('current_status').execute()
        for p in (all_resp.data or []):
            s = p.get('current_status') or 'Registered'
            status_counts[s] = status_counts.get(s, 0) + 1
    except Exception:
        pass

    return render_template('subsystems/core_transaction/ct3/patient_census.html',
                           patients=patients,
                           status_filter=status_filter,
                           search=search,
                           status_counts=status_counts,
                           status_colors=STATUS_COLORS,
                           all_statuses=list(STATUS_COLORS.keys()),
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/patients/<int:patient_id>/status')
@login_required
@policy_required(BLUEPRINT_NAME)
def patient_status_panel(patient_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        p_resp = client.table('patients').select('*').eq('id', patient_id).single().execute()
        patient = p_resp.data or {}
        current_status = patient.get('current_status') or 'Registered'
        allowed = get_allowed_transitions(current_status)
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('ct3.patient_census'))

    return render_template('subsystems/core_transaction/ct3/patient_status_panel.html',
                           patient=patient,
                           current_status=current_status,
                           allowed_transitions=allowed,
                           requires_reason=REQUIRES_REASON,
                           status_colors=STATUS_COLORS,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/patients/<int:patient_id>/status/update', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def update_patient_status(patient_id):
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import AuditLog
    client = get_supabase_client()

    new_status = request.form.get('new_status', '').strip()
    reason = request.form.get('reason', '').strip()
    metadata_raw = request.form.get('metadata', '{}')

    try:
        import json
        metadata = json.loads(metadata_raw) if metadata_raw else {}
    except Exception:
        metadata = {}

    try:
        p_resp = client.table('patients').select('id, current_status').eq('id', patient_id).single().execute()
        patient = p_resp.data
        if not patient:
            flash('Patient not found.', 'danger')
            return redirect(url_for('ct3.patient_census'))

        old_status = patient.get('current_status') or 'Registered'
        allowed = get_allowed_transitions(old_status)

        if new_status not in allowed:
            flash(f'Transition from "{old_status}" to "{new_status}" is not allowed.', 'danger')
            return redirect(url_for('ct3.patient_status_panel', patient_id=patient_id))

        if new_status in REQUIRES_REASON and not reason:
            flash(f'A reason is required when setting status to "{new_status}".', 'danger')
            return redirect(url_for('ct3.patient_status_panel', patient_id=patient_id))

        # Insert history record
        history_data = {
            'patient_id': patient_id,
            'old_status': old_status,
            'new_status': new_status,
            'changed_by': current_user.id,
            'reason': reason or None,
            'metadata': metadata or None,
        }
        client.table('patient_status_history').insert(history_data).execute()

        # Build update dict
        update_data = {
            'current_status': new_status,
            'status_updated_at': datetime.utcnow().isoformat(),
            'status_updated_by': current_user.id,
        }
        if new_status == 'Admitted':
            update_data['admission_date'] = datetime.utcnow().isoformat()
        if new_status in TERMINAL_STATUSES:
            update_data['discharge_date'] = datetime.utcnow().isoformat()

        client.table('patients').update(update_data).eq('id', patient_id).execute()

        # Activity log
        _log_activity('Status Change', patient_id=patient_id, performed_by=current_user.id,
                      description=f'Status changed from {old_status} → {new_status}',
                      metadata={'old': old_status, 'new': new_status, 'reason': reason})
        AuditLog.log(current_user.id, "Patient Status Change", BLUEPRINT_NAME,
                     {"patient_id": patient_id, "from": old_status, "to": new_status})

        flash(f'Patient status updated to "{new_status}".', 'success')
    except Exception as e:
        flash(f'Error updating status: {e}', 'danger')

    return redirect(url_for('ct3.patient_status_panel', patient_id=patient_id))


@ct3_bp.route('/patients/<int:patient_id>/status/history')
@login_required
@policy_required(BLUEPRINT_NAME)
def patient_status_history(patient_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        p_resp = client.table('patients').select('id, first_name, last_name, patient_id_alt, current_status').eq('id', patient_id).single().execute()
        patient = p_resp.data or {}
        h_resp = client.table('patient_status_history').select('*').eq('patient_id', patient_id).order('changed_at', desc=True).execute()
        history = h_resp.data or []

        user_ids = list({r['changed_by'] for r in history if r.get('changed_by')})
        users_map = {}
        if user_ids:
            u_resp = client.table('users').select('id, username').in_('id', user_ids).execute()
            users_map = {u['id']: u for u in (u_resp.data or [])}
        for r in history:
            r['changer'] = users_map.get(r.get('changed_by'))
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        patient = {}
        history = []

    return render_template('subsystems/core_transaction/ct3/patient_status_history.html',
                           patient=patient,
                           history=history,
                           status_colors=STATUS_COLORS,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/status-board')
@login_required
@policy_required(BLUEPRINT_NAME)
def status_board():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        resp = client.table('patients').select('id, first_name, last_name, patient_id_alt, current_status, status_updated_at').execute()
        patients = resp.data or []
        # Group by status
        by_status = {}
        for s in STATUS_COLORS:
            by_status[s] = []
        for p in patients:
            s = p.get('current_status') or 'Registered'
            by_status.setdefault(s, []).append(p)
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        by_status = {}

    return render_template('subsystems/core_transaction/ct3/status_board.html',
                           by_status=by_status,
                           status_colors=STATUS_COLORS,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — ACTIVITY FEED
# ─────────────────────────────────────────────────────────────────────────────

def _log_activity_admin(activity_type, patient_id=None, user_id=None,
                        description='', metadata=None):
    """Insert activity log using service role (bypasses RLS). Admin use only."""
    try:
        from supabase import create_client
        from config import Config
        
        if not Config.SUPABASE_URL or not Config.SUPABASE_SERVICE_KEY:
            return False
            
        client = create_client(Config.SUPABASE_URL, Config.SUPABASE_SERVICE_KEY)
        data = {
            'activity_type': activity_type,
            'description': description,
        }
        if patient_id is not None:
            data['patient_id'] = patient_id
        if user_id is not None:
            data['user_id'] = user_id
        if metadata is not None:
            data['metadata'] = metadata
        
        client.table('hospital_activity_log').insert(data).execute()
        return True
    except Exception as e:
        print(f"Activity log error: {e}")
        return False


def _log_activity(activity_type, patient_id=None, user_id=None,
                  description='', metadata=None):
    """Insert a row into hospital_activity_log. Silently fails so it never breaks callers."""
    try:
        from utils.supabase_client import get_supabase_client
        client = get_supabase_client()
        data = {
            'activity_type': activity_type,
            'description': description,
        }
        if patient_id is not None:
            data['patient_id'] = patient_id
        if user_id is not None:
            data['user_id'] = user_id
        if metadata is not None:
            data['metadata'] = metadata
        client.table('hospital_activity_log').insert(data).execute()
    except Exception:
        pass


@ct3_bp.route('/debug/populate_activity')
@login_required
@policy_required(BLUEPRINT_NAME)
def populate_activity_debug():
    """Temporary route to populate test activity data - open access for setup"""
    from flask_login import current_user
    # Use 1 as a fallback system user ID if no user is logged in
    current_uid = current_user.id if hasattr(current_user, 'id') else 1
    
    activities = [
        {'activity_type': 'Status Change', 'patient_id': 14, 'user_id': current_uid, 'description': 'Patient asdd asdd admitted to Ward A'},
        {'activity_type': 'Record Updated', 'patient_id': 7, 'user_id': current_uid, 'description': 'Medical record updated with new vitals'},
        {'activity_type': 'Admission', 'patient_id': 24, 'user_id': current_uid, 'description': 'Patient angelo lesiges admitted to ICU'},
        {'activity_type': 'Billing Event', 'patient_id': 14, 'user_id': current_uid, 'description': 'Invoice generated for patient'},
        {'activity_type': 'Alert Raised', 'patient_id': 7, 'user_id': current_uid, 'description': 'Critical temperature reading detected'},
        {'activity_type': 'Procedure Started', 'patient_id': 14, 'user_id': current_uid, 'description': 'Surgical procedure initiated'},
        {'activity_type': 'Record Created', 'patient_id': 24, 'user_id': current_uid, 'description': 'New medical record created'},
        {'activity_type': 'Transfer', 'patient_id': 7, 'user_id': current_uid, 'description': 'Patient transferred from Ward B to Ward A'},
        {'activity_type': 'Discharge', 'patient_id': None, 'user_id': current_uid, 'description': 'Hospital-wide system maintenance completed'},
        {'activity_type': 'Procedure Ended', 'patient_id': 14, 'user_id': current_uid, 'description': 'Surgical procedure completed successfully'},
    ]
    
    inserted = 0
    for activity in activities:
        if _log_activity_admin(
            activity['activity_type'],
            patient_id=activity['patient_id'],
            user_id=activity['user_id'],
            description=activity['description']
        ):
            inserted += 1
    
    # Verify read
    try:
        from config import Config
        from supabase import create_client
        client = create_client(Config.SUPABASE_URL, Config.SUPABASE_SERVICE_KEY)
        res = client.table('hospital_activity_log').select('*', count='exact').execute()
        count = res.count
        data_sample = res.data[:2] if res.data else []
    except Exception as e:
        return f"Inserted {inserted}, but failed to read back: {e}"

    return f"Inserted {inserted} activity records. DB Count: {count}. Sample: {data_sample} <a href='/core-transaction/ct3/activity'>Go to Activity Feed</a>"

@ct3_bp.route('/activity')
@login_required
@policy_required(BLUEPRINT_NAME)
def activity_feed():
    try:
        from config import Config
        from supabase import create_client
        # Use service key to bypass RLS for activity logs if available, else fallback
        s_key = Config.SUPABASE_SERVICE_KEY or Config.SUPABASE_KEY
        client = create_client(Config.SUPABASE_URL, s_key)
    except ImportError:
        # Fallback for environments where supabase or config might have issues
        from utils.supabase_client import get_supabase_client
        client = get_supabase_client()

    # Default values
    logs = []
    page = int(request.args.get('page', 1))
    per_page = 50
    offset = (page - 1) * per_page
    activity_type = request.args.get('type', '')

    q = client.table('hospital_activity_log').select('*')
    if activity_type:
        q = q.eq('activity_type', activity_type)
    
    try:
        q = q.order('created_at', desc=True).range(offset, offset + per_page - 1)
        # Execute query
        resp = q.execute()
        logs = resp.data or []
    except Exception as e:
        print(f"Error executing activity query: {e}")
        logs = []

    patient_ids = list({r['patient_id'] for r in logs if r.get('patient_id')})
    user_ids    = list({r['user_id'] for r in logs if r.get('user_id')})
    patients_map = {}
    users_map    = {}
    if patient_ids:
        pr = client.table('patients').select('id, first_name, last_name, patient_id_alt').in_('id', patient_ids).execute()
        patients_map = {p['id']: p for p in (pr.data or [])}
    if user_ids:
        # Use service role here too just in case
        ur = client.table('users').select('id, username').in_('id', user_ids).execute()
        users_map = {u['id']: u for u in (ur.data or [])}
    for r in logs:
        r['patient_obj'] = patients_map.get(r.get('patient_id'))
        r['user_obj']    = users_map.get(r.get('user_id'))

    activity_types = [
        'Status Change', 'Admission', 'Discharge', 'Transfer',
        'Procedure Started', 'Procedure Ended', 'Death',
        'Billing Event', 'Record Created', 'Record Updated', 'Alert Raised',
    ]
    return render_template('subsystems/core_transaction/ct3/activity_feed.html',
                           logs=logs,
                           page=page,
                           activity_type=activity_type,
                           activity_types=activity_types,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/activity/patient/<int:patient_id>')
@login_required
@policy_required(BLUEPRINT_NAME)
def patient_activity(patient_id):
    try:
        from config import Config
        from supabase import create_client
        # Use service key if available, else standard key (RLS will apply, but won't crash)
        s_key = Config.SUPABASE_SERVICE_KEY or Config.SUPABASE_KEY
        client = create_client(Config.SUPABASE_URL, s_key)
    except:
        from utils.supabase_client import get_supabase_client
        client = get_supabase_client()

    try:
        p_resp = client.table('patients').select('id, first_name, last_name, patient_id_alt').eq('id', patient_id).single().execute()
        patient = p_resp.data or {}
        resp = client.table('hospital_activity_log').select('*').eq('patient_id', patient_id).order('created_at', desc=True).limit(100).execute()
        logs = resp.data or []
        user_ids = list({r['user_id'] for r in logs if r.get('user_id')})
        users_map = {}
        if user_ids:
            ur = client.table('users').select('id, username').in_('id', user_ids).execute()
            users_map = {u['id']: u for u in (ur.data or [])}
        for r in logs:
            r['user_obj'] = users_map.get(r.get('user_id'))
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        patient = {}
        logs = []

    return render_template('subsystems/core_transaction/ct3/patient_activity.html',
                           patient=patient,
                           logs=logs,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/activity/export')
@login_required
@policy_required(BLUEPRINT_NAME)
def export_activity():
    if not current_user.is_admin():
        flash('Unauthorized.', 'danger')
        return redirect(url_for('ct3.activity_feed'))
    import csv, io
    from flask import Response
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        resp = client.table('hospital_activity_log').select('*').order('created_at', desc=True).execute()
        logs = resp.data or []
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Date', 'Type', 'Patient ID', 'Performed By', 'Module', 'Description'])
        for r in logs:
            writer.writerow([r.get('created_at', '')[:19], r.get('activity_type'), r.get('patient_id'), r.get('performed_by'), r.get('source_module'), r.get('description')])
        output.seek(0)
        return Response(output.getvalue(), mimetype='text/csv',
                        headers={'Content-Disposition': f'attachment; filename=activity_log_{datetime.now().strftime("%Y%m%d")}.csv'})
    except Exception as e:
        flash(f'Export error: {e}', 'danger')
        return redirect(url_for('ct3.activity_feed'))


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — PATIENT TIMELINE
# ─────────────────────────────────────────────────────────────────────────────

@ct3_bp.route('/patients/<int:patient_id>/timeline')
@login_required
@policy_required(BLUEPRINT_NAME)
def patient_timeline(patient_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        p_resp = client.table('patients').select('*').eq('id', patient_id).single().execute()
        patient = p_resp.data or {}
    except Exception:
        patient = {}

    events = []

    def _safe(func):
        try:
            return func() or []
        except Exception:
            return []

    # Patient registration event
    if patient.get('created_at'):
        events.append({
            'date': patient['created_at'],
            'type': 'Registration',
            'icon': 'bi-person-plus',
            'color': '#6B7280',
            'title': 'Patient Registered',
            'detail': f"ID: {patient.get('patient_id_alt', '')}",
        })

    # Status changes
    for r in _safe(lambda: client.table('patient_status_history').select('*').eq('patient_id', patient_id).execute().data):
        events.append({'date': r.get('changed_at', ''), 'type': 'Status Change', 'icon': 'bi-arrow-right-circle',
                       'color': STATUS_COLORS.get(r.get('new_status', ''), '#6B7280'),
                       'title': f"Status → {r.get('new_status')}", 'detail': r.get('reason', '')})

    # Medical records
    for r in _safe(lambda: client.table('medical_records').select('*').eq('patient_id', patient_id).execute().data):
        events.append({'date': r.get('visit_date', ''), 'type': 'Medical Record',
                       'icon': 'bi-file-earmark-medical', 'color': '#6366F1',
                       'title': f"Diagnosis: {r.get('diagnosis', 'N/A')}", 'detail': r.get('treatment', '')})

    # Billing records
    for r in _safe(lambda: client.table('billing_records').select('*').eq('patient_id', patient_id).execute().data):
        events.append({'date': r.get('created_at', ''), 'type': 'Billing',
                       'icon': 'bi-receipt', 'color': '#059669',
                       'title': f"Bill #{r.get('id')} — ₱{r.get('total_amount', 0)}", 'detail': r.get('status', '')})

    # Activity logs
    for r in _safe(lambda: client.table('hospital_activity_log').select('*').eq('patient_id', patient_id).execute().data):
        events.append({'date': r.get('created_at', ''), 'type': r.get('activity_type', 'Activity'),
                       'icon': 'bi-lightning', 'color': '#F59E0B',
                       'title': r.get('activity_type', 'Activity'), 'detail': r.get('description', '')})

    # Sort by date descending
    events.sort(key=lambda x: x.get('date', ''), reverse=True)

    return render_template('subsystems/core_transaction/ct3/patient_timeline.html',
                           patient=patient,
                           events=events,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — CENSUS BOARD
# ─────────────────────────────────────────────────────────────────────────────

@ct3_bp.route('/census')
@login_required
@policy_required(BLUEPRINT_NAME)
def census_board():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        beds_resp = client.table('beds').select('*').execute()
        beds = beds_resp.data or []
        patients_resp = client.table('patients').select('id, first_name, last_name, patient_id_alt, current_status, admission_date').execute()
        patients = patients_resp.data or []
    except Exception as e:
        flash(f'Census error: {e}', 'danger')
        beds = []
        patients = []

    total_beds     = len(beds)
    occupied_count = sum(1 for b in beds if b.get('status') == 'Occupied')
    available_count = sum(1 for b in beds if b.get('status') == 'Available')

    active_statuses  = ['Admitted', 'Under Consultation', 'Under Treatment', 'Under Observation', 'In Surgery / Procedure', 'Recovered / Stable']
    active_patients  = [p for p in patients if p.get('current_status') in active_statuses]
    waiting_patients = [p for p in patients if p.get('current_status') == 'Waiting']

    return render_template('subsystems/core_transaction/ct3/census_board.html',
                           beds=beds,
                           total_beds=total_beds,
                           occupied_count=occupied_count,
                           available_count=available_count,
                           active_patients=active_patients,
                           waiting_patients=waiting_patients,
                           status_colors=STATUS_COLORS,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/census/export')
@login_required
@policy_required(BLUEPRINT_NAME)
def census_export():
    if not current_user.is_admin():
        flash('Unauthorized.', 'danger')
        return redirect(url_for('ct3.census_board'))
    import csv, io
    from flask import Response
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        resp = client.table('patients').select('*').execute()
        patients = resp.data or []
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Patient ID', 'Name', 'Status', 'Admission Date', 'Status Updated'])
        for p in patients:
            writer.writerow([p.get('patient_id_alt'), f"{p.get('first_name')} {p.get('last_name')}",
                             p.get('current_status', 'Registered'), (p.get('admission_date') or '')[:10],
                             (p.get('status_updated_at') or '')[:10]])
        output.seek(0)
        return Response(output.getvalue(), mimetype='text/csv',
                        headers={'Content-Disposition': f'attachment; filename=census_{datetime.now().strftime("%Y%m%d")}.csv'})
    except Exception as e:
        flash(f'Export error: {e}', 'danger')
        return redirect(url_for('ct3.census_board'))


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 — DISCHARGE PLANNER
# ─────────────────────────────────────────────────────────────────────────────

@ct3_bp.route('/discharge/queue')
@login_required
@policy_required(BLUEPRINT_NAME)
def discharge_queue():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        resp = client.table('discharge_plans').select('*').in_('plan_status', ['Pending', 'Reviewing']).order('created_at', desc=True).execute()
        plans = resp.data or []
        patient_ids = list({r['patient_id'] for r in plans if r.get('patient_id')})
        patients_map = {}
        if patient_ids:
            pr = client.table('patients').select('id, first_name, last_name, patient_id_alt, current_status').in_('id', patient_ids).execute()
            patients_map = {p['id']: p for p in (pr.data or [])}
        for plan in plans:
            plan['patient_obj'] = patients_map.get(plan.get('patient_id'))
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        plans = []

    return render_template('subsystems/core_transaction/ct3/discharge_queue.html',
                           plans=plans,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/discharge/initiate/<int:patient_id>', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def initiate_discharge(patient_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        existing = client.table('discharge_plans').select('id').eq('patient_id', patient_id).in_('plan_status', ['Pending', 'Reviewing']).execute()
        if existing.data:
            flash('A discharge plan already exists for this patient.', 'warning')
            return redirect(url_for('ct3.discharge_plan_view', plan_id=existing.data[0]['id']))
        data = {
            'patient_id': patient_id,
            'created_by': current_user.id,
            'plan_status': 'Pending',
        }
        resp = client.table('discharge_plans').insert(data).execute()
        plan_id = resp.data[0]['id'] if resp.data else None
        _log_activity('Discharge Initiated', patient_id=patient_id, performed_by=current_user.id,
                      description='Discharge plan initiated')
        flash('Discharge plan initiated.', 'success')
        if plan_id:
            return redirect(url_for('ct3.discharge_plan_view', plan_id=plan_id))
    except Exception as e:
        flash(f'Error: {e}', 'danger')
    return redirect(url_for('ct3.patient_census'))


@ct3_bp.route('/discharge/plan/<int:plan_id>', methods=['GET', 'POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def discharge_plan_view(plan_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        plan_resp = client.table('discharge_plans').select('*').eq('id', plan_id).single().execute()
        plan = plan_resp.data or {}
        patient_resp = client.table('patients').select('*').eq('id', plan.get('patient_id')).single().execute()
        patient = patient_resp.data or {}

        # Check clearances
        patient_id = plan.get('patient_id')
        bills_resp = client.table('billing_records').select('status').eq('patient_id', patient_id).execute()
        labs_resp = client.table('lab_orders').select('status').eq('patient_id', patient_id).execute()
        bills = bills_resp.data or []
        labs  = labs_resp.data or []
        billing_cleared = bool(bills) and all(b['status'] == 'Paid' for b in bills)
        labs_cleared    = not labs or all(l['status'] == 'Resulted' for l in labs)
        fully_cleared   = billing_cleared and labs_cleared and bool(plan.get('discharge_summary'))
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('ct3.discharge_queue'))

    if request.method == 'POST':
        action = request.form.get('action', 'save')
        try:
            update = {
                'discharge_summary':    request.form.get('discharge_summary', ''),
                'diagnosis':  request.form.get('discharge_diagnosis', ''),
                'follow_up_date':       request.form.get('follow_up_date') or None,
                'follow_up_instructions':      request.form.get('follow_up_notes', ''),
                'activity_restrictions': request.form.get('activity_restrictions', ''),
                'diet_instructions':    request.form.get('diet_instructions', ''),
                'wound_care_instructions':     request.form.get('wound_care_notes', ''),
                'plan_status': 'Reviewing',
            }
            if action == 'clear':
                update['plan_status'] = 'Cleared'
                update['cleared_by'] = current_user.id
                update['cleared_at'] = datetime.utcnow().isoformat()
                # Change patient status to Discharged
                client.table('patients').update({'current_status': 'Discharged', 'discharge_date': datetime.utcnow().isoformat()}).eq('id', plan.get('patient_id')).execute()
                _log_activity('Discharge', patient_id=plan.get('patient_id'), performed_by=current_user.id,
                              description='Patient cleared for discharge')
            client.table('discharge_plans').update(update).eq('id', plan_id).execute()
            flash('Discharge plan saved.' if action != 'clear' else 'Patient cleared for discharge.', 'success')
            return redirect(url_for('ct3.discharge_plan_view', plan_id=plan_id))
        except Exception as e:
            flash(f'Error saving: {e}', 'danger')

    return render_template('subsystems/core_transaction/ct3/discharge_plan.html',
                           plan=plan,
                           patient=patient,
                           billing_cleared=billing_cleared,
                           labs_cleared=labs_cleared,
                           fully_cleared=fully_cleared,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/discharge/plan/<int:plan_id>/print')
@login_required
def discharge_plan_print(plan_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        plan_resp = client.table('discharge_plans').select('*').eq('id', plan_id).single().execute()
        plan = plan_resp.data or {}
        patient_resp = client.table('patients').select('*').eq('id', plan.get('patient_id')).single().execute()
        patient = patient_resp.data or {}
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('ct3.discharge_queue'))
    return render_template('subsystems/core_transaction/ct3/discharge_print.html',
                           plan=plan, patient=patient, now=datetime.utcnow())


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6 — TRANSFER MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

@ct3_bp.route('/transfers')
@login_required
@policy_required(BLUEPRINT_NAME)
def transfers():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        resp = client.table('patient_transfers').select('*').order('initiated_at', desc=True).limit(100).execute()
        transfers_list = resp.data or []
        patient_ids = list({r['patient_id'] for r in transfers_list if r.get('patient_id')})
        patients_map = {}
        if patient_ids:
            pr = client.table('patients').select('id, first_name, last_name, patient_id_alt').in_('id', patient_ids).execute()
            patients_map = {p['id']: p for p in (pr.data or [])}
        for t in transfers_list:
            t['patient_obj'] = patients_map.get(t.get('patient_id'))
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        transfers_list = []

    # Patients eligible for transfer (non-terminal status)
    eligible = []
    try:
        pr = client.table('patients').select('id, first_name, last_name, patient_id_alt, current_status').not_.in_('current_status', list(TERMINAL_STATUSES)).execute()
        eligible = pr.data or []
    except Exception:
        pass

    return render_template('subsystems/core_transaction/ct3/transfers.html',
                           transfers_list=transfers_list,
                           eligible_patients=eligible,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/transfers/new/<int:patient_id>', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def new_transfer(patient_id):
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import AuditLog
    client = get_supabase_client()
    try:
        data = {
            'patient_id':             patient_id,
            'transfer_type':          request.form.get('transfer_type', 'Internal'),
            'from_location':          request.form.get('from_location', '') or None,
            'to_location':            request.form.get('to_location') or request.form.get('destination_department') or 'TBD',
            'destination_hospital':   request.form.get('destination_hospital', '') or None,
            'destination_department': request.form.get('destination_department', '') or None,
            'reason':                 request.form.get('reason', ''),
            'transport_mode':         request.form.get('transport_mode', '') or None,
            'clinical_summary':       request.form.get('clinical_summary', '') or None,
            'initiated_by':           current_user.id,
            'status':                 'Pending',
        }
        resp = client.table('patient_transfers').insert(data).execute()
        transfer_id = resp.data[0]['id'] if resp.data else None
        _log_activity('Transfer', patient_id=patient_id, performed_by=current_user.id,
                      description=f"Transfer initiated ({data['transfer_type']})")
        AuditLog.log(current_user.id, "Patient Transfer Initiated", BLUEPRINT_NAME, {"patient_id": patient_id})
        flash('Transfer initiated.', 'success')
        if transfer_id:
            return redirect(url_for('ct3.transfer_detail', transfer_id=transfer_id))
    except Exception as e:
        flash(f'Error: {e}', 'danger')
    return redirect(url_for('ct3.transfers'))


@ct3_bp.route('/transfers/<int:transfer_id>')
@login_required
@policy_required(BLUEPRINT_NAME)
def transfer_detail(transfer_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        t_resp = client.table('patient_transfers').select('*').eq('id', transfer_id).single().execute()
        transfer = t_resp.data or {}
        patient_resp = client.table('patients').select('*').eq('id', transfer.get('patient_id')).single().execute()
        patient = patient_resp.data or {}
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('ct3.transfers'))
    return render_template('subsystems/core_transaction/ct3/transfer_detail.html',
                           transfer=transfer, patient=patient, now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/transfers/<int:transfer_id>/complete', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def complete_transfer(transfer_id):
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import AuditLog
    client = get_supabase_client()
    try:
        t_resp = client.table('patient_transfers').select('patient_id').eq('id', transfer_id).single().execute()
        patient_id = t_resp.data['patient_id'] if t_resp.data else None
        client.table('patient_transfers').update({'status': 'Completed', 'completed_at': datetime.utcnow().isoformat()}).eq('id', transfer_id).execute()
        if patient_id:
            client.table('patients').update({'current_status': 'Transferred', 'status_updated_at': datetime.utcnow().isoformat(), 'status_updated_by': current_user.id}).eq('id', patient_id).execute()
            _log_activity('Transfer', patient_id=patient_id, performed_by=current_user.id, description='Transfer completed')
        AuditLog.log(current_user.id, "Transfer Completed", BLUEPRINT_NAME, {"transfer_id": transfer_id})
        flash('Transfer marked as completed.', 'success')
    except Exception as e:
        flash(f'Error: {e}', 'danger')
    return redirect(url_for('ct3.transfers'))


@ct3_bp.route('/transfers/<int:transfer_id>/cancel', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def cancel_transfer(transfer_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        client.table('patient_transfers').update({'status': 'Cancelled'}).eq('id', transfer_id).execute()
        flash('Transfer cancelled.', 'info')
    except Exception as e:
        flash(f'Error: {e}', 'danger')
    return redirect(url_for('ct3.transfers'))


@ct3_bp.route('/transfers/<int:transfer_id>/print')
@login_required
def transfer_print(transfer_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        t_resp = client.table('patient_transfers').select('*').eq('id', transfer_id).single().execute()
        transfer = t_resp.data or {}
        patient_resp = client.table('patients').select('*').eq('id', transfer.get('patient_id')).single().execute()
        patient = patient_resp.data or {}
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('ct3.transfers'))
    return render_template('subsystems/core_transaction/ct3/transfer_print.html',
                           transfer=transfer, patient=patient, now=datetime.utcnow())


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7 — DOCUMENT VAULT
# ─────────────────────────────────────────────────────────────────────────────

@ct3_bp.route('/documents')
@login_required
@policy_required(BLUEPRINT_NAME)
def documents():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    search = request.args.get('search', '')
    doc_type = request.args.get('type', '')
    try:
        q = client.table('patient_documents').select('*')
        if doc_type:
            q = q.eq('document_type', doc_type)
        if search:
            q = q.ilike('title', f'%{search}%')
        resp = q.order('uploaded_at', desc=True).limit(100).execute()
        docs = resp.data or []
        patient_ids = list({d['patient_id'] for d in docs if d.get('patient_id')})
        patients_map = {}
        if patient_ids:
            pr = client.table('patients').select('id, first_name, last_name, patient_id_alt').in_('id', patient_ids).execute()
            patients_map = {p['id']: p for p in (pr.data or [])}
        for d in docs:
            d['patient_obj'] = patients_map.get(d.get('patient_id'))
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        docs = []

    patients_list = []
    try:
        pr = client.table('patients').select('id, first_name, last_name, patient_id_alt').order('last_name').execute()
        patients_list = pr.data or []
    except Exception:
        pass

    doc_types = ['Consent Form', 'Lab Report', 'Imaging Report', 'Clinical Summary',
                 'Discharge Summary', 'Referral Letter', 'Prescription', 'Transfer Note', 'Other']

    return render_template('subsystems/core_transaction/ct3/documents.html',
                           docs=docs,
                           search=search,
                           doc_type=doc_type,
                           doc_types=doc_types,
                           patients_list=patients_list,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/documents/patient/<int:patient_id>')
@login_required
@policy_required(BLUEPRINT_NAME)
def patient_documents(patient_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        p_resp = client.table('patients').select('id, first_name, last_name, patient_id_alt').eq('id', patient_id).single().execute()
        patient = p_resp.data or {}
        resp = client.table('patient_documents').select('*').eq('patient_id', patient_id).order('uploaded_at', desc=True).execute()
        docs = resp.data or []
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        patient = {}
        docs = []
    doc_types = ['Consent Form', 'Lab Report', 'Imaging Report', 'Clinical Summary',
                 'Discharge Summary', 'Referral Letter', 'Prescription', 'Transfer Note', 'Other']
    return render_template('subsystems/core_transaction/ct3/patient_documents.html',
                           patient=patient, docs=docs, doc_types=doc_types,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/documents/upload', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def upload_document():
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import AuditLog
    client = get_supabase_client()
    
    # File upload configuration
    UPLOAD_FOLDER = 'static/uploads/documents'
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'txt'}
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    
    try:
        # Check if file is present
        if 'document_file' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(url_for('ct3.documents'))
        
        file = request.files['document_file']
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('ct3.documents'))
        
        # Validate file
        if not allowed_file(file.filename):
            flash('Invalid file type. Please upload PDF, Word documents, images, or text files.', 'danger')
            return redirect(url_for('ct3.documents'))
        
        # Check file size (approximate)
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)  # Reset file pointer
        
        if file_size > MAX_FILE_SIZE:
            flash('File too large. Maximum size is 10MB.', 'danger')
            return redirect(url_for('ct3.documents'))
        
        # Create upload directory if it doesn't exist
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        
        # Generate secure filename
        original_filename = secure_filename(file.filename)
        file_extension = original_filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{file_extension}"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        
        # Save the file
        file.save(file_path)
        
        # Create database record
        data = {
            'patient_id':    int(request.form.get('patient_id')),
            'document_type': request.form.get('document_type', 'Other'),
            'title':         request.form.get('title', ''),
            'description':   request.form.get('description', '') or None,
            'file_url':      f"/{file_path}",  # Store relative path
            'file_size_kb':  int(round(file_size / 1024)),  # Convert to integer KB
            'mime_type':     file.content_type,
            'is_confidential': request.form.get('is_confidential') == '1',
            'uploaded_by':   current_user.id,
        }
        
        client.table('patient_documents').insert(data).execute()
        _log_activity('Record Created', patient_id=data['patient_id'], performed_by=current_user.id,
                      description=f"Document uploaded: {data['title']} ({original_filename})")
        AuditLog.log(current_user.id, "Document Upload", BLUEPRINT_NAME, {
            "patient_id": data['patient_id'], 
            "title": data['title'],
            "filename": original_filename,
            "file_size_kb": data['file_size_kb']
        })
        flash('Document uploaded successfully.', 'success')
        
    except Exception as e:
        flash(f'Error uploading file: {e}', 'danger')
        # Try to clean up the file if it was saved
        if 'file_path' in locals() and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except:
                pass
    
    # Handle redirect
    redirect_to = request.form.get('redirect_patient_id')
    if redirect_to:
        return redirect(url_for('ct3.patient_documents', patient_id=int(redirect_to)))
    return redirect(url_for('ct3.documents'))


@ct3_bp.route('/documents/<int:doc_id>/delete', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def delete_document(doc_id):
    if not current_user.is_admin():
        flash('Unauthorized.', 'danger')
        return redirect(url_for('ct3.documents'))
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        client.table('patient_documents').delete().eq('id', doc_id).execute()
        flash('Document removed.', 'info')
    except Exception as e:
        flash(f'Error: {e}', 'danger')
    return redirect(url_for('ct3.documents'))


@ct3_bp.route('/documents/<int:doc_id>/view')
@login_required
@policy_required(BLUEPRINT_NAME)
def view_document(doc_id):
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import AuditLog
    client = get_supabase_client()
    
    try:
        # Get document from database
        resp = client.table('patient_documents').select('*').eq('id', doc_id).single().execute()
        document = resp.data
        
        if not document:
            flash('Document not found.', 'error')
            return redirect(url_for('ct3.documents'))
        
        # Log document access
        AuditLog.log(current_user.id, "Document View", BLUEPRINT_NAME, {
            "document_id": doc_id,
            "patient_id": document.get('patient_id'),
            "document_type": document.get('document_type')
        })
        
        # Get file path (remove leading slash if present)
        file_path = document['file_url'].lstrip('/')
        
        # Check if file exists
        if not os.path.exists(file_path):
            flash('File not found on disk.', 'error')
            return redirect(url_for('ct3.documents'))
        
        # Serve the file
        directory = os.path.dirname(file_path)
        filename = os.path.basename(file_path)
        
        return send_from_directory(
            directory=directory,
            path=filename,
            as_attachment=False
        )
        
    except Exception as e:
        flash(f'Error viewing document: {str(e)}', 'error')
        return redirect(url_for('ct3.documents'))


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 8 — BILLING ENHANCEMENT
# ─────────────────────────────────────────────────────────────────────────────

HICS_WORKFLOW_START = 'AUTO_CAPTURE_CHARGES'
HICS_WORKFLOW_END = 'PATIENT_PAID'

HICS_STAGE_LABELS = {
    'AUTO_CAPTURE_CHARGES': 'Auto Capture Charges',
    'VALIDATE_COMPLETENESS_REMOVE_DUPLICATES': 'Validate Completeness & Remove Duplicates',
    'REVIEW_POSTED_CHARGES': 'Review Posted Charges',
    'ASSIGN_VERIFY_CODES': 'Assign / Verify Codes',
    'APPLY_DISCOUNTS_PACKAGES': 'Apply Discounts / Packages',
    'GENERATE_ITEMIZED_BILL': 'Generate Itemized Bill',
    'APPROVE_FINAL_BILL': 'Approve Final Bill',
    'CHECK_ELIGIBILITY_BENEFITS': 'Check Eligibility & Benefits',
    'CONTINUE_TO_PATIENT_PAYMENT': 'Continue to Patient Payment',
    'FULL_PATIENT_PAYMENT': 'Full Patient Payment',
    'GENERATE_RECEIPT': 'Generate Receipt',
    'CLAIM_CREATION': 'Claim Creation',
    'PREPARE_CLAIM_DOCUMENTS': 'Prepare Claim Documents',
    'SUBMIT_CLAIM_TO_INSURANCE': 'Submit Claim to Insurance',
    'CLAIM_DECISION': 'Claim Decision',
    'REVIEW_DENIAL': 'Review Denial',
    'CORRECT_RESUBMIT_CLAIM': 'Correct & Resubmit Claim',
    'POST_INSURANCE_PAYMENT': 'Post Insurance Payment',
    'COLLECT_PATIENT_SHARE': 'Collect Patient Share',
    'POST_PAYMENT_UPDATE_BALANCE': 'Post Payment & Update Balance',
    'PATIENT_PAID': 'Patient Paid',
}

HICS_COMMON_PATH = [
    'AUTO_CAPTURE_CHARGES',
    'VALIDATE_COMPLETENESS_REMOVE_DUPLICATES',
    'REVIEW_POSTED_CHARGES',
    'ASSIGN_VERIFY_CODES',
    'APPLY_DISCOUNTS_PACKAGES',
    'GENERATE_ITEMIZED_BILL',
    'APPROVE_FINAL_BILL',
    'CHECK_ELIGIBILITY_BENEFITS',
]

HICS_CASH_BRANCH = [
    'CONTINUE_TO_PATIENT_PAYMENT',
    'FULL_PATIENT_PAYMENT',
    'GENERATE_RECEIPT',
    'PATIENT_PAID',
]

HICS_INSURANCE_BRANCH = [
    'CLAIM_CREATION',
    'PREPARE_CLAIM_DOCUMENTS',
    'SUBMIT_CLAIM_TO_INSURANCE',
    'CLAIM_DECISION',
    'POST_INSURANCE_PAYMENT',
    'COLLECT_PATIENT_SHARE',
    'POST_PAYMENT_UPDATE_BALANCE',
    'GENERATE_RECEIPT',
    'PATIENT_PAID',
]

HICS_DEFAULT_NEXT = {
    # COMMON PATH (1-8)
    'AUTO_CAPTURE_CHARGES': 'VALIDATE_COMPLETENESS_REMOVE_DUPLICATES',
    'VALIDATE_COMPLETENESS_REMOVE_DUPLICATES': 'REVIEW_POSTED_CHARGES',
    'REVIEW_POSTED_CHARGES': 'ASSIGN_VERIFY_CODES',
    'ASSIGN_VERIFY_CODES': 'APPLY_DISCOUNTS_PACKAGES',
    'APPLY_DISCOUNTS_PACKAGES': 'GENERATE_ITEMIZED_BILL',
    'GENERATE_ITEMIZED_BILL': 'APPROVE_FINAL_BILL',
    'APPROVE_FINAL_BILL': 'CHECK_ELIGIBILITY_BENEFITS',
    # DECISION GATE: CHECK_ELIGIBILITY_BENEFITS (requires manual decision)
    
    # NO INSURANCE BRANCH (patient pays full amount)
    'CONTINUE_TO_PATIENT_PAYMENT': 'FULL_PATIENT_PAYMENT',
    'FULL_PATIENT_PAYMENT': 'GENERATE_RECEIPT',
    
    # INSURANCE BRANCH (submit claim)
    'CLAIM_CREATION': 'PREPARE_CLAIM_DOCUMENTS',
    'PREPARE_CLAIM_DOCUMENTS': 'SUBMIT_CLAIM_TO_INSURANCE',
    'SUBMIT_CLAIM_TO_INSURANCE': 'CLAIM_DECISION',
    # DECISION GATE: CLAIM_DECISION (requires manual decision)
    
    # CLAIM DECISION BRANCH: APPROVED
    'POST_INSURANCE_PAYMENT': 'COLLECT_PATIENT_SHARE',
    'COLLECT_PATIENT_SHARE': 'POST_PAYMENT_UPDATE_BALANCE',
    'POST_PAYMENT_UPDATE_BALANCE': 'GENERATE_RECEIPT',
    
    # CLAIM DECISION BRANCH: DENIED
    'REVIEW_DENIAL': 'CORRECT_RESUBMIT_CLAIM',
    'CORRECT_RESUBMIT_CLAIM': 'SUBMIT_CLAIM_TO_INSURANCE',  # Loop back
    
    # CONVERGENCE: Both branches go to GENERATE_RECEIPT then PATIENT_PAID
    'GENERATE_RECEIPT': 'PATIENT_PAID',
}


def _get_hics_workflow_stage(bill):
    raw_stage = (bill.get('workflow_stage') or bill.get('insurance_claim_status') or '').strip()
    if raw_stage in HICS_STAGE_LABELS:
        return raw_stage
    if (bill.get('status') or '').strip().lower() == 'paid':
        return 'PATIENT_PAID'
    return HICS_WORKFLOW_START


def _set_hics_workflow_stage(client, bill_id, stage):
    try:
        client.table('billing_records').update({'workflow_stage': stage}).eq('id', bill_id).execute()
    except Exception:
        client.table('billing_records').update({'insurance_claim_status': stage}).eq('id', bill_id).execute()


def _set_hics_eligibility_flag(client, bill_id, has_valid_insurance):
    try:
        client.table('billing_records').update({'has_valid_insurance': bool(has_valid_insurance)}).eq('id', bill_id).execute()
    except Exception:
        pass


def _mark_bill_paid(client, bill_id):
    try:
        client.table('billing_records').update({'status': 'Paid'}).eq('id', bill_id).execute()
    except Exception:
        pass


def _get_hics_stage_label(stage):
    return HICS_STAGE_LABELS.get(stage, stage.replace('_', ' ').title())

def _get_billing_line_items(client, bill_id):
    combined_items = []
    seen_ids = set()

    for fk_col in ['billing_id', 'bill_id']:
        try:
            try:
                resp = client.table('billing_line_items').select('*').eq(fk_col, bill_id).order('posted_at').execute()
            except Exception:
                try:
                    resp = client.table('billing_line_items').select('*').eq(fk_col, bill_id).order('created_at').execute()
                except Exception:
                    resp = client.table('billing_line_items').select('*').eq(fk_col, bill_id).execute()

            for item in (resp.data or []):
                item_id = item.get('id')
                if item_id is not None:
                    if item_id in seen_ids:
                        continue
                    seen_ids.add(item_id)
                combined_items.append(item)
        except Exception:
            continue

    return combined_items, 'mixed'


def _sum_billing_line_items_total(client, bill_id):
    gross_total, _, _ = _sum_billing_line_items_totals(client, bill_id)
    return gross_total


def _sum_billing_line_items_totals(client, bill_id):
    items, _ = _get_billing_line_items(client, bill_id)

    gross_total = 0.0
    line_discount_total = 0.0
    line_net_total = 0.0

    for item in items:
        try:
            qty = 0.0
            if 'quantity' in item and item.get('quantity') is not None:
                qty = float(item.get('quantity') or 0)
            elif 'qty' in item and item.get('qty') is not None:
                qty = float(item.get('qty') or 0)

            unit_price = 0.0
            if 'unit_price' in item and item.get('unit_price') is not None:
                unit_price = float(item.get('unit_price') or 0)

            line_discount = 0.0
            if 'discount' in item and item.get('discount') is not None:
                line_discount = float(item.get('discount') or 0)
            line_discount = max(0.0, line_discount)

            gross = max(0.0, qty * unit_price)

            # Fallback when qty/unit_price are missing
            if gross == 0.0:
                if 'line_total' in item and item.get('line_total') is not None:
                    net_val = float(item.get('line_total') or 0)
                    gross = max(0.0, net_val + line_discount)
                elif 'amount' in item and item.get('amount') is not None:
                    net_val = float(item.get('amount') or 0)
                    gross = max(0.0, net_val + line_discount)

            # Cap discount at gross
            line_discount = min(line_discount, gross)
            line_net = max(0.0, gross - line_discount)

            gross_total += gross
            line_discount_total += line_discount
            line_net_total += line_net
        except (ValueError, TypeError):
            continue

    return gross_total, line_discount_total, line_net_total


def _sum_bill_level_discounts(bill):
    bill = bill or {}
    total = 0.0
    for field in ['insurance_coverage', 'philhealth_coverage', 'senior_discount', 'pwd_discount']:
        try:
            total += float(bill.get(field) or 0)
        except (ValueError, TypeError):
            continue
    return max(0.0, total)


@ct3_bp.route('/billing/<int:bill_id>/detail')
@login_required
@policy_required(BLUEPRINT_NAME)
def billing_detail(bill_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        b_resp = client.table('billing_records').select('*').eq('id', bill_id).single().execute()
        bill = b_resp.data or {}
        p_resp = client.table('patients').select('*').eq('id', bill.get('patient_id')).single().execute()
        patient = p_resp.data or {}
        line_items, _ = _get_billing_line_items(client, bill_id)
        gross_total, line_discount_total, _ = _sum_billing_line_items_totals(client, bill_id)
        bill_level_discount_total = _sum_bill_level_discounts(bill)
        discount_base_amount = max(0.0, gross_total - line_discount_total)
        computed_net_amount = max(0.0, discount_base_amount - bill_level_discount_total)

        # Keep detail page display consistent with computed values
        bill['total_amount'] = gross_total
        bill['net_amount'] = computed_net_amount
        hics_stage = _get_hics_workflow_stage(bill)
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('ct3.billing'))
    return render_template('subsystems/core_transaction/ct3/billing_detail.html',
                           bill=bill, patient=patient, line_items=line_items,
                           hics_stage=hics_stage,
                           hics_stage_label=_get_hics_stage_label(hics_stage),
                           hics_common_path=HICS_COMMON_PATH,
                           hics_cash_branch=HICS_CASH_BRANCH,
                           hics_insurance_branch=HICS_INSURANCE_BRANCH,
                           hics_stage_labels=HICS_STAGE_LABELS,
                           line_discount_total=line_discount_total,
                           bill_level_discount_total=bill_level_discount_total,
                           discount_base_amount=discount_base_amount,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/billing/<int:bill_id>/workflow/advance', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def advance_hics_workflow(bill_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can update workflow.', 'danger')
        return redirect(url_for('ct3.billing_detail', bill_id=bill_id))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        bill = client.table('billing_records').select('*').eq('id', bill_id).single().execute().data or {}
        stage = _get_hics_workflow_stage(bill)

        if stage == 'CHECK_ELIGIBILITY_BENEFITS':
            flash('Please choose whether patient has valid insurance.', 'warning')
            return redirect(url_for('ct3.billing_detail', bill_id=bill_id))

        if stage == 'CLAIM_DECISION':
            flash('Please choose claim decision: Approved or Denied.', 'warning')
            return redirect(url_for('ct3.billing_detail', bill_id=bill_id))

        if stage == HICS_WORKFLOW_END:
            flash('Workflow already completed.', 'info')
            return redirect(url_for('ct3.billing_detail', bill_id=bill_id))

        next_stage = HICS_DEFAULT_NEXT.get(stage)
        if not next_stage:
            flash('No next step is configured for this stage.', 'warning')
            return redirect(url_for('ct3.billing_detail', bill_id=bill_id))

        _set_hics_workflow_stage(client, bill_id, next_stage)
        if next_stage == HICS_WORKFLOW_END:
            _mark_bill_paid(client, bill_id)

        flash(f'Workflow moved to: {_get_hics_stage_label(next_stage)}', 'success')
    except Exception as e:
        flash(f'Error updating workflow: {e}', 'danger')

    return redirect(url_for('ct3.billing_detail', bill_id=bill_id))


@ct3_bp.route('/billing/<int:bill_id>/workflow/eligibility', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def set_hics_eligibility(bill_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can update workflow.', 'danger')
        return redirect(url_for('ct3.billing_detail', bill_id=bill_id))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    decision = (request.form.get('has_valid_insurance') or '').strip().lower()
    if decision not in ['yes', 'no']:
        flash('Invalid eligibility decision.', 'danger')
        return redirect(url_for('ct3.billing_detail', bill_id=bill_id))

    try:
        if decision == 'yes':
            # Update both eligibility flag and workflow stage
            try:
                client.table('billing_records').update({
                    'has_valid_insurance': True,
                    'workflow_stage': 'CLAIM_CREATION'
                }).eq('id', bill_id).execute()
            except Exception:
                # Fallback: Update each separately
                _set_hics_eligibility_flag(client, bill_id, True)
                _set_hics_workflow_stage(client, bill_id, 'CLAIM_CREATION')
            
            flash('Eligibility set: valid insurance. Workflow moved to Claim Creation.', 'success')
        else:
            # Update both eligibility flag and workflow stage
            try:
                client.table('billing_records').update({
                    'has_valid_insurance': False,
                    'workflow_stage': 'CONTINUE_TO_PATIENT_PAYMENT'
                }).eq('id', bill_id).execute()
            except Exception:
                # Fallback: Update each separately
                _set_hics_eligibility_flag(client, bill_id, False)
                _set_hics_workflow_stage(client, bill_id, 'CONTINUE_TO_PATIENT_PAYMENT')
            
            flash('Eligibility set: no insurance. Workflow moved to Patient Payment.', 'success')
    except Exception as e:
        flash(f'Error setting eligibility: {e}', 'danger')

    return redirect(url_for('ct3.billing_detail', bill_id=bill_id))


@ct3_bp.route('/billing/<int:bill_id>/workflow/claim-decision', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def set_hics_claim_decision(bill_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can update workflow.', 'danger')
        return redirect(url_for('ct3.billing_detail', bill_id=bill_id))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    decision = (request.form.get('claim_decision') or '').strip().lower()
    if decision not in ['approved', 'denied']:
        flash('Invalid claim decision.', 'danger')
        return redirect(url_for('ct3.billing_detail', bill_id=bill_id))

    try:
        next_stage = 'POST_INSURANCE_PAYMENT' if decision == 'approved' else 'REVIEW_DENIAL'
        
        # Update both claim decision and workflow stage
        try:
            client.table('billing_records').update({
                'claim_decision': decision,
                'claim_last_updated_at': datetime.utcnow().isoformat(),
                'workflow_stage': next_stage
            }).eq('id', bill_id).execute()
        except Exception:
            # Fallback: Just update workflow stage if columns don't exist
            _set_hics_workflow_stage(client, bill_id, next_stage)
        
        flash(f'Claim decision recorded: {decision.title()}. Workflow moved to {_get_hics_stage_label(next_stage)}', 'success')
    except Exception as e:
        flash(f'Error setting claim decision: {e}', 'danger')

    return redirect(url_for('ct3.billing_detail', bill_id=bill_id))


@ct3_bp.route('/billing/<int:bill_id>/add-item', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def add_billing_item(bill_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        # First, verify the bill exists in any of the possible tables
        bill_exists = False
        bill_record = None
        
        # Try billing_records first
        try:
            response = client.table('billing_records').select('id').eq('id', bill_id).single().execute()
            bill_record = response.data
            bill_exists = True
        except Exception:
            pass
        
        # If not found, try "billing" table (for FK constraint)
        if not bill_exists:
            try:
                response = client.table('billing').select('id').eq('id', bill_id).single().execute()
                bill_record = response.data
                bill_exists = True
            except Exception:
                pass
        
        if not bill_exists:
            flash(f'Error: Bill #{bill_id} not found in billing records.', 'danger')
            return redirect(url_for('ct3.billing_detail', bill_id=bill_id))

        # Now proceed with adding the line item
        qty = int(request.form.get('quantity', 1))
        unit_price = float(request.form.get('unit_price', 0))
        discount = float(request.form.get('discount', 0))
        
        # Validate and cap discount
        subtotal = qty * unit_price
        if discount > subtotal:
            flash(f'Warning: Discount (₱{discount:.2f}) exceeds subtotal (₱{subtotal:.2f}). Capping discount to subtotal.', 'warning')
            discount = subtotal
        
        if discount < 0:
            discount = 0
        
        # Ensure line_total is never negative
        line_total = max(0, subtotal - discount)
        
        base_data = {
            'description': request.form.get('description', ''),
            'quantity': qty,
            'unit_price': unit_price,
            'discount': discount,
            'line_total': line_total,
        }
        source_module = request.form.get('source_module', 'CT3')

        payload_candidates = [
            {**base_data, 'source_module': source_module, 'billing_id': bill_id},
            {**base_data, 'source_module': source_module, 'bill_id': bill_id},
            {**base_data, 'billing_id': bill_id},
            {**base_data, 'bill_id': bill_id},
        ]

        last_error = None
        inserted = False
        for payload in payload_candidates:
            try:
                client.table('billing_line_items').insert(payload).execute()
                inserted = True
                break
            except Exception as insert_error:
                last_error = insert_error

        if not inserted:
            raise last_error if last_error else Exception('Failed to insert billing line item.')

        # Recompute bill totals from line items
        gross_total, line_discount_total, _ = _sum_billing_line_items_totals(client, bill_id)
        
        try:
            # Get current bill to fetch existing discounts
            current_bill = client.table('billing_records').select('*').eq('id', bill_id).single().execute().data or {}
            existing_cols = set(current_bill.keys())
            
            # Sum bill-level discounts
            bill_level_discounts = 0.0
            discount_fields = ['insurance_coverage', 'philhealth_coverage', 'senior_discount', 'pwd_discount']
            for field in discount_fields:
                if field in existing_cols:
                    bill_level_discounts += float(current_bill.get(field, 0) or 0)
            
            # Net = gross - line-item discounts - bill-level discounts
            net_amount = max(0, gross_total - line_discount_total - bill_level_discounts)
            
            # Update both total and net amount
            update_payload = {'total_amount': gross_total}
            if 'net_amount' in existing_cols:
                update_payload['net_amount'] = net_amount
            
            client.table('billing_records').update(update_payload).eq('id', bill_id).execute()
        except Exception:
            # If update fails, try just updating total
            try:
                client.table('billing_records').update({'total_amount': gross_total}).eq('id', bill_id).execute()
            except Exception:
                flash(f'Warning: Line item added but total not updated. (Calculated: ₱{gross_total:.2f})', 'warning')
        
        flash('Line item added successfully.', 'success')
    except Exception as e:
        flash(f'Error adding line item: {str(e)}', 'danger')
    return redirect(url_for('ct3.billing_detail', bill_id=bill_id))


@ct3_bp.route('/billing/<int:bill_id>/remove-item/<int:item_id>', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def remove_billing_item(bill_id, item_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        client.table('billing_line_items').delete().eq('id', item_id).execute()

        # Recompute bill totals from remaining items
        gross_total, line_discount_total, _ = _sum_billing_line_items_totals(client, bill_id)
        
        try:
            # Get current bill to fetch existing discounts
            current_bill = client.table('billing_records').select('*').eq('id', bill_id).single().execute().data or {}
            existing_cols = set(current_bill.keys())
            
            # Sum bill-level discounts
            bill_level_discounts = 0.0
            discount_fields = ['insurance_coverage', 'philhealth_coverage', 'senior_discount', 'pwd_discount']
            for field in discount_fields:
                if field in existing_cols:
                    bill_level_discounts += float(current_bill.get(field, 0) or 0)
            
            # Net = gross - line-item discounts - bill-level discounts
            net_amount = max(0, gross_total - line_discount_total - bill_level_discounts)
            
            # Update both total and net amount
            update_payload = {'total_amount': gross_total}
            if 'net_amount' in existing_cols:
                update_payload['net_amount'] = net_amount
            
            client.table('billing_records').update(update_payload).eq('id', bill_id).execute()
            
            removed_msg = f'Item removed. Updated total: ₱{gross_total:.2f}'
            if (line_discount_total + bill_level_discounts) > 0:
                removed_msg += f' (Net: ₱{net_amount:.2f})'
            flash(removed_msg, 'success')
        except Exception as e_update:
            # If update fails, try just updating total
            try:
                client.table('billing_records').update({'total_amount': gross_total}).eq('id', bill_id).execute()
                flash(f'Item removed. Total recalculated: ₱{gross_total:.2f}', 'success')
            except Exception:
                flash(f'Item removed but total update failed. (Calculated: ₱{gross_total:.2f})', 'warning')
    except Exception as e:
        flash(f'Error removing item: {str(e)}', 'danger')
    return redirect(url_for('ct3.billing_detail', bill_id=bill_id))


@ct3_bp.route('/billing/<int:bill_id>/apply-discount', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def apply_billing_discount(bill_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can apply discounts.', 'danger')
        return redirect(url_for('ct3.billing_detail', bill_id=bill_id))
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        current_bill = client.table('billing_records').select('*').eq('id', bill_id).single().execute().data or {}
        existing_cols = set(current_bill.keys())

        update_data = {}
        
        # Update text fields (insurance provider, policy, payment method)
        for field in ['insurance_provider', 'insurance_policy_no', 'payment_method']:
            val = request.form.get(field, '').strip()
            if val and field in existing_cols:
                update_data[field] = val
        
        # Compute available base for bill-level discounts (after line-item discounts)
        gross_total, line_discount_total, _ = _sum_billing_line_items_totals(client, bill_id)
        discount_base_amount = max(0.0, gross_total - line_discount_total)

        # Update numeric discount fields - ONLY if they exist in schema
        discount_fields = ['insurance_coverage', 'philhealth_coverage', 'senior_discount', 'pwd_discount']
        total_discounts = 0.0
        requested_discounts = {}

        for field in discount_fields:
            try:
                val = float(request.form.get(field, 0) or 0)
                requested_discounts[field] = max(0.0, val)
            except ValueError:
                requested_discounts[field] = 0.0

        # Apply caps so overall bill-level discounts never exceed available amount
        remaining = discount_base_amount
        capped_any = False
        for field in discount_fields:
            requested = requested_discounts.get(field, 0.0)
            applied = min(requested, remaining)
            if requested > applied:
                capped_any = True
            remaining = max(0.0, remaining - applied)

            if field in existing_cols:
                update_data[field] = applied
            total_discounts += applied

        # Recompute net based on gross, line-item discounts, and applied bill-level discounts
        net_amount = max(0, gross_total - line_discount_total - total_discounts)

        # Keep total_amount aligned with gross line-item subtotal
        if 'total_amount' in existing_cols:
            update_data['total_amount'] = gross_total
        elif 'amount' in existing_cols:
            update_data['amount'] = gross_total
        
        # Only update net_amount if it exists in schema
        if 'net_amount' in existing_cols:
            update_data['net_amount'] = net_amount

        # Execute update
        if update_data:
            response = client.table('billing_records').update(update_data).eq('id', bill_id).execute()
            if response.data:
                if capped_any:
                    flash('Some discount values exceeded the remaining bill amount and were capped automatically.', 'warning')
                flash(f'Discounts applied successfully. Net Amount: ₱{net_amount:.2f}', 'success')
            else:
                flash('Discounts saved.', 'success')
        else:
            flash('No compatible discount fields found in schema. Please ensure insurance_coverage, philhealth_coverage, senior_discount, or pwd_discount columns exist.', 'warning')
    except Exception as e:
        flash(f'Error applying discounts: {str(e)}', 'danger')
    
    return redirect(url_for('ct3.billing_detail', bill_id=bill_id))


@ct3_bp.route('/billing/<int:bill_id>/update-amount', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def update_billing_amount(bill_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can edit bill amounts.', 'danger')
        return redirect(url_for('ct3.billing_detail', bill_id=bill_id))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        new_total = float(request.form.get('total_amount', 0) or 0)
        if new_total < 0:
            raise ValueError('Amount cannot be negative.')

        b = client.table('billing_records').select('*').eq('id', bill_id).single().execute().data or {}
        existing_cols = set(b.keys())

        discounts = (
            float(b.get('insurance_coverage') or 0)
            + float(b.get('philhealth_coverage') or 0)
            + float(b.get('senior_discount') or 0)
            + float(b.get('pwd_discount') or 0)
        )

        amount_col = 'total_amount' if 'total_amount' in existing_cols else 'amount'
        update_data = {amount_col: new_total}
        if 'net_amount' in existing_cols:
            update_data['net_amount'] = max(0, new_total - discounts)

        client.table('billing_records').update(update_data).eq('id', bill_id).execute()
        flash('Billing amount updated successfully.', 'success')
    except Exception as e:
        flash(f'Error updating amount: {e}', 'danger')

    return redirect(url_for('ct3.billing_detail', bill_id=bill_id))


@ct3_bp.route('/billing/<int:bill_id>/print')
@login_required
def billing_print(bill_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        b_resp = client.table('billing_records').select('*').eq('id', bill_id).single().execute()
        bill = b_resp.data or {}
        p_resp = client.table('patients').select('*').eq('id', bill.get('patient_id')).single().execute()
        patient = p_resp.data or {}
        line_items, _ = _get_billing_line_items(client, bill_id)
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('ct3.billing'))
    return render_template('subsystems/core_transaction/ct3/billing_print.html',
                           bill=bill, patient=patient, line_items=line_items, now=datetime.utcnow())


@ct3_bp.route('/billing/summary')
@login_required
@policy_required(BLUEPRINT_NAME)
def billing_summary():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        resp = client.table('billing_records').select('*').execute()
        all_bills = resp.data or []
        total_billed    = sum(float(b.get('total_amount', 0)) for b in all_bills)
        total_collected = sum(float(b.get('total_amount', 0)) for b in all_bills if b.get('status') == 'Paid')
        total_outstanding = total_billed - total_collected
        by_method = {}
        for b in all_bills:
            m = b.get('payment_method') or 'Cash'
            if b.get('status') == 'Paid':
                by_method[m] = by_method.get(m, 0) + float(b.get('total_amount', 0))
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        all_bills = []
        total_billed = total_collected = total_outstanding = 0
        by_method = {}
    return render_template('subsystems/core_transaction/ct3/billing_summary.html',
                           all_bills=all_bills,
                           total_billed=total_billed,
                           total_collected=total_collected,
                           total_outstanding=total_outstanding,
                           by_method=by_method,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 9 — REPORTING CENTER
# ─────────────────────────────────────────────────────────────────────────────

@ct3_bp.route('/reports')
@login_required
@policy_required(BLUEPRINT_NAME)
def reports_hub():
    return render_template('subsystems/core_transaction/ct3/reports_hub.html',
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/reports/census')
@login_required
@policy_required(BLUEPRINT_NAME)
def report_census():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    date_from = request.args.get('date_from', '')
    date_to   = request.args.get('date_to', '')
    try:
        resp = client.table('patients').select('*').execute()
        patients = resp.data or []
        beds_resp = client.table('beds').select('*').execute()
        beds = beds_resp.data or []
        total_beds      = len(beds)
        occupied        = sum(1 for b in beds if b.get('status') == 'Occupied')
        occupancy_rate  = round(occupied / total_beds * 100, 1) if total_beds else 0
        status_dist = {}
        for p in patients:
            s = p.get('current_status') or 'Registered'
            status_dist[s] = status_dist.get(s, 0) + 1
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        patients = []
        beds = []
        total_beds = occupied = occupancy_rate = 0
        status_dist = {}
    return render_template('subsystems/core_transaction/ct3/report_census.html',
                           patients=patients, beds=beds,
                           total_beds=total_beds, occupied=occupied,
                           occupancy_rate=occupancy_rate, status_dist=status_dist,
                           status_colors=STATUS_COLORS,
                           date_from=date_from, date_to=date_to,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/reports/admissions')
@login_required
@policy_required(BLUEPRINT_NAME)
def report_admissions():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    date_from = request.args.get('date_from', '')
    date_to   = request.args.get('date_to', '')
    try:
        q = client.table('patient_status_history').select('*').eq('new_status', 'Admitted')
        if date_from:
            q = q.gte('changed_at', date_from)
        if date_to:
            q = q.lte('changed_at', date_to + 'T23:59:59')
        resp = q.order('changed_at', desc=True).execute()
        admissions = resp.data or []
        patient_ids = list({r['patient_id'] for r in admissions if r.get('patient_id')})
        patients_map = {}
        if patient_ids:
            pr = client.table('patients').select('id, first_name, last_name, patient_id_alt, gender').in_('id', patient_ids).execute()
            patients_map = {p['id']: p for p in (pr.data or [])}
        for r in admissions:
            r['patient_obj'] = patients_map.get(r.get('patient_id'))
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        admissions = []
    return render_template('subsystems/core_transaction/ct3/report_admissions.html',
                           admissions=admissions, date_from=date_from, date_to=date_to,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/reports/discharges')
@login_required
@policy_required(BLUEPRINT_NAME)
def report_discharges():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    date_from = request.args.get('date_from', '')
    date_to   = request.args.get('date_to', '')
    try:
        q = client.table('patients').select('*').eq('current_status', 'Discharged')
        if date_from:
            q = q.gte('discharge_date', date_from)
        if date_to:
            q = q.lte('discharge_date', date_to + 'T23:59:59')
        resp = q.order('discharge_date', desc=True).execute()
        discharged = resp.data or []
        # Calculate LOS
        for p in discharged:
            try:
                adm = datetime.fromisoformat(p['admission_date'][:19]) if p.get('admission_date') else None
                dis = datetime.fromisoformat(p['discharge_date'][:19]) if p.get('discharge_date') else datetime.utcnow()
                p['los_days'] = (dis - adm).days if adm else None
            except Exception:
                p['los_days'] = None
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        discharged = []
    return render_template('subsystems/core_transaction/ct3/report_discharges.html',
                           discharged=discharged, date_from=date_from, date_to=date_to,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/reports/billing')
@login_required
@policy_required(BLUEPRINT_NAME)
def report_billing():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    date_from = request.args.get('date_from', '')
    date_to   = request.args.get('date_to', '')
    try:
        q = client.table('billing_records').select('*')
        if date_from:
            q = q.gte('created_at', date_from)
        if date_to:
            q = q.lte('created_at', date_to + 'T23:59:59')
        resp = q.order('created_at', desc=True).execute()
        bills = resp.data or []
        patient_ids = list({b['patient_id'] for b in bills if b.get('patient_id')})
        patients_map = {}
        if patient_ids:
            pr = client.table('patients').select('id, first_name, last_name, patient_id_alt').in_('id', patient_ids).execute()
            patients_map = {p['id']: p for p in (pr.data or [])}
        for b in bills:
            b['patient_obj'] = patients_map.get(b.get('patient_id'))
        total_billed = sum(float(b.get('total_amount', 0)) for b in bills)
        total_paid   = sum(float(b.get('total_amount', 0)) for b in bills if b.get('status') == 'Paid')
        total_unpaid = total_billed - total_paid
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        bills = []
        total_billed = total_paid = total_unpaid = 0
    return render_template('subsystems/core_transaction/ct3/report_billing.html',
                           bills=bills, total_billed=total_billed,
                           total_paid=total_paid, total_unpaid=total_unpaid,
                           date_from=date_from, date_to=date_to,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/reports/mortality')
@login_required
@policy_required(BLUEPRINT_NAME)
def report_mortality():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    date_from = request.args.get('date_from', '')
    date_to   = request.args.get('date_to', '')
    try:
        q = client.table('patient_status_history').select('*').eq('new_status', 'Deceased')
        if date_from:
            q = q.gte('changed_at', date_from)
        if date_to:
            q = q.lte('changed_at', date_to + 'T23:59:59')
        resp = q.order('changed_at', desc=True).execute()
        records = resp.data or []
        patient_ids = list({r['patient_id'] for r in records if r.get('patient_id')})
        patients_map = {}
        if patient_ids:
            pr = client.table('patients').select('id, first_name, last_name, patient_id_alt, gender').in_('id', patient_ids).execute()
            patients_map = {p['id']: p for p in (pr.data or [])}
        for r in records:
            r['patient_obj'] = patients_map.get(r.get('patient_id'))
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        records = []
    return render_template('subsystems/core_transaction/ct3/report_mortality.html',
                           records=records, date_from=date_from, date_to=date_to,
                           now=datetime.utcnow(),
                           subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)


@ct3_bp.route('/reports/generate', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def generate_report():
    report_type = request.form.get('report_type', 'census')
    date_from = request.form.get('date_from', '')
    date_to   = request.form.get('date_to', '')
    routes_map = {
        'census':     'ct3.report_census',
        'admissions': 'ct3.report_admissions',
        'discharges': 'ct3.report_discharges',
        'billing':    'ct3.report_billing',
        'mortality':  'ct3.report_mortality',
    }
    target_route = routes_map.get(report_type, 'ct3.reports_hub')
    return redirect(url_for(target_route, date_from=date_from, date_to=date_to))


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 10 — ANALYTICS DASHBOARD (enhanced)
# ─────────────────────────────────────────────────────────────────────────────

@ct3_bp.route('/analytics/api/status-distribution')
@login_required
def analytics_status_distribution():
    from flask import jsonify
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        resp = client.table('patients').select('current_status').execute()
        counts = {}
        for p in (resp.data or []):
            s = p.get('current_status') or 'Registered'
            counts[s] = counts.get(s, 0) + 1
        return jsonify({'labels': list(counts.keys()), 'values': list(counts.values()),
                        'colors': [STATUS_COLORS.get(s, '#6B7280') for s in counts]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ct3_bp.route('/analytics/api/admissions-trend')
@login_required
def analytics_admissions_trend():
    from flask import jsonify
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        # Last 30 days admissions
        from datetime import timedelta
        start = (datetime.utcnow() - timedelta(days=29)).strftime('%Y-%m-%d')
        resp = client.table('patient_status_history').select('changed_at').eq('new_status', 'Admitted').gte('changed_at', start).execute()
        day_counts = {}
        for r in (resp.data or []):
            day = r['changed_at'][:10]
            day_counts[day] = day_counts.get(day, 0) + 1
        # Build last 30 days consistent range
        from datetime import timedelta
        labels, values = [], []
        for i in range(29, -1, -1):
            d = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
            labels.append(d)
            values.append(day_counts.get(d, 0))
        return jsonify({'labels': labels, 'values': values})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ct3_bp.route('/analytics/api/revenue-trend')
@login_required
def analytics_revenue_trend():
    from flask import jsonify
    from utils.supabase_client import get_supabase_client
    from datetime import timedelta
    client = get_supabase_client()
    try:
        start = (datetime.utcnow() - timedelta(days=29)).strftime('%Y-%m-%d')
        resp = client.table('billing_records').select('created_at, total_amount, status').gte('created_at', start).execute()
        day_revenue = {}
        for r in (resp.data or []):
            if r.get('status') == 'Paid':
                day = r['created_at'][:10]
                day_revenue[day] = day_revenue.get(day, 0) + float(r.get('total_amount', 0))
        labels, values = [], []
        for i in range(29, -1, -1):
            d = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
            labels.append(d)
            values.append(round(day_revenue.get(d, 0), 2))
        return jsonify({'labels': labels, 'values': values})
    except Exception as e:
        return jsonify({'error': str(e)}), 500



