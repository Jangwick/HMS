from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, get_supabase_client, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from datetime import datetime

patient_bp = Blueprint('patient', __name__)

@patient_bp.route('/')
def landing():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch some live stats for the interactive features
    stats = {
        'occupied_beds': 0,
        'total_beds': 0,
        'er_wait_time': '12 mins'
    }
    
    try:
        beds_resp = client.table('beds').select('status', count='exact').execute()
        if beds_resp.data:
            stats['total_beds'] = len(beds_resp.data)
            stats['occupied_beds'] = sum(1 for b in beds_resp.data if b['status'] == 'Occupied')
    except:
        pass
        
    return render_template('portal/patient_landing.html', stats=stats)

@patient_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated and current_user.role == 'Patient':
        return redirect(url_for('patient.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Patients are in a specific 'patient' subsystem to isolate them
        user = User.get_by_username(username, 'patient')
        
        if user and user.check_password(password):
            if user.status != 'Active':
                flash('Your account is awaiting activation.', 'info')
                return render_template('portal/patient_login.html')
            
            if login_user(user):
                register_successful_login(subsystem='patient')
                return redirect(url_for('patient.dashboard'))
        
        flash('Invalid credentials.', 'danger')
        register_failed_attempt(subsystem='patient')
        
    return render_template('portal/patient_login.html')

@patient_bp.route('/dashboard')
@login_required
def dashboard():
    if current_user.role != 'Patient' or not current_user.patient_id:
        flash('Access restricted to registered patients.', 'warning')
        return redirect(url_for('portal.index'))
    
    client = get_supabase_client()
    patient_id = current_user.patient_id
    
    try:
        # 1. Fetch Patient Info & Stay (CT1)
        patient_resp = client.table('patients').select('*').eq('id', patient_id).single().execute()
        patient = patient_resp.data
        
        bed_resp = client.table('beds').select('*').eq('patient_id', patient_id).execute()
        bed_info = bed_resp.data[0] if bed_resp.data else None
        
        # 2. Fetch Clinical Data (CT2)
        labs_resp = client.table('lab_orders').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        prescriptions_resp = client.table('prescriptions').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        
        # 3. Fetch Billing (CT3 / Financials)
        billing_resp = client.table('billing_records').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        total_due = sum(float(b['total_amount']) for b in billing_resp.data if b['status'] != 'Paid') if billing_resp.data else 0.0
        
        # 4. Fetch Appointments (CT1)
        appt_resp = client.table('appointments').select('*, users(username)').eq('patient_id', patient_id).order('appointment_date').execute()
        
    except Exception as e:
        import traceback
        print(f"Error fetching care hub data for patient {patient_id}: {e}")
        traceback.print_exc()
        flash('Some health data could not be synchronized. Please contact support if this persists.', 'warning')
        patient = {'first_name': 'Patient', 'last_name': 'User'} # Fallback to prevent crash
        bed_info = None
        labs_resp = type('obj', (object,), {'data': []})
        prescriptions_resp = type('obj', (object,), {'data': []})
        billing_resp = type('obj', (object,), {'data': []})
        appt_resp = type('obj', (object,), {'data': []})
        total_due = 0.0

    return render_template('portal/patient_dashboard.html',
                           patient=patient,
                           bed_info=bed_info,
                           labs=labs_resp.data,
                           prescriptions=prescriptions_resp.data,
                           bills=billing_resp.data,
                           appointments=appt_resp.data,
                           total_due=total_due)

@patient_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('patient.login'))
