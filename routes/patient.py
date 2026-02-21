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
    
    next_page = request.args.get('next')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        next_page = request.form.get('next')
        
        # Patients are in a specific 'patient' subsystem to isolate them
        user = User.get_by_username(username, 'patient')
        
        if user and user.check_password(password):
            if user.status != 'Active':
                flash('Your account is awaiting activation.', 'info')
                return render_template('portal/patient_login.html', next=next_page)
            
            if login_user(user):
                register_successful_login(subsystem='patient')
                return redirect(next_page if next_page else url_for('patient.dashboard'))
        
        flash('Invalid credentials.', 'danger')
        register_failed_attempt(subsystem='patient')
        
    return render_template('portal/patient_login.html', next=next_page)

@patient_bp.route('/dashboard')
@login_required
def dashboard():
    if current_user.role != 'Patient' or not current_user.patient_id:
        flash('Access restricted to registered patients.', 'warning')
        return redirect(url_for('portal.index'))
    
    client = get_supabase_client()
    patient_id = current_user.patient_id
    
    # Initialize data structures
    data = {
        'patient': None,
        'bed_info': None,
        'labs': [],
        'radiology': [],
        'prescriptions': [],
        'bills': [],
        'appointments': [],
        'vitals': None,
        'diet': None,
        'meals': [],
        'total_due': 0.0,
        'timeline': []
    }
    
    try:
        # 1. Fetch Patient Info
        patient_resp = client.table('patients').select('*').eq('id', patient_id).single().execute()
        data['patient'] = patient_resp.data
        
        # 2. Fetch Stay Info (CT1/CT3)
        bed_resp = client.table('beds').select('*').eq('patient_id', patient_id).execute()
        data['bed_info'] = bed_resp.data[0] if bed_resp.data else None
        
        # 3. Fetch Clinical Data (CT2)
        labs_resp = client.table('lab_orders').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['labs'] = labs_resp.data
        
        radio_resp = client.table('radiology_orders').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['radiology'] = radio_resp.data
        
        prescriptions_resp = client.table('prescriptions').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['prescriptions'] = prescriptions_resp.data
        
        # 4. Fetch Vitals & Medical Records (CT3)
        records_resp = client.table('medical_records').select('*').eq('patient_id', patient_id).order('visit_date', desc=True).execute()
        if records_resp.data:
            # Find most recent vitals
            for record in records_resp.data:
                if record.get('vitals'):
                    data['vitals'] = record['vitals']
                    break
        
        # 5. Fetch Nutrition (CT2 - DNMS)
        diet_resp = client.table('diet_plans').select('*').eq('patient_id', patient_id).eq('status', 'Active').order('created_at', desc=True).execute()
        data['diet'] = diet_resp.data[0] if diet_resp.data else None
        
        meals_resp = client.table('meal_tracking').select('*').eq('patient_id', patient_id).order('created_at', desc=True).limit(5).execute()
        data['meals'] = meals_resp.data
        
        # 6. Fetch Billing (CT3 / Financials)
        billing_resp = client.table('billing_records').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['bills'] = billing_resp.data
        data['total_due'] = sum(float(b['total_amount']) for b in billing_resp.data if b['status'] != 'Paid') if billing_resp.data else 0.0
        
        # 7. Fetch Appointments (CT1)
        appt_resp = client.table('appointments').select('*, users(full_name)').eq('patient_id', patient_id).order('appointment_date').execute()
        data['appointments'] = appt_resp.data

        # 8. Construct Unified Timeline
        # Combine different events into a single sorted list
        timeline = []
        for lab in data['labs']:
            timeline.append({'type': 'lab', 'title': lab['test_name'], 'date': lab['created_at'], 'status': lab['status']})
        for rad in data['radiology']:
            timeline.append({'type': 'radiology', 'title': rad['imaging_type'], 'date': rad['created_at'], 'status': rad['status']})
        for appt in data['appointments']:
            timeline.append({'type': 'appointment', 'title': f"Consultation: {appt['type']}", 'date': appt['appointment_date'], 'status': appt['status']})
        
        # Sort timeline by date descending
        data['timeline'] = sorted(timeline, key=lambda x: x['date'], reverse=True)[:10]

    except Exception as e:
        import traceback
        print(f"Error fetching unified care data: {e}")
        traceback.print_exc()
        flash('Data synchronization partial. Some modules may be unavailable.', 'warning')
        if not data['patient']:
            data['patient'] = {'first_name': 'Patient', 'last_name': 'User'}

    return render_template('portal/patient_dashboard.html', **data)

@patient_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('patient.login'))
