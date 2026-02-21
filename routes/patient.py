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
    if current_user.is_authenticated:
        return redirect(url_for('patient.dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        next_url = request.form.get('next')
        
        user = User.get_by_username(username, 'patient')
        if user and user.check_password(password):
            if login_user(user):
                flash('Welcome back to the HMS Patient Portal.', 'success')
                return redirect(next_url or url_for('patient.dashboard'))
        
        flash('Invalid credentials. Please try again.', 'danger')
        
    return render_template('portal/patient_login.html', next=request.args.get('next'))

@patient_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('patient.dashboard'))
        
    if request.method == 'POST':
        from utils.hms_models import Patient
        
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        dob = request.form.get('dob')
        gender = request.form.get('gender')
        contact_number = request.form.get('contact_number')
        address = request.form.get('address')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('portal/patient_register.html')
            
        # Check if username exists
        if User.get_by_username(username):
            flash('Username already exists. Please choose another.', 'danger')
            return render_template('portal/patient_register.html')
            
        try:
            # 1. Create Patient record
            patient_data = {
                'first_name': first_name,
                'last_name': last_name,
                'dob': dob,
                'gender': gender,
                'contact_number': contact_number,
                'address': address
            }
            patient = Patient.create(patient_data)
            
            if patient:
                # 2. Create User account
                User.create(
                    username=username,
                    email=f"{username.lower()}@hms-patient.com",
                    password=password,
                    subsystem='patient',
                    department='PATIENT_PORTAL',
                    role='Patient',
                    status='Active',
                    full_name=f"{first_name} {last_name}",
                    patient_id=patient.id,
                    skip_validation=True
                )
                
                # 3. Notify CT1 (Patient Access) of new registration
                from utils.hms_models import Notification
                Notification.create(
                    subsystem='ct1',
                    title="New Digital Registration",
                    message=f"A new patient ({first_name} {last_name}) has registered via the portal and is awaiting clinical onboarding.",
                    n_type="info",
                    sender_subsystem='patient',
                    target_url=url_for('ct1.list_patients', _external=True)
                )
                
                flash('Account created successfully! You can now log in.', 'success')
                return redirect(url_for('patient.login'))
            else:
                flash('Failed to create patient record. Please contact support.', 'danger')
        except Exception as e:
            flash(f'Registration error: {str(e)}', 'danger')
            
    return render_template('portal/patient_register.html')

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
        
        # 2. Fetch Stay Info (CT1/CT3) - Use JSONB workaround since beds table has no patient_id column
        patient_insurance = data['patient'].get('insurance_info') or {}
        current_bed_id = patient_insurance.get('current_bed_id')
        if current_bed_id:
            bed_resp = client.table('beds').select('*').eq('id', int(current_bed_id)).execute()
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

@patient_bp.route('/journey')
@login_required
def journey():
    if current_user.role != 'Patient' or not current_user.patient_id:
        flash('Access restricted to registered patients.', 'warning')
        return redirect(url_for('portal.index'))
    
    client = get_supabase_client()
    patient_id = current_user.patient_id
    
    data = {
        'patient': None,
        'labs': [],
        'radiology': [],
        'medical_records': [],
        'appointments': [],
        'prescriptions': [],
        'bills': [],
        'timeline': []
    }
    
    try:
        # Fetch Patient Info
        patient_resp = client.table('patients').select('*').eq('id', patient_id).single().execute()
        data['patient'] = patient_resp.data
        
        # Fetch detailed clinical data
        labs_resp = client.table('lab_orders').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['labs'] = labs_resp.data
        
        radio_resp = client.table('radiology_orders').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['radiology'] = radio_resp.data
        
        records_resp = client.table('medical_records').select('*, users(full_name)').eq('patient_id', patient_id).order('visit_date', desc=True).execute()
        data['medical_records'] = records_resp.data
        
        appt_resp = client.table('appointments').select('*, users(full_name)').eq('patient_id', patient_id).order('appointment_date', desc=True).execute()
        data['appointments'] = appt_resp.data

        prescriptions_resp = client.table('prescriptions').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['prescriptions'] = prescriptions_resp.data

        billing_resp = client.table('billing_records').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['bills'] = billing_resp.data

        # Construct Unified Timeline for Journey (More detailed)
        timeline = []
        for lab in data['labs']:
            timeline.append({
                'type': 'lab',
                'title': lab['test_name'],
                'date': lab['created_at'],
                'status': lab['status'],
                'details': lab.get('results'),
                'icon': 'bi-microscope',
                'category': 'Diagnostics'
            })
        for rad in data['radiology']:
            timeline.append({
                'type': 'radiology',
                'title': rad['imaging_type'],
                'date': rad['created_at'],
                'status': rad['status'],
                'details': rad.get('findings'),
                'icon': 'bi-camera',
                'category': 'Imaging'
            })
        for record in data['medical_records']:
            timeline.append({
                'type': 'medical_record',
                'title': f"Clinic Visit: {record['diagnosis']}",
                'date': record['visit_date'],
                'status': 'Finalized',
                'details': record.get('treatment'),
                'doctor': record['users']['full_name'] if record.get('users') else 'Attending Physician',
                'icon': 'bi-file-earmark-medical',
                'category': 'Clinical Visit'
            })
        for appt in data['appointments']:
            timeline.append({
                'type': 'appointment',
                'title': f"Consultation: {appt['type']}",
                'date': appt['appointment_date'],
                'status': appt['status'],
                'doctor': appt['users']['full_name'] if appt.get('users') else 'Staff',
                'icon': 'bi-calendar2-check',
                'category': 'Schedule'
            })
        for rx in data['prescriptions']:
            timeline.append({
                'type': 'prescription',
                'title': f"Prescription: {rx['medication_name']}",
                'date': rx['created_at'],
                'status': rx['status'],
                'details': f"Dosage: {rx['dosage']} - {rx['instructions']}",
                'icon': 'bi-capsule',
                'category': 'Medication'
            })
        for bill in data['bills']:
            timeline.append({
                'type': 'billing',
                'title': f"Billing: {bill['description'] or 'Service Charge'}",
                'date': bill['created_at'],
                'status': bill['status'],
                'details': f"Amount: ${bill['total_amount']}",
                'icon': 'bi-wallet2',
                'category': 'Financial'
            })
        
        data['timeline'] = sorted(timeline, key=lambda x: x['date'], reverse=True)

    except Exception as e:
        print(f"Error fetching journey data: {e}")
        flash('Some journey details could not be synchronized.', 'warning')

    return render_template('portal/patient_journey.html', **data)

@patient_bp.route('/stay')
@login_required
def stay():
    if current_user.role != 'Patient' or not current_user.patient_id:
        flash('Access restricted to registered patients.', 'warning')
        return redirect(url_for('portal.index'))
    
    client = get_supabase_client()
    patient_id = current_user.patient_id
    
    data = {
        'patient': None,
        'bed_info': None,
        'diet': None,
        'meals': [],
        'assessments': []
    }
    
    try:
        # Fetch Patient Info
        patient_resp = client.table('patients').select('*').eq('id', patient_id).single().execute()
        data['patient'] = patient_resp.data
        
        # Fetch Bed Info - Use JSONB workaround since beds table has no patient_id column
        patient_insurance = data['patient'].get('insurance_info') or {}
        current_bed_id = patient_insurance.get('current_bed_id')
        if current_bed_id:
            bed_resp = client.table('beds').select('*').eq('id', int(current_bed_id)).execute()
            data['bed_info'] = bed_resp.data[0] if bed_resp.data else None
        
        # Fetch Nutrition Info
        diet_resp = client.table('diet_plans').select('*, users(full_name)').eq('patient_id', patient_id).eq('status', 'Active').order('created_at', desc=True).execute()
        data['diet'] = diet_resp.data[0] if diet_resp.data else None
        
        meals_resp = client.table('meal_tracking').select('*, users(full_name)').eq('patient_id', patient_id).order('created_at', desc=True).limit(10).execute()
        data['meals'] = meals_resp.data
        
        assess_resp = client.table('nutritional_assessments').select('*').eq('patient_id', patient_id).order('created_at', desc=True).limit(5).execute()
        data['assessments'] = assess_resp.data

    except Exception as e:
        print(f"Error fetching stay data: {e}")
        flash('Some facility details could not be synchronized.', 'warning')

    return render_template('portal/patient_stay.html', **data)

@patient_bp.route('/inventory')
@login_required
def inventory():
    if current_user.role != 'Patient' or not current_user.patient_id:
        flash('Access restricted to registered patients.', 'warning')
        return redirect(url_for('portal.index'))
    
    client = get_supabase_client()
    patient_id = current_user.patient_id
    
    data = {
        'patient': None,
        'active_prescriptions': [],
        'past_prescriptions': [],
        'dispensing_history': []
    }
    
    try:
        patient_resp = client.table('patients').select('*').eq('id', patient_id).single().execute()
        data['patient'] = patient_resp.data
        
        rx_resp = client.table('prescriptions').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        
        if rx_resp.data:
            for rx in rx_resp.data:
                if rx.get('status') in ['Active', 'Pending']:
                    data['active_prescriptions'].append(rx)
                else:
                    data['past_prescriptions'].append(rx)

        dispense_resp = client.table('dispensing_history').select('*, inventory(item_name)').eq('patient_id', patient_id).order('dispensed_at', desc=True).limit(20).execute()
        data['dispensing_history'] = dispense_resp.data

    except Exception as e:
        print(f"Error fetching inventory data: {e}")
        flash('Some pharmacy details could not be synchronized.', 'warning')

    return render_template('portal/patient_inventory.html', **data)

@patient_bp.route('/ledger')
@login_required
def ledger():
    if current_user.role != 'Patient' or not current_user.patient_id:
        flash('Access restricted to registered patients.', 'warning')
        return redirect(url_for('portal.index'))
    
    client = get_supabase_client()
    patient_id = current_user.patient_id
    
    data = {
        'patient': None,
        'bills': [],
        'total_due': 0.0,
        'recent_payments': []
    }
    
    try:
        patient_resp = client.table('patients').select('*').eq('id', patient_id).single().execute()
        data['patient'] = patient_resp.data
        
        # Fetch Billing Records
        billing_resp = client.table('billing_records').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['bills'] = billing_resp.data
        
        if billing_resp.data:
            data['total_due'] = sum(float(b['total_amount']) for b in billing_resp.data if b.get('status') != 'Paid')
            # Assuming 'Paid' records act as recent payments for this view
            data['recent_payments'] = [b for b in billing_resp.data if b.get('status') == 'Paid']

    except Exception as e:
        print(f"Error fetching ledger data: {e}")
        flash('Some financial details could not be synchronized.', 'warning')

    return render_template('portal/patient_ledger.html', **data)

@patient_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('patient.login'))
