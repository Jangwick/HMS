from flask import Blueprint, render_template, redirect, url_for, flash, request, session
import os
import re
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, get_supabase_client, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from datetime import datetime

# ── Validation helpers ─────────────────────────────────────────────────────────
_NAME_RE    = re.compile(r"^[A-Za-z\u00C0-\u024F\s\-']+$")
_PHONE_PH   = re.compile(r"^(09|\+639)\d{9}$")
_ALNUM_DASH = re.compile(r"^[A-Za-z0-9\-]*$")

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

    # Fetch open vacancies for the "Join Our Team" section
    open_vacancies = []
    try:
        vac_resp = client.table('vacancies').select('id, position_name, department').eq('status', 'Open').order('created_at', desc=True).limit(6).execute()
        open_vacancies = vac_resp.data or []
    except:
        pass
        
    return render_template('portal/patient_landing.html', stats=stats, open_vacancies=open_vacancies)

@patient_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('ct1.dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        next_url = request.form.get('next')
        
        user = User.get_by_username(username, 'patient')
        if user and user.check_password(password):
            if login_user(user):
                flash('Welcome back to the HMS Patient Portal.', 'success')
                return redirect(next_url or url_for('ct1.dashboard'))
        
        flash('Invalid credentials. Please try again.', 'danger')
        
    return render_template('portal/patient_login.html', next=request.args.get('next'))

@patient_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('ct1.dashboard'))
        
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
        terms_agreed = request.form.get('terms_agreed')

        if not terms_agreed:
            flash('You must agree to the Terms & Conditions to register.', 'danger')
            return render_template('portal/patient_register.html')

        # ── Presence checks on all required fields ─────────────────────────────
        required_map = {
            'First name': first_name,
            'Last name': last_name,
            'Date of birth': dob,
            'Gender': request.form.get('gender'),
            'Visit type': request.form.get('visit_type'),
            'Contact number': request.form.get('contact_number'),
            'Address': request.form.get('address'),
            'Username': username,
            'Password': password,
        }
        for label, val in required_map.items():
            if not val or not str(val).strip():
                flash(f'{label} is required.', 'danger')
                return render_template('portal/patient_register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('portal/patient_register.html')

        # ── Server-side input validation ───────────────────────────────────────
        if not first_name or not _NAME_RE.match(first_name.strip()):
            flash('First name must contain letters only (spaces, hyphens, apostrophes allowed).', 'danger')
            return render_template('portal/patient_register.html')
        if not last_name or not _NAME_RE.match(last_name.strip()):
            flash('Last name must contain letters only (spaces, hyphens, apostrophes allowed).', 'danger')
            return render_template('portal/patient_register.html')
        if contact_number and not _PHONE_PH.match(contact_number.strip()):
            flash('Contact number must be a valid Philippine mobile number (09XXXXXXXXX or +639XXXXXXXXX).', 'danger')
            return render_template('portal/patient_register.html')
        if dob:
            try:
                dob_parsed = datetime.strptime(dob, '%Y-%m-%d')
                if dob_parsed.year < 1900 or dob_parsed > datetime.now():
                    flash('Date of birth must be between 1900 and today.', 'danger')
                    return render_template('portal/patient_register.html')
            except ValueError:
                flash('Invalid date of birth format.', 'danger')
                return render_template('portal/patient_register.html')
        visit_type = request.form.get('visit_type', 'General Consultation')
        gov_id_file = request.files.get('gov_id')

        # ── Duplicate phone check ──────────────────────────────────────────────
        _client = get_supabase_client()
        if contact_number:
            dup_phone = _client.table('patients').select('id').eq('contact_number', contact_number.strip()).execute()
            if dup_phone.data:
                flash('A patient with this contact number is already registered.', 'danger')
                return render_template('portal/patient_register.html')

        # ── §2.10 Full duplicate patient check (name + DOB) ────────────────────
        if first_name and last_name and dob:
            dup_name = _client.table('patients').select('id, first_name, last_name').ilike(
                'first_name', first_name.strip()).ilike('last_name', last_name.strip()).eq('dob', dob).execute()
            if dup_name.data:
                flash(
                    f'A patient named {first_name.strip()} {last_name.strip()} with the same date of birth '
                    f'already exists in the system (ID #{dup_name.data[0]["id"]}). '
                    'If this is you, please log in or contact the clinic to retrieve your account.',
                    'warning'
                )
                return render_template('portal/patient_register.html')

        # ── §2.9 Government ID upload validation ──────────────────────────────
        gov_id_url = None
        if not gov_id_file or not gov_id_file.filename:
            flash('A government-issued ID file is required for registration.', 'danger')
            return render_template('portal/patient_register.html')
        allowed_ext = {'pdf', 'jpg', 'jpeg', 'png'}
        ext = gov_id_file.filename.rsplit('.', 1)[-1].lower() if '.' in gov_id_file.filename else ''
        if ext not in allowed_ext:
            flash('Government ID must be PDF, JPG, or PNG.', 'danger')
            return render_template('portal/patient_register.html')
        gov_id_file.seek(0, 2)
        size = gov_id_file.tell()
        gov_id_file.seek(0)
        if size > 5 * 1024 * 1024:
            flash('Government ID file must be smaller than 5 MB.', 'danger')
            return render_template('portal/patient_register.html')

        # Check if username exists
        if User.get_by_username(username):
            flash('Username already exists. Please choose another.', 'danger')
            return render_template('portal/patient_register.html')

        try:
            now = datetime.now()

            # ── §2.7 Generate Temp Patient ID ─────────────────────────────────
            import random, string
            suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
            temp_id = f"TMP-{now.strftime('%Y%m%d')}-{suffix}"

            # ── §2.13 Queue number ─────────────────────────────────────────────
            queue_number = f"Q-{now.strftime('%H%M%S')}"

            # ── §2.11 Official Patient ID (sequential PT-YYYY-NNNNN) ──────────
            count_resp = _client.table('patients').select('id', count='exact').execute()
            seq = (count_resp.count or 0) + 1
            official_id = f"PT-{now.year}-{seq:05d}"

            # 1. Create Patient record
            patient_data = {
                'first_name': first_name.strip(),
                'last_name': last_name.strip(),
                'dob': dob,
                'gender': gender,
                'contact_number': contact_number,
                'address': address,
                'temp_id': temp_id,
                'status': 'Temporary',
                'queue_number': queue_number,
                'official_id': official_id,
                'terms_agreed': True,
                'terms_agreed_at': now.isoformat(),
                'visit_type': visit_type,
            }
            patient = Patient.create(patient_data)
            
            if patient:
                # ── §2.9 Upload Government ID ──────────────────────────────
                if gov_id_file and gov_id_file.filename:
                    try:
                        file_bytes = gov_id_file.read()
                        storage_path = f"gov_ids/{patient.id}_{now.strftime('%Y%m%d%H%M%S')}.{ext}"
                        _client.storage.from_('patient-documents').upload(
                            storage_path, file_bytes,
                            {'content-type': gov_id_file.content_type or 'application/octet-stream'}
                        )
                        pub = _client.storage.from_('patient-documents').get_public_url(storage_path)
                        gov_id_url = pub if isinstance(pub, str) else pub.get('publicUrl', '')
                        _client.table('patients').update({'gov_id_url': gov_id_url, 'status': 'Active'}).eq('id', patient.id).execute()
                    except Exception:
                        pass  # ID upload failure is non-fatal

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
                
                flash(
                    f'Account created successfully! '
                    f'Temp ID: <strong>{temp_id}</strong> &nbsp;|&nbsp; '
                    f'Queue: <strong>{queue_number}</strong> &nbsp;|&nbsp; '
                    f'Patient ID: <strong>{official_id}</strong>. '
                    f'You can now log in.',
                    'success'
                )
                return redirect(url_for('patient.login'))
            else:
                flash('Failed to create patient record. Please contact support.', 'danger')
        except Exception as e:
            flash(f'Registration error: {str(e)}', 'danger')
            
    return render_template('portal/patient_register.html')

@patient_bp.route('/check-duplicate')
def check_duplicate():
    """AJAX endpoint: check if a username or phone number is already taken."""
    from flask import jsonify
    check_type = request.args.get('type')  # 'username' or 'phone'
    value = (request.args.get('value') or '').strip()
    if not check_type or not value:
        return jsonify({'exists': False})
    try:
        client = get_supabase_client()
        if check_type == 'username':
            res = client.table('users').select('id').eq('username', value).eq('subsystem', 'patient').execute()
        elif check_type == 'phone':
            res = client.table('patients').select('id').eq('contact_number', value).execute()
        elif check_type == 'name_dob':
            # value format: "FirstName|LastName|YYYY-MM-DD"
            parts = value.split('|')
            if len(parts) == 3:
                res = client.table('patients').select('id').ilike(
                    'first_name', parts[0]).ilike('last_name', parts[1]).eq('dob', parts[2]).execute()
            else:
                return jsonify({'exists': False})
        else:
            return jsonify({'exists': False})
        return jsonify({'exists': bool(res.data)})
    except Exception:
        return jsonify({'exists': False})
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

@patient_bp.route('/profile')
@login_required
def profile():
    if current_user.role != 'Patient' or not current_user.patient_id:
        flash('Access restricted to registered patients.', 'warning')
        return redirect(url_for('portal.index'))
    
    client = get_supabase_client()
    patient_id = current_user.patient_id
    
    try:
        patient_resp = client.table('patients').select('*').eq('id', patient_id).single().execute()
        patient = patient_resp.data
        
        # Calculate consistency metrics/stats for profile
        stats = {
            'records_count': 0,
            'active_rx': 0,
            'next_appt': None
        }
        
        # Fetch counts/stats
        records_resp = client.table('medical_records').select('id', count='exact').eq('patient_id', patient_id).execute()
        stats['records_count'] = len(records_resp.data) if records_resp.data else 0
        
        rx_resp = client.table('prescriptions').select('id').eq('patient_id', patient_id).eq('status', 'Active').execute()
        stats['active_rx'] = len(rx_resp.data) if rx_resp.data else 0
        
        appt_resp = client.table('appointments').select('*').eq('patient_id', patient_id).gte('appointment_date', datetime.now().isoformat()).order('appointment_date').limit(1).execute()
        stats['next_appt'] = appt_resp.data[0] if appt_resp.data else None

        return render_template('portal/patient_profile.html', patient=patient, stats=stats)
    except Exception as e:
        print(f"Error fetching profile data: {e}")
        flash('Error loading profile information.', 'danger')
        return redirect(url_for('ct1.dashboard'))

@patient_bp.route('/profile/upload-avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('patient.profile'))
    
    file = request.files['avatar']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('patient.profile'))
    
    if file:
        try:
            client = get_supabase_client()
            
            # File extension
            ext = os.path.splitext(file.filename)[1].lower()
            if ext not in ['.jpg', '.jpeg', '.png', '.gif']:
                flash('Invalid file type. Please upload an image.', 'danger')
                return redirect(url_for('patient.profile'))

            # Read file content
            file_content = file.read()
            # Unique filename
            file_path = f"avatars/patient_{current_user.id}_{int(datetime.now().timestamp())}{ext}"
            
            # Upload to Supabase Storage
            bucket_name = 'profiles'
            client.storage.from_(bucket_name).upload(
                path=file_path,
                file=file_content,
                file_options={"content-type": file.content_type, "x-upsert": "true"}
            )
            
            # Get public URL
            avatar_url = client.storage.from_(bucket_name).get_public_url(file_path)
            
            # Update user record
            current_user.update(avatar_url=avatar_url)
            
            flash('Profile picture updated successfully!', 'success')
        except Exception as e:
            flash(f'Error uploading image: {str(e)}', 'danger')
            
    return redirect(url_for('patient.profile'))

@patient_bp.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    if current_user.role != 'Patient' or not current_user.patient_id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('portal.index'))
    
    patient_id = current_user.patient_id
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    dob = request.form.get('dob')
    gender = request.form.get('gender')
    contact_number = request.form.get('contact_number')
    address = request.form.get('address')
    
    try:
        client = get_supabase_client()
        
        # 1. Update Patients Table
        update_data = {
            'first_name': first_name,
            'last_name': last_name,
            'dob': dob,
            'gender': gender,
            'contact_number': contact_number,
            'address': address
        }
        client.table('patients').update(update_data).eq('id', patient_id).execute()
        
        # 2. Update Users Table (for full_name consistency)
        client.table('users').update({
            'full_name': f"{first_name} {last_name}"
        }).eq('id', current_user.id).execute()
        
        # 3. Log Action
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "PROFILE_UPDATE", "patient", f"Updated personal details for {first_name} {last_name}")
        
        flash('Profile updated successfully!', 'success')
    except Exception as e:
        print(f"Error updating profile: {e}")
        flash('Failed to update profile. Please try again.', 'danger')
        
    return redirect(url_for('patient.profile'))

@patient_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('patient.login'))
