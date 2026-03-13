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
        return redirect(url_for('patient.dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        next_url = request.form.get('next')
        
        user = User.get_by_username(username, 'patient')
        if user and user.check_password(password):
            # ── Block pending / rejected accounts ─────────────────────────
            if getattr(user, 'status', None) == 'Pending':
                flash(
                    'Your account is <strong>pending approval</strong> by our staff. '
                    'You will receive access once reviewed. Please check back later.',
                    'warning'
                )
                return render_template('portal/patient_login.html', next=request.args.get('next'))
            if getattr(user, 'status', None) == 'Rejected':
                flash(
                    'Your registration was <strong>not approved</strong>. '
                    'Please contact the clinic for more information.',
                    'danger'
                )
                return render_template('portal/patient_login.html', next=request.args.get('next'))
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
                'status': 'Pending Approval',
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
                        _client.table('patients').update({'gov_id_url': gov_id_url}).eq('id', patient.id).execute()
                    except Exception:
                        pass  # ID upload failure is non-fatal

                # 2. Create User account (Pending until CT1 approves)
                User.create(
                    username=username,
                    email=f"{username.lower()}@hms-patient.com",
                    password=password,
                    subsystem='patient',
                    department='PATIENT_PORTAL',
                    role='Patient',
                    status='Pending',
                    full_name=f"{first_name} {last_name}",
                    patient_id=patient.id,
                    skip_validation=True
                )
                
                # 3. Notify CT1 (Patient Access) of new registration
                from utils.hms_models import Notification
                Notification.create(
                    subsystem='ct1',
                    title="New Portal Registration — Pending Approval",
                    message=f"{first_name} {last_name} has registered via the Patient Portal and is awaiting your review.",
                    n_type="info",
                    sender_subsystem='patient',
                    target_url=url_for('ct1.list_patients', tab='registrations', _external=True)
                )

                flash(
                    f'Registration submitted! Your account is <strong>pending approval</strong> by our staff. '
                    f'You will be able to log in once approved. '
                    f'Temp ID: <strong>{temp_id}</strong>',
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
    except Exception as e:
        print(f'Patient fetch error: {e}')
        data['patient'] = {'first_name': 'Patient', 'last_name': 'User'}

    try:
        # 2. Fetch Stay Info
        patient_insurance = (data['patient'] or {}).get('insurance_info') or {}
        current_bed_id = patient_insurance.get('current_bed_id')
        if current_bed_id:
            bed_resp = client.table('beds').select('*').eq('id', int(current_bed_id)).execute()
            data['bed_info'] = bed_resp.data[0] if bed_resp.data else None
    except Exception as e:
        print(f'Bed fetch error: {e}')

    try:
        # 3a. Labs
        labs_resp = client.table('lab_orders').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['labs'] = labs_resp.data or []
    except Exception as e:
        print(f'Labs fetch error: {e}')

    try:
        # 3b. Radiology
        radio_resp = client.table('radiology_orders').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['radiology'] = radio_resp.data or []
    except Exception as e:
        print(f'Radiology fetch error: {e}')

    try:
        # 3c. Prescriptions
        prescriptions_resp = client.table('prescriptions').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['prescriptions'] = prescriptions_resp.data or []
    except Exception as e:
        print(f'Prescriptions fetch error: {e}')

    try:
        # 4. Vitals / Medical Records
        records_resp = client.table('medical_records').select('*').eq('patient_id', patient_id).order('visit_date', desc=True).execute()
        if records_resp.data:
            for record in records_resp.data:
                if record.get('vitals'):
                    data['vitals'] = record['vitals']
                    break
    except Exception as e:
        print(f'Medical records fetch error: {e}')

    try:
        # 5. Nutrition
        diet_resp = client.table('diet_plans').select('*').eq('patient_id', patient_id).eq('status', 'Active').order('created_at', desc=True).execute()
        data['diet'] = diet_resp.data[0] if diet_resp.data else None
    except Exception as e:
        print(f'Diet fetch error: {e}')

    try:
        meals_resp = client.table('meal_tracking').select('*').eq('patient_id', patient_id).order('created_at', desc=True).limit(5).execute()
        data['meals'] = meals_resp.data or []
    except Exception as e:
        print(f'Meals fetch error: {e}')

    try:
        # 6. Billing — table is 'invoices', amount field is 'amount'
        billing_resp = client.table('invoices').select('*').eq('patient_id', patient_id).order('issued_at', desc=True).execute()
        data['bills'] = billing_resp.data or []
        data['total_due'] = sum(float(b['amount']) for b in data['bills'] if b.get('status') != 'Paid') if data['bills'] else 0.0
    except Exception as e:
        print(f'Billing fetch error: {e}')

    try:
        # 7. Appointments
        appt_resp = client.table('appointments').select('*, users(full_name)').eq('patient_id', patient_id).order('appointment_date').execute()
        data['appointments'] = appt_resp.data or []
    except Exception as e:
        print(f'Appointments fetch error: {e}')

    try:
        # 8. Construct Unified Timeline
        timeline = []
        for lab in data['labs']:
            timeline.append({'type': 'lab', 'title': lab.get('test_name', 'Lab'), 'date': lab.get('created_at', ''), 'status': lab.get('status', '')})
        for rad in data['radiology']:
            timeline.append({'type': 'radiology', 'title': rad.get('imaging_type', 'Radiology'), 'date': rad.get('created_at', ''), 'status': rad.get('status', '')})
        for appt in data['appointments']:
            timeline.append({'type': 'appointment', 'title': f"Consultation: {appt.get('type','')}", 'date': appt.get('appointment_date', ''), 'status': appt.get('status', '')})
        data['timeline'] = sorted(timeline, key=lambda x: x['date'], reverse=True)[:10]
    except Exception as e:
        print(f'Timeline build error: {e}')

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
        'telehealth_sessions': [],
        'prescriptions': [],
        'bills': [],
        'timeline': []
    }
    
    try:
        patient_resp = client.table('patients').select('*').eq('id', patient_id).single().execute()
        data['patient'] = patient_resp.data
    except Exception as e:
        print(f'Patient fetch error: {e}')

    try:
        labs_resp = client.table('lab_orders').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['labs'] = labs_resp.data or []
    except Exception as e:
        print(f'Labs fetch error: {e}')

    try:
        radio_resp = client.table('radiology_orders').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['radiology'] = radio_resp.data or []
    except Exception as e:
        print(f'Radiology fetch error: {e}')

    try:
        records_resp = client.table('medical_records').select('*, users(full_name)').eq('patient_id', patient_id).order('visit_date', desc=True).execute()
        data['medical_records'] = records_resp.data or []
    except Exception as e:
        print(f'Medical records fetch error: {e}')

    try:
        appt_resp = client.table('appointments').select('*, users(full_name)').eq('patient_id', patient_id).order('appointment_date', desc=True).execute()
        data['appointments'] = appt_resp.data or []
    except Exception as e:
        print(f'Appointments fetch error: {e}')

    try:
        tele_resp = client.table('telehealth_sessions').select('*, users!telehealth_sessions_doctor_id_fkey(full_name)').eq('patient_id', patient_id).order('scheduled_at', desc=True).execute()
        data['telehealth_sessions'] = tele_resp.data or []
    except Exception as e:
        print(f'Telehealth sessions fetch error: {e}')
        try:
            tele_resp = client.table('telehealth_sessions').select('*').eq('patient_id', patient_id).order('scheduled_at', desc=True).execute()
            data['telehealth_sessions'] = tele_resp.data or []
        except Exception as e2:
            print(f'Telehealth fallback fetch error: {e2}')

    try:
        prescriptions_resp = client.table('prescriptions').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['prescriptions'] = prescriptions_resp.data or []
    except Exception as e:
        print(f'Prescriptions fetch error: {e}')

    try:
        billing_resp = client.table('billing_records').select('*').eq('patient_id', patient_id).order('created_at', desc=True).execute()
        data['bills'] = billing_resp.data or []
    except Exception as e:
        print(f'Billing fetch error: {e}')

    # Construct Unified Timeline
    timeline = []
    for lab in data['labs']:
        try:
            timeline.append({
                'type': 'lab',
                'title': lab['test_name'],
                'date': lab['created_at'],
                'status': lab['status'],
                'details': lab.get('results'),
                'icon': 'bi-microscope',
                'category': 'Diagnostics'
            })
        except Exception: pass
    for rad in data['radiology']:
        try:
            timeline.append({
                'type': 'radiology',
                'title': rad['imaging_type'],
                'date': rad['created_at'],
                'status': rad['status'],
                'details': rad.get('findings'),
                'icon': 'bi-camera',
                'category': 'Imaging'
            })
        except Exception: pass
    for record in data['medical_records']:
        try:
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
        except Exception: pass
    for appt in data['appointments']:
        try:
            timeline.append({
                'type': 'appointment',
                'title': f"Consultation: {appt['type']}",
                'date': appt['appointment_date'],
                'status': appt['status'],
                'doctor': appt['users']['full_name'] if appt.get('users') else 'Staff',
                'icon': 'bi-calendar2-check',
                'category': 'Schedule'
            })
        except Exception: pass
    for sess in data['telehealth_sessions']:
        try:
            doctor_name = 'Doctor'
            if sess.get('users'):
                doctor_name = sess['users'].get('full_name', 'Doctor')
            timeline.append({
                'type': 'telehealth',
                'title': 'Telehealth Session',
                'date': sess.get('scheduled_at') or sess.get('created_at'),
                'status': sess.get('status', 'Scheduled'),
                'details': sess.get('notes') or None,
                'doctor': doctor_name,
                'meeting_link': sess.get('meeting_link'),
                'icon': 'bi-camera-video',
                'category': 'Virtual Care'
            })
        except Exception: pass
    for rx in data['prescriptions']:
        try:
            timeline.append({
                'type': 'prescription',
                'title': f"Prescription: {rx['medication_name']}",
                'date': rx['created_at'],
                'status': rx['status'],
                'details': f"Dosage: {rx['dosage']} - {rx['instructions']}",
                'icon': 'bi-capsule',
                'category': 'Medication'
            })
        except Exception: pass
    for bill in data['bills']:
        try:
            timeline.append({
                'type': 'billing',
                'title': f"Billing: {bill['description'] or 'Service Charge'}",
                'date': bill['created_at'],
                'status': bill['status'],
                'details': f"Amount: ${bill['total_amount']}",
                'icon': 'bi-wallet2',
                'category': 'Financial'
            })
        except Exception: pass

    data['timeline'] = sorted(timeline, key=lambda x: x.get('date') or '', reverse=True)

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
        return redirect(url_for('patient.dashboard'))

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


@patient_bp.route('/book-appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    """Patient self-service appointment booking."""
    if current_user.role != 'Patient' or not current_user.patient_id:
        flash('Access restricted to registered patients.', 'warning')
        return redirect(url_for('portal.index'))

    client = get_supabase_client()
    patient_id = current_user.patient_id

    # Fetch patient record
    patient_rec = None
    try:
        pr = client.table('patients').select('*').eq('id', patient_id).single().execute()
        patient_rec = pr.data
    except Exception:
        pass

    if not patient_rec:
        flash('Patient record not found. Please contact reception.', 'danger')
        return redirect(url_for('patient.dashboard'))

    # Check ban / no-show restriction
    is_banned = patient_rec.get('is_banned') or False
    no_show_count = max(
        int(patient_rec.get('no_show_count') or 0),
        int((patient_rec.get('insurance_info') or {}).get('no_show_count', 0))
    )
    if is_banned or no_show_count >= 3:
        flash(
            f'Your account has {no_show_count} recorded no-shows and is currently restricted from self-booking. '
            'Please contact reception to resolve outstanding fees.',
            'warning'
        )
        return redirect(url_for('patient.dashboard'))

    # Available doctors
    doctors = client.table('users').select('id, username, full_name, subsystem') \
        .in_('subsystem', ['ct2', 'ct3']).execute().data or []

    if request.method == 'POST':
        from datetime import datetime as _dt
        appt_dt_str = request.form.get('appointment_date', '').strip()
        doctor_id   = request.form.get('doctor_id', '').strip()
        visit_type  = request.form.get('visit_type', 'General Consultation').strip()
        appt_type   = request.form.get('type', 'Outpatient').strip()
        notes       = request.form.get('notes', '').strip()

        # Validate datetime
        if not appt_dt_str or not doctor_id:
            flash('Please fill in all required fields.', 'warning')
            return render_template('portal/patient_book_appointment.html',
                                   patient=patient_rec, doctors=doctors,
                                   now=datetime.utcnow)

        try:
            appt_dt = _dt.fromisoformat(appt_dt_str.replace('T', ' '))
            if appt_dt < _dt.now():
                flash('Appointment cannot be scheduled in the past.', 'danger')
                return render_template('portal/patient_book_appointment.html',
                                       patient=patient_rec, doctors=doctors, now=datetime.utcnow)
            if not (7 <= appt_dt.hour < 15):
                flash('Appointments are only available between 7:00 AM and 3:00 PM.', 'danger')
                return render_template('portal/patient_book_appointment.html',
                                       patient=patient_rec, doctors=doctors, now=datetime.utcnow)
        except ValueError:
            flash('Invalid date/time format.', 'danger')
            return render_template('portal/patient_book_appointment.html',
                                   patient=patient_rec, doctors=doctors, now=datetime.utcnow)

        date_part = appt_dt_str[:10]

        # Duplicate same-day check for this patient
        dup_q = client.table('appointments') \
            .select('id') \
            .eq('patient_id', patient_id) \
            .in_('status', ['Scheduled', 'Arrived']) \
            .gte('appointment_date', date_part + 'T00:00:00') \
            .lt('appointment_date',  date_part + 'T23:59:59') \
            .execute()
        if dup_q.data:
            flash('You already have an appointment scheduled on that date. '
                  'Please choose a different day or contact reception.', 'danger')
            return render_template('portal/patient_book_appointment.html',
                                   patient=patient_rec, doctors=doctors, now=datetime.utcnow)

        # Duplicate doctor slot check
        doc_dup = client.table('appointments') \
            .select('id') \
            .eq('doctor_id', doctor_id) \
            .eq('appointment_date', appt_dt_str) \
            .in_('status', ['Scheduled', 'Arrived']) \
            .execute()
        if doc_dup.data:
            flash('That time slot is already taken. Please choose a different time.', 'danger')
            return render_template('portal/patient_book_appointment.html',
                                   patient=patient_rec, doctors=doctors, now=datetime.utcnow)

        try:
            result = client.table('appointments').insert({
                'patient_id':       patient_id,
                'doctor_id':        doctor_id,
                'appointment_date': appt_dt_str,
                'type':             appt_type,
                'visit_type':       visit_type,
                'notes':            notes,
                'status':           'Scheduled',
                'terms_agreed':     True,
            }).execute()

            if result.data:
                appt_id = result.data[0]['id']
                # Notify doctor
                from utils.hms_models import Notification
                Notification.create(
                    user_id=int(doctor_id),
                    subsystem='ct2',
                    title='New Appointment (Self-Booked)',
                    message=f'{patient_rec.get("first_name","")} {patient_rec.get("last_name","")} '
                            f'has self-booked an appointment on {appt_dt_str}.',
                    n_type='info',
                    sender_subsystem='patient'
                )
                flash('Your appointment has been booked successfully!', 'success')
                return redirect(url_for('patient.dashboard'))
            else:
                flash('Booking failed. Please try again.', 'danger')
        except Exception as e:
            flash(f'Booking error: {str(e)}', 'danger')

    return render_template('portal/patient_book_appointment.html',
                           patient=patient_rec,
                           doctors=doctors,
                           now=datetime.utcnow)


@patient_bp.route('/bill/<int:bill_id>')
@login_required
def view_bill(bill_id):
    if current_user.role != 'Patient' or not current_user.patient_id:
        flash('Access restricted to registered patients.', 'warning')
        return redirect(url_for('portal.index'))
    
    client = get_supabase_client()
    patient_id = current_user.patient_id
    
    try:
        # Fetch bill - must belong to current patient
        bill_resp = client.table('billing_records').select('*').eq('id', bill_id).single().execute()
        bill = bill_resp.data
        
        if not bill or bill.get('patient_id') != patient_id:
            flash('Bill not found or access denied.', 'warning')
            return redirect(url_for('patient.ledger'))
        
        # Fetch patient info
        patient_resp = client.table('patients').select('*').eq('id', patient_id).single().execute()
        patient = patient_resp.data
        
        # Fetch line items with fallback for different column names
        line_items = []
        try:
            resp = client.table('billing_line_items').select('*').eq('billing_id', bill_id).execute()
            line_items = resp.data or []
        except Exception:
            try:
                resp = client.table('billing_line_items').select('*').eq('bill_id', bill_id).execute()
                line_items = resp.data or []
            except Exception:
                pass
        
        return render_template('portal/patient_bill_detail.html',
                               patient=patient,
                               bill=bill,
                               line_items=line_items,
                               now=datetime.utcnow())
    except Exception as e:
        flash(f'Error loading bill: {str(e)}', 'danger')
        return redirect(url_for('patient.ledger'))


@patient_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('patient.login'))
