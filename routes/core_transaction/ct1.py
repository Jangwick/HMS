from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error, get_supabase_client
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from datetime import datetime

ct1_bp = Blueprint('ct1', __name__, template_folder='templates')

# Subsystem configuration
SUBSYSTEM_NAME = 'CT1 - Patient Access'
ACCENT_COLOR = '#10B981'
SUBSYSTEM_ICON = 'person-badge'
BLUEPRINT_NAME = 'ct1'

@ct1_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked(subsystem=BLUEPRINT_NAME)
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/core_transaction/ct1/login.html', 
                               remaining_seconds=remaining_seconds,
                               subsystem_name=SUBSYSTEM_NAME,
                               accent_color=ACCENT_COLOR,
                               subsystem_icon=SUBSYSTEM_ICON,
                               blueprint_name=BLUEPRINT_NAME,
                               hub_route='portal.ct_hub')
    
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
                    return redirect(url_for('ct1.change_password'))

                # Check if account is approved
                if user.status != 'Active':
                    if user.status == 'Pending':
                        flash('Your account is awaiting approval from HR2 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('subsystems/core_transaction/ct1/login.html',
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           subsystem_icon=SUBSYSTEM_ICON,
                                           blueprint_name=BLUEPRINT_NAME,
                                           hub_route='portal.ct_hub')

                # Clear IP lockout attempts on successful login
                register_successful_login(subsystem=BLUEPRINT_NAME)
                user.register_successful_login()
                
                if login_user(user):
                    from utils.hms_models import AuditLog
                    AuditLog.log(user.id, "Login", BLUEPRINT_NAME, {"ip": request.remote_addr})
                    
                    days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                    if days_left <= 7:
                        flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    return redirect(url_for('ct1.dashboard'))
                else:
                    flash('Login failed. Your account may be deactivated.', 'danger')
                    return render_template('shared/login.html',
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           subsystem_icon=SUBSYSTEM_ICON,
                                           blueprint_name=BLUEPRINT_NAME,
                                           hub_route='portal.ct_hub')
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt(subsystem=BLUEPRINT_NAME)
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('shared/login.html', 
                                           remaining_seconds=remaining_seconds,
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           subsystem_icon=SUBSYSTEM_ICON,
                                           blueprint_name=BLUEPRINT_NAME,
                                           hub_route='portal.ct_hub')
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
                return render_template('shared/login.html', 
                                       remaining_seconds=remaining_seconds,
                                       subsystem_name=SUBSYSTEM_NAME,
                                       accent_color=ACCENT_COLOR,
                                       subsystem_icon=SUBSYSTEM_ICON,
                                       blueprint_name=BLUEPRINT_NAME,
                                       hub_route='portal.ct_hub')
            
    return render_template('shared/login.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           subsystem_icon=SUBSYSTEM_ICON,
                           blueprint_name=BLUEPRINT_NAME,
                           hub_route='portal.ct_hub')


@ct1_bp.route('/change-password', methods=['GET', 'POST'])
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
            return redirect(url_for('ct1.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('ct1.login'))
    
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
            return redirect(url_for('ct1.login'))
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html',
        subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@ct1_bp.route('/dashboard')
@login_required
@policy_required(BLUEPRINT_NAME)
def dashboard():
    from utils.hms_models import Appointment, Patient
    from datetime import datetime, timedelta
    
    # Get stats
    client = get_supabase_client()
    
    # Total Patients
    total_patients = client.table('patients').select('id', count='exact').execute().count or 0
    
    # New Patients this week
    last_week = (datetime.now() - timedelta(days=7)).isoformat()
    new_patients_week = client.table('patients').select('id', count='exact').gte('created_at', last_week).execute().count or 0
    
    # Appointments today
    today_start = datetime.now().strftime('%Y-%m-%d 00:00:00')
    today_end = datetime.now().strftime('%Y-%m-%d 23:59:59')
    appointments_today_resp = client.table('appointments')\
        .select('id', count='exact')\
        .gte('appointment_date', today_start)\
        .lte('appointment_date', today_end)\
        .neq('status', 'Cancelled')\
        .execute()
    appointments_today = appointments_today_resp.count or 0

    # Bed stats
    bed_resp = client.table('beds').select('id, status', count='exact').execute()
    total_beds = bed_resp.count or 0
    occupied_beds = sum(1 for b in bed_resp.data if b['status'] == 'Occupied') if bed_resp.data else 0

    upcoming_appointments = Appointment.get_upcoming()
    
    metrics = {
        'total_patients': total_patients,
        'new_patients_week': new_patients_week,
        'appointments_today': appointments_today,
        'occupied_beds': occupied_beds,
        'total_beds': total_beds,
        'system_status': 'Operational'
    }
    
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
        
    return render_template('subsystems/core_transaction/ct1/dashboard.html', 
                           now=datetime.utcnow,
                           appointments=upcoming_appointments,
                           metrics=metrics,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct1_bp.route('/patients')
@login_required
def list_patients():
    from utils.hms_models import Patient
    from datetime import datetime
    
    client = get_supabase_client()
    patients = Patient.get_all()
    
    # Calculate New This Month
    now = datetime.now()
    first_day_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    
    new_this_month = 0
    try:
        res = client.table('patients').select('id', count='exact').gte('created_at', first_day_month).execute()
        new_this_month = res.count or 0
    except Exception as e:
        print(f"Error calculating monthly stats: {e}")

    return render_template('subsystems/core_transaction/ct1/patient_list.html',
                           now=datetime.utcnow,
                           patients=patients,
                           new_this_month=new_this_month,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct1_bp.route('/register-patient', methods=['GET', 'POST'])
@login_required
def register_patient():
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can register patients.', 'error')
        return redirect(url_for('ct1.list_patients'))

    from datetime import datetime
    if request.method == 'POST':
        from utils.hms_models import Patient
        try:
            patient_data = {
                'first_name': request.form.get('first_name'),
                'last_name': request.form.get('last_name'),
                'dob': request.form.get('dob'),
                'gender': request.form.get('gender'),
                'contact_number': request.form.get('contact_number'),
                'address': request.form.get('address'),
                'insurance_info': {
                    'provider': request.form.get('insurance_provider') or 'None',
                    'policy_number': request.form.get('policy_number') or 'N/A',
                    'group_number': request.form.get('group_number') or 'N/A'
                }
            }
            patient = Patient.create(patient_data)
            if patient:
                # Handle Portal Account Creation
                if request.form.get('create_portal_account') == 'yes':
                    portal_username = request.form.get('portal_username')
                    portal_password = request.form.get('portal_password')
                    try:
                        # Create User with 'Patient' role and 'patient' subsystem
                        User.create(
                            username=portal_username,
                            email=f"{portal_username}@hms-patient.com",
                            password=portal_password,
                            subsystem='patient',
                            department='PATIENT_PORTAL',
                            role='Patient',
                            status='Active',
                            full_name=f"{patient.first_name} {patient.last_name}",
                            patient_id=patient.id, # Link directly during creation
                            skip_validation=True
                        )
                        
                        flash(f'Portal account created for {portal_username}!', 'success')
                    except Exception as portal_err:
                        flash(f'Patient registered, but portal account failed: {str(portal_err)}', 'warning')

                from utils.hms_models import AuditLog
                AuditLog.log(current_user.id, "Register Patient", BLUEPRINT_NAME, {"patient_id": patient.id, "name": f"{patient.first_name} {patient.last_name}"})
                flash(f'Patient {patient.first_name} {patient.last_name} registered successfully! ID: {patient.patient_id_alt}', 'success')
                return redirect(url_for('ct1.view_patient', patient_id=patient.id))
            else:
                flash('Failed to register patient.', 'danger')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            
    return render_template('subsystems/core_transaction/ct1/patient_registration.html',
                           now=datetime.utcnow,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct1_bp.route('/search-patients')
@login_required
def search_patients():
    from datetime import datetime
    query = request.args.get('q', '')
    from utils.hms_models import Patient
    patients = []
    if query:
        patients = Patient.search(query)
    return render_template('subsystems/core_transaction/ct1/patient_search.html', 
                           now=datetime.utcnow,
                           patients=patients,
                           query=query,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct1_bp.route('/view-patient/<patient_id>')
@login_required
def view_patient(patient_id):
    from datetime import datetime
    client = get_supabase_client()
    try:
        # Get patient details
        patient_res = client.table('patients').select('*').eq('id', patient_id).single().execute()
        if not patient_res.data:
            flash('Patient not found.', 'danger')
            return redirect(url_for('ct1.list_patients'))
        
        patient = patient_res.data
        
        # Get appointments for this patient and join with doctor info (users)
        # Note: We need to use a join query that Supabase understands or separate queries
        appointments_res = client.table('appointments').select('*, users!appointments_doctor_id_fkey(username, department, subsystem)').eq('patient_id', patient_id).execute()
        appointments = appointments_res.data or []
        
        return render_template('subsystems/core_transaction/ct1/view_patient.html',
                               now=datetime.utcnow,
                               patient=patient,
                               appointments=appointments,
                               subsystem_name=SUBSYSTEM_NAME,
                               accent_color=ACCENT_COLOR,
                               blueprint_name=BLUEPRINT_NAME)
    except Exception as e:
        flash(f'Error retrieving patient profile: {str(e)}', 'danger')
        return redirect(url_for('ct1.list_patients'))

@ct1_bp.route('/view-patient/edit/<patient_id>', methods=['POST'])
@login_required
def update_patient(patient_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can update patient records.', 'error')
        return redirect(url_for('ct1.view_patient', patient_id=patient_id))
    
    client = get_supabase_client()
    try:
        ins_provider   = (request.form.get('insurance_provider') or '').strip()
        ins_group      = (request.form.get('group_number') or '').strip()
        ins_policy     = (request.form.get('policy_number') or '').strip()

        # §2.12 Insurance group number uniqueness check
        if ins_group and ins_provider:
            try:
                dup_ins = client.table('patients').select('id, first_name, last_name, insurance_info').neq(
                    'id', patient_id).execute()
                conflicts = [
                    p for p in (dup_ins.data or [])
                    if (p.get('insurance_info') or {}).get('group_number') == ins_group
                    and (p.get('insurance_info') or {}).get('provider','').lower() == ins_provider.lower()
                ]
                if conflicts:
                    c = conflicts[0]
                    flash(
                        f'Warning: Group number "{ins_group}" is already assigned to another patient '
                        f'({c["first_name"]} {c["last_name"]}, ID #{c["id"]}) under {ins_provider}. '
                        'Record was saved — please verify this is correct.',
                        'warning'
                    )
            except Exception:
                pass

        updated_data = {
            'first_name': request.form.get('first_name'),
            'last_name': request.form.get('last_name'),
            'dob': request.form.get('dob'),
            'gender': request.form.get('gender'),
            'contact_number': request.form.get('contact_number'),
            'address': request.form.get('address'),
            'insurance_info': {
                'provider': ins_provider,
                'policy_number': ins_policy,
                'group_number': ins_group,
            }
        }
        client.table('patients').update(updated_data).eq('id', patient_id).execute()
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Update Patient", BLUEPRINT_NAME, {"patient_id": patient_id})
        flash('Patient record updated successfully!', 'success')
    except Exception as e:
        flash(f'Update failed: {str(e)}', 'danger')
    return redirect(url_for('ct1.view_patient', patient_id=patient_id))

@ct1_bp.route('/patients/delete/<patient_id>', methods=['POST'])
@login_required
def delete_patient(patient_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can delete patient records.', 'error')
        return redirect(url_for('ct1.view_patient', patient_id=patient_id))
    
    client = get_supabase_client()
    try:
        # Check if patient has appointments
        res = client.table('appointments').select('id').eq('patient_id', patient_id).execute()
        if res.data:
            flash('Cannot delete patient with existing appointment history.', 'warning')
            return redirect(url_for('ct1.view_patient', patient_id=patient_id))
            
        client.table('patients').delete().eq('id', patient_id).execute()
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Delete Patient", BLUEPRINT_NAME, {"patient_id": patient_id})
        flash('Patient record deleted successfully.', 'success')
        return redirect(url_for('ct1.list_patients'))
    except Exception as e:
        flash(f'Deletion failed: {str(e)}', 'danger')
        return redirect(url_for('ct1.view_patient', patient_id=patient_id))

@ct1_bp.route('/book-appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    from datetime import datetime
    from utils.hms_models import Patient, Appointment
    if request.method == 'POST':
        try:
            appt_dt_str = request.form.get('appointment_date', '')
            patient_id_book = request.form.get('patient_id')

            # ── Validate appointment time window (7AM–3PM) ─────────────────────
            if appt_dt_str:
                try:
                    appt_dt = datetime.fromisoformat(appt_dt_str.replace('T', ' '))
                    if appt_dt < datetime.now():
                        flash('Appointment cannot be scheduled in the past.', 'danger')
                        patients = Patient.get_all()
                        doctors = get_supabase_client().table('users').select('*').in_('subsystem', ['ct2', 'ct3']).execute().data or []
                        return render_template('subsystems/core_transaction/ct1/book_appointment.html', now=datetime.utcnow, doctors=doctors, patients=patients, selected_patient_id=None, subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)
                    if not (7 <= appt_dt.hour < 15):
                        flash('Appointments must be scheduled between 7:00 AM and 3:00 PM.', 'danger')
                        patients = Patient.get_all()
                        doctors = get_supabase_client().table('users').select('*').in_('subsystem', ['ct2', 'ct3']).execute().data or []
                        return render_template('subsystems/core_transaction/ct1/book_appointment.html', now=datetime.utcnow, doctors=doctors, patients=patients, selected_patient_id=None, subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)
                except ValueError:
                    flash('Invalid appointment date/time format.', 'danger')
                    patients = Patient.get_all()
                    doctors = get_supabase_client().table('users').select('*').in_('subsystem', ['ct2', 'ct3']).execute().data or []
                    return render_template('subsystems/core_transaction/ct1/book_appointment.html', now=datetime.utcnow, doctors=doctors, patients=patients, selected_patient_id=None, subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)

            # ── No-show / ban check (§3.4) ──────────────────────────────────
            if patient_id_book:
                _cli = get_supabase_client()
                _p = _cli.table('patients').select('is_banned, ban_reason, no_show_count, insurance_info').eq('id', patient_id_book).single().execute()
                if _p.data:
                    _banned  = _p.data.get('is_banned') or False
                    _ns_col  = int(_p.data.get('no_show_count') or 0)
                    _ns_jsonb = int((_p.data.get('insurance_info') or {}).get('no_show_count', 0))
                    _no_show_count = max(_ns_col, _ns_jsonb)
                    if _banned or _no_show_count >= 3:
                        flash(
                            f'This patient has {_no_show_count} recorded no-shows and is currently banned from new appointments. '
                            f'Please resolve outstanding fees first.',
                            'warning'
                        )
                        patients = Patient.get_all()
                        doctors = _cli.table('users').select('*').in_('subsystem', ['ct2', 'ct3']).execute().data or []
                        return render_template('subsystems/core_transaction/ct1/book_appointment.html', now=datetime.utcnow, doctors=doctors, patients=patients, selected_patient_id=None, subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)

            # ── §4.4 Duplicate booking prevention ─────────────────────────────
            _doctor_id = request.form.get('doctor_id')
            if _doctor_id and appt_dt_str:
                try:
                    _dup = get_supabase_client().table('appointments').select('id').eq(
                        'doctor_id', _doctor_id).eq('appointment_date', appt_dt_str).in_(
                        'status', ['Scheduled', 'Arrived']).execute()
                    if _dup.data:
                        flash('This doctor already has an appointment scheduled at that exact time. Please choose a different slot.', 'danger')
                        patients = Patient.get_all()
                        doctors = get_supabase_client().table('users').select('*').in_('subsystem', ['ct2', 'ct3']).execute().data or []
                        return render_template('subsystems/core_transaction/ct1/book_appointment.html', now=datetime.utcnow, doctors=doctors, patients=patients, selected_patient_id=None, subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)
                except Exception:
                    pass

            appointment_data = {
                'patient_id': patient_id_book,
                'doctor_id': _doctor_id,
                'appointment_date': appt_dt_str,
                'type': request.form.get('type'),
                'visit_type': request.form.get('visit_type', 'General Consultation'),
                'status': 'Scheduled',
                'notes': request.form.get('notes'),
                'terms_agreed': True,
            }
            appointment = Appointment.create(appointment_data)
            if appointment:
                from utils.hms_models import AuditLog, Notification
                AuditLog.log(current_user.id, "Book Appointment", BLUEPRINT_NAME, {"appointment_id": appointment.id, "patient_id": appointment.patient_id})
                
                # Notify the doctor/Clinical Ops (CT2)
                Notification.create(
                    user_id=appointment_data['doctor_id'], 
                    subsystem='ct2',
                    title="New Appointment Scheduled",
                    message=f"A new appointment has been scheduled for {appointment_data['appointment_date']}.",
                    n_type="info",
                    sender_subsystem=BLUEPRINT_NAME,
                    target_url=url_for('ct2.dashboard')
                )
                
                # Notify the Patient
                client = get_supabase_client()
                portal_user_res = client.table('users').select('id').eq('patient_id', appointment.patient_id).execute()
                if portal_user_res.data:
                    portal_user_id = portal_user_res.data[0]['id']
                    date_obj = datetime.fromisoformat(appointment_data['appointment_date'].replace('Z', '+00:00')) if 'T' in appointment_data['appointment_date'] else datetime.strptime(appointment_data['appointment_date'], '%Y-%m-%d')
                    date_str = date_obj.strftime('%b %d, %Y')
                    t = appointment_data.get('type') or 'Consultation'
                    Notification.create(
                        user_id=portal_user_id,
                        subsystem='patient',
                        title="Appointment Confirmed",
                        message=f"Your appointment ({t}) has been scheduled for {date_str}.",
                        n_type="info",
                        sender_subsystem=BLUEPRINT_NAME,
                        target_url=url_for('ct1.dashboard')
                    )
                
                flash('Appointment booked successfully!', 'success')
                return redirect(url_for('ct1.dashboard'))
            else:
                flash('Failed to book appointment.', 'danger')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            
    patients = Patient.get_all()
    # Get doctors (users in CT2 or CT3)
    client = get_supabase_client()
    doctors = client.table('users').select('*').in_('subsystem', ['ct2', 'ct3']).execute().data or []
    
    selected_patient_id = request.args.get('patient_id')
    
    return render_template('subsystems/core_transaction/ct1/book_appointment.html', 
                           now=datetime.utcnow,
                           doctors=doctors,
                           patients=patients,
                           selected_patient_id=selected_patient_id,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct1_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    from datetime import datetime
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
                           now=datetime.utcnow,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct1_bp.route('/beds')
@login_required
def bed_management():
    client = get_supabase_client()
    
    try:
        response = client.table('beds').select('*').order('room_number').execute()
        beds = response.data if response.data else []
        
        # Fetch all patients who have a bed assignment in their insurance_info JSONB
        # We fetch all patients here to build our lookup map
        patients_resp = client.table('patients').select('id, first_name, last_name, patient_id_alt, insurance_info').execute()
        patients_list = patients_resp.data if patients_resp.data else []
        
        # Build inverse lookup: bed_id -> patient_info
        # Workaround: patient_id is missing from beds table, so we use insurance_info on patients as the source of truth
        bed_to_patient = {}
        for p in patients_list:
            info = p.get('insurance_info') or {}
            b_id = info.get('current_bed_id')
            if b_id:
                bed_to_patient[int(b_id)] = p
        
        for bed in beds:
            bed['patient_info'] = bed_to_patient.get(bed['id'])
            # Ensure status logic matches actual assignment
            if bed['patient_info'] and bed['status'] != 'Occupied':
                # Self-correction: if a patient is in it, it should be occupied
                bed['status'] = 'Occupied'
                
    except Exception as e:
        flash(f'Error fetching bed data: {str(e)}', 'danger')
        beds = []
        patients_list = []
        
    return render_template('subsystems/core_transaction/ct1/beds.html',
                           beds=beds,
                           patients_list=patients_list,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct1_bp.route('/beds/update/<int:bed_id>', methods=['POST'])
@login_required
def update_bed(bed_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can modify bed configurations.', 'error')
        return redirect(url_for('ct1.bed_management'))
    
    client = get_supabase_client()
    
    new_status = request.form.get('status')
    try:
        client.table('beds').update({'status': new_status}).eq('id', bed_id).execute()
        
        # If transitioning away from Occupied, clear any patient assignment via JSONB
        if new_status != 'Occupied':
            assigned = client.table('patients').select('id, insurance_info').contains('insurance_info', {'current_bed_id': bed_id}).execute()
            if assigned.data:
                for p in assigned.data:
                    insurance = p.get('insurance_info') or {}
                    if 'current_bed_id' in insurance:
                        del insurance['current_bed_id']
                    client.table('patients').update({'insurance_info': insurance}).eq('id', p['id']).execute()
        
        flash(f'Bed status updated to {new_status}.', 'success')
    except Exception as e:
        flash(f'Error updating bed: {str(e)}', 'danger')
        
    return redirect(url_for('ct1.bed_management'))

@ct1_bp.route('/beds/assign/<int:bed_id>', methods=['POST'])
@login_required
def assign_patient_to_bed(bed_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can assign patients.', 'error')
        return redirect(url_for('ct1.bed_management'))
    
    client = get_supabase_client()
    patient_id = request.form.get('patient_id')
    
    if not patient_id:
        flash('Please select a patient to assign.', 'warning')
        return redirect(url_for('ct1.bed_management'))
    
    try:
        # 1. Verify patient exists and get their current insurance_info
        p_res = client.table('patients').select('id, insurance_info').eq('id', int(patient_id)).single().execute()
        if not p_res.data:
            flash('Patient not found.', 'danger')
            return redirect(url_for('ct1.bed_management'))
            
        patient = p_res.data
        insurance = patient.get('insurance_info') or {}
        
        # 2. Check if patient is already assigned elsewhere (Workaround query)
        existing = client.table('patients').select('id').contains('insurance_info', {'current_bed_id': bed_id}).execute()
        if existing.data and any(e['id'] != int(patient_id) for e in existing.data):
             flash('This bed is already claimed by another patient record (metadata sync issue). Try clearing it first.', 'warning')
             # Note: We'll force clear the bed in step 4 anyway, but good to warn.

        # 3. Update Patient record with the bed assignment
        insurance['current_bed_id'] = bed_id
        client.table('patients').update({'insurance_info': insurance}).eq('id', int(patient_id)).execute()
        
        # 4. Update Bed status
        client.table('beds').update({'status': 'Occupied'}).eq('id', bed_id).execute()
        
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Assign Patient to Bed", BLUEPRINT_NAME, {"bed_id": bed_id, "patient_id": patient_id})
        flash('Patient assigned to bed successfully!', 'success')
    except Exception as e:
        flash(f'Error assigning patient: {str(e)}', 'danger')
    
    return redirect(url_for('ct1.bed_management'))

@ct1_bp.route('/beds/unassign/<int:bed_id>', methods=['POST'])
@login_required
def unassign_patient_from_bed(bed_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can unassign patients.', 'error')
        return redirect(url_for('ct1.bed_management'))
    
    client = get_supabase_client()
    
    try:
        # 1. Find the patient currently assigned to this bed via insurance_info
        assigned = client.table('patients').select('id, insurance_info').contains('insurance_info', {'current_bed_id': bed_id}).execute()
        
        if assigned.data:
            for p in assigned.data:
                insurance = p.get('insurance_info') or {}
                if 'current_bed_id' in insurance:
                    del insurance['current_bed_id']
                client.table('patients').update({'insurance_info': insurance}).eq('id', p['id']).execute()
        
        # 2. Mark bed for cleaning
        client.table('beds').update({
            'status': 'Cleaning'
        }).eq('id', bed_id).execute()
        
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Unassign Patient from Bed", BLUEPRINT_NAME, {"bed_id": bed_id})
        flash('Patient unassigned. Bed marked for cleaning.', 'success')
    except Exception as e:
        flash(f'Error unassigning patient: {str(e)}', 'danger')
    
    return redirect(url_for('ct1.bed_management'))


@ct1_bp.route('/beds/<int:bed_id>/discharge-report')
@login_required
def bed_discharge_report(bed_id):
    """Generate a PDF discharge summary for a bed."""
    from datetime import datetime
    from io import BytesIO
    from flask import make_response
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    except ImportError:
        flash('PDF library not available.', 'danger')
        return redirect(url_for('ct1.bed_management'))

    client = get_supabase_client()
    bed = None
    patient = None

    try:
        bed_res = client.table('beds').select('*').eq('id', bed_id).single().execute()
        bed = bed_res.data or {}
    except Exception:
        pass

    # Try to retrieve last assigned patient via insurance_info
    try:
        p_res = client.table('patients').select('*').contains('insurance_info', {'current_bed_id': bed_id}).execute()
        if p_res.data:
            patient = p_res.data[0]
    except Exception:
        pass

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    accent = colors.HexColor('#10B981')
    dark = colors.HexColor('#111827')

    header_style = ParagraphStyle('h1', parent=styles['Heading1'], textColor=dark, fontSize=16, spaceAfter=4)
    sub_style = ParagraphStyle('sub', parent=styles['Normal'], textColor=colors.HexColor('#6B7280'), fontSize=9)
    label_style = ParagraphStyle('lbl', parent=styles['Normal'], textColor=colors.HexColor('#374151'), fontSize=9, fontName='Helvetica-Bold')
    value_style = ParagraphStyle('val', parent=styles['Normal'], textColor=dark, fontSize=9)

    story = []
    story.append(Paragraph('HMS — Bed Discharge Report', header_style))
    story.append(Paragraph(f'Generated: {datetime.now().strftime("%B %d, %Y  %H:%M")}  |  Printed by: {current_user.username}', sub_style))
    story.append(Spacer(1, 8*mm))

    # Bed Details table
    room = bed.get('room_number', 'N/A')
    ward = bed.get('ward_name', 'N/A')
    btype = bed.get('type', 'N/A')
    status = bed.get('status', 'N/A')

    bed_data_table = [
        [Paragraph('Bed ID', label_style), Paragraph(str(bed_id), value_style),
         Paragraph('Room No.', label_style), Paragraph(room, value_style)],
        [Paragraph('Ward', label_style), Paragraph(ward, value_style),
         Paragraph('Type', label_style), Paragraph(btype, value_style)],
        [Paragraph('Current Status', label_style), Paragraph(status, value_style), '', ''],
    ]
    bed_table = Table(bed_data_table, colWidths=[35*mm, 50*mm, 35*mm, 50*mm])
    bed_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F0FDF4')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D1FAE5')),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#F9FAFB')]),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(Paragraph('Bed Information', ParagraphStyle('s2', parent=styles['Heading2'], textColor=accent, fontSize=11, spaceAfter=4)))
    story.append(bed_table)
    story.append(Spacer(1, 6*mm))

    # Patient info
    story.append(Paragraph('Last Assigned Patient', ParagraphStyle('s2b', parent=styles['Heading2'], textColor=accent, fontSize=11, spaceAfter=4)))
    if patient:
        pname = f"{patient.get('first_name','')} {patient.get('last_name','')}".strip()
        pid = patient.get('patient_id_alt', patient.get('id', 'N/A'))
        dob = patient.get('dob', 'N/A')
        contact = patient.get('contact_number', 'N/A')
        pt_data = [
            [Paragraph('Patient Name', label_style), Paragraph(pname, value_style),
             Paragraph('Patient ID', label_style), Paragraph(str(pid), value_style)],
            [Paragraph('Date of Birth', label_style), Paragraph(str(dob), value_style),
             Paragraph('Contact', label_style), Paragraph(str(contact), value_style)],
        ]
        pt_table = Table(pt_data, colWidths=[35*mm, 50*mm, 35*mm, 50*mm])
        pt_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#F9FAFB')]),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(pt_table)
    else:
        story.append(Paragraph('No patient currently assigned to this bed.', sub_style))

    story.append(Spacer(1, 10*mm))
    story.append(Paragraph('Discharge verified by ward staff. Bed queued for cleaning & sterilization.', sub_style))
    story.append(Spacer(1, 6*mm))

    # Signature line
    sig_data = [
        ['_________________________', '', '_________________________'],
        ['Ward Nurse / Attendant', '', 'CT1 Administrator'],
        ['Date: ___________________', '', 'Date: ___________________'],
    ]
    sig_table = Table(sig_data, colWidths=[60*mm, 40*mm, 60*mm])
    sig_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TEXTCOLOR', (0, 1), (-1, 1), colors.HexColor('#6B7280')),
    ]))
    story.append(sig_table)

    doc.build(story)
    buffer.seek(0)
    resp = make_response(buffer.read())
    resp.headers['Content-Type'] = 'application/pdf'
    resp.headers['Content-Disposition'] = f'attachment; filename="Discharge_Report_Bed{bed_id}_{datetime.now().strftime("%Y%m%d")}.pdf"'
    return resp

@ct1_bp.route('/beds/add', methods=['POST'])
@login_required
def add_bed():
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can add beds.', 'error')
        return redirect(url_for('ct1.bed_management'))
    
    client = get_supabase_client()
    try:
        room_number = request.form.get('room_number', '').strip()
        ward_name = request.form.get('ward_name', '').strip()

        # ── Duplicate room/ward check ──────────────────────────────────────────
        dup = client.table('beds').select('id').eq('room_number', room_number).eq('ward_name', ward_name).execute()
        if dup.data:
            flash(f'Room "{room_number}" already exists in "{ward_name}". Please use a unique room number.', 'warning')
            return redirect(url_for('ct1.bed_management'))

        bed_data = {
            'room_number': room_number,
            'ward_name': ward_name,
            'type': request.form.get('type'),
            'status': 'Available'
        }
        client.table('beds').insert(bed_data).execute()
        flash('Bed added successfully!', 'success')
    except Exception as e:
        flash(f'Error adding bed: {str(e)}', 'danger')
    return redirect(url_for('ct1.bed_management'))

@ct1_bp.route('/beds/delete/<int:bed_id>', methods=['POST'])
@login_required
def delete_bed(bed_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can delete beds.', 'error')
        return redirect(url_for('ct1.bed_management'))
        
    client = get_supabase_client()
    try:
        # Check if occupied
        res = client.table('beds').select('status').eq('id', bed_id).execute()
        if res.data and res.data[0]['status'] == 'Occupied':
            flash('Cannot delete an occupied bed.', 'warning')
            return redirect(url_for('ct1.bed_management'))
            
        client.table('beds').delete().eq('id', bed_id).execute()
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Delete Bed", BLUEPRINT_NAME, {"bed_id": bed_id})
        flash('Bed deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error deleting bed: {str(e)}', 'danger')
    return redirect(url_for('ct1.bed_management'))

@ct1_bp.route('/triage', methods=['GET', 'POST'])
@login_required
def emergency_triage():
    from utils.hms_models import Patient, ERTriage
    client = get_supabase_client()
    
    if request.method == 'POST':
        try:
            triage_data = {
                'patient_id': request.form.get('patient_id'),
                'complaint': request.form.get('complaint'),
                'priority_level': request.form.get('priority_level'),
                'pain_score': int(request.form.get('pain_score') or 0),
                'vitals': {
                    'bp': request.form.get('bp'),
                    'hr': request.form.get('hr'),
                    'temp': request.form.get('temp'),
                    'resp': request.form.get('resp'),
                    'spo2': request.form.get('spo2')
                },
                'triage_officer_id': current_user.id,
                'status': 'Waiting',
                'notes': request.form.get('notes')
            }
            ERTriage.create(triage_data)
            flash('Triage record created successfully.', 'success')
        except Exception as e:
            flash(f'Error creating triage: {str(e)}', 'danger')
            
    triage_list = ERTriage.get_all()
    patients = Patient.get_all()
    
    return render_template('subsystems/core_transaction/ct1/triage.html',
                           triage_list=triage_list,
                           patients=patients,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct1_bp.route('/triage/update-status/<int:triage_id>', methods=['POST'])
@login_required
def update_triage_status(triage_id):
    client = get_supabase_client()
    new_status = request.form.get('status')
    try:
        client.table('er_triage').update({'status': new_status}).eq('id', triage_id).execute()
        flash(f'Triage status updated to {new_status}.', 'success')
    except Exception as e:
        flash(f'Error updating status: {str(e)}', 'danger')
    return redirect(url_for('ct1.emergency_triage'))

@ct1_bp.route('/telehealth')
@login_required
def telehealth():
    from utils.hms_models import Patient, TelehealthSession
    client = get_supabase_client()
    
    sessions = TelehealthSession.get_all()
    patients = Patient.get_all()
    # Doctors for meeting
    doctors = client.table('users').select('*').in_('subsystem', ['ct2', 'ct3']).execute().data or []
    
    return render_template('subsystems/core_transaction/ct1/telehealth.html',
                           sessions=sessions,
                           patients=patients,
                           doctors=doctors,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct1_bp.route('/telehealth/schedule', methods=['POST'])
@login_required
def schedule_telehealth():
    from utils.hms_models import TelehealthSession
    try:
        import uuid
        scheduled_at = request.form.get('scheduled_at') or ''
        # §4.2 Auto-generate unique Jitsi meeting link if none provided
        raw_link = (request.form.get('meeting_link') or '').strip()
        if not raw_link:
            room_token = uuid.uuid4().hex[:16]
            raw_link = f'https://meet.jit.si/hms-{room_token}'
        data = {
            'patient_id': request.form.get('patient_id'),
            'doctor_id': request.form.get('doctor_id'),
            'scheduled_at': scheduled_at,
            'meeting_link': raw_link,
            'notes': request.form.get('notes'),
            'status': 'Scheduled'
        }
        TelehealthSession.create(data)
        flash(f'Telehealth session scheduled. Meeting link: {raw_link}', 'success')
    except Exception as e:
        flash(f'Error scheduling: {str(e)}', 'danger')
    return redirect(url_for('ct1.telehealth'))


@ct1_bp.route('/telehealth/<int:session_id>/start', methods=['POST'])
@login_required
def start_telehealth_session(session_id):
    """Record session start time and mark In Progress."""
    from datetime import datetime
    client = get_supabase_client()
    try:
        client.table('telehealth_sessions').update({
            'status': 'In Progress',
            'started_at': datetime.utcnow().isoformat()
        }).eq('id', session_id).execute()
        flash('Session started. Duration tracking begun.', 'success')
    except Exception as e:
        flash(f'Error starting session: {str(e)}', 'danger')
    return redirect(url_for('ct1.telehealth'))


@ct1_bp.route('/telehealth/<int:session_id>/end', methods=['POST'])
@login_required
def end_telehealth_session(session_id):
    """Record session end time, compute duration, mark Completed."""
    from datetime import datetime
    client = get_supabase_client()
    try:
        sess_res = client.table('telehealth_sessions').select('started_at').eq('id', session_id).single().execute()
        duration_minutes = None
        if sess_res.data and sess_res.data.get('started_at'):
            started = datetime.fromisoformat(sess_res.data['started_at'].replace('Z', '+00:00'))
            duration_minutes = int((datetime.utcnow() - started.replace(tzinfo=None)).total_seconds() / 60)
        update_data = {
            'status': 'Completed',
            'ended_at': datetime.utcnow().isoformat()
        }
        if duration_minutes is not None:
            update_data['duration_minutes'] = duration_minutes
        client.table('telehealth_sessions').update(update_data).eq('id', session_id).execute()

        # §4.10 Create / update medical_records entry
        try:
            sess_full = client.table('telehealth_sessions').select(
                'patient_id, doctor_id, notes, appointment_id').eq('id', session_id).single().execute()
            if sess_full.data:
                sd = sess_full.data
                client.table('medical_records').insert({
                    'patient_id': sd.get('patient_id'),
                    'appointment_id': sd.get('appointment_id'),
                    'session_id': session_id,
                    'record_type': 'Telehealth',
                    'notes': sd.get('notes'),
                    'recorded_by': current_user.id,
                }).execute()
        except Exception:
            pass  # non-fatal

        msg = f'Session completed. Duration: {duration_minutes} min.' if duration_minutes is not None else 'Session completed.'
        flash(msg, 'success')
    except Exception as e:
        flash(f'Error ending session: {str(e)}', 'danger')
    return redirect(url_for('ct1.telehealth'))

@ct1_bp.route('/logout')
@login_required
def logout():
    from utils.hms_models import AuditLog
    AuditLog.log(current_user.id, "Logout", BLUEPRINT_NAME)
    logout_user()
    return redirect(url_for('ct1.login'))

@ct1_bp.route('/appointment/<int:appointment_id>/cancel', methods=['POST'])
@login_required
def cancel_appointment(appointment_id):
    from datetime import datetime, timedelta
    client = get_supabase_client()
    try:
        appt_res = client.table('appointments').select('*').eq('id', appointment_id).single().execute()
        if not appt_res.data:
            flash('Appointment not found.', 'danger')
            return redirect(request.referrer or url_for('ct1.dashboard'))
        
        appt = appt_res.data
        late_cancel_fee = False

        # ── 24-hour late-cancel rule ───────────────────────────────────────────
        appt_date_str = appt.get('appointment_date', '')
        if appt_date_str:
            try:
                appt_dt = datetime.fromisoformat(appt_date_str.replace('Z', '+00:00').replace(' ', 'T'))
                appt_dt_naive = appt_dt.replace(tzinfo=None)
                hours_until = (appt_dt_naive - datetime.now()).total_seconds() / 3600
                if 0 < hours_until < 24:
                    late_cancel_fee = True
            except Exception:
                pass

        client.table('appointments').update({'status': 'Cancelled'}).eq('id', appointment_id).execute()

        # Create late-cancel billing record (₱560)
        if late_cancel_fee and appt.get('patient_id'):
            try:
                client.table('billing_records').insert({
                    'patient_id': appt['patient_id'],
                    'description': 'Late Cancellation Fee (< 24h notice)',
                    'total_amount': 560.00,
                    'status': 'Pending',
                    'category': 'Administrative Fee'
                }).execute()
                flash('Appointment cancelled. A ₱560.00 late cancellation fee has been recorded (within 24h of appointment).', 'warning')
            except Exception as fee_err:
                flash(f'Appointment cancelled with late cancel fee (billing error: {fee_err}).', 'warning')
        else:
            flash('Appointment cancelled.', 'info')

    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct1.dashboard'))


@ct1_bp.route('/appointment/<int:appointment_id>/flag-noshow', methods=['POST'])
@login_required
def flag_noshow(appointment_id):
    """Mark appointment as No-Show, charge ₱1,500 penalty, increment no-show counter."""
    from datetime import datetime
    client = get_supabase_client()
    try:
        appt_res = client.table('appointments').select('*').eq('id', appointment_id).single().execute()
        if not appt_res.data:
            flash('Appointment not found.', 'danger')
            return redirect(request.referrer or url_for('ct1.dashboard'))
        
        appt = appt_res.data
        patient_id = appt.get('patient_id')

        # Mark as No-Show
        client.table('appointments').update({'status': 'No-Show'}).eq('id', appointment_id).execute()

        if patient_id:
            # Create no-show billing record (₱1,500)
            try:
                client.table('billing_records').insert({
                    'patient_id': patient_id,
                    'description': 'No-Show Penalty',
                    'total_amount': 1500.00,
                    'status': 'Pending',
                    'category': 'Administrative Fee'
                }).execute()
            except Exception:
                pass

            # Increment no-show counter — new no_show_count column + legacy JSONB
            try:
                p_res = client.table('patients').select('insurance_info, no_show_count').eq('id', patient_id).single().execute()
                if p_res.data:
                    cur_count = int(p_res.data.get('no_show_count') or 0) + 1
                    info = p_res.data.get('insurance_info') or {}
                    info['no_show_count'] = cur_count
                    client.table('patients').update({
                        'no_show_count': cur_count,
                        'insurance_info': info,
                        'is_banned': cur_count >= 3,
                        'ban_reason': 'Exceeded 3 no-show limit' if cur_count >= 3 else None
                    }).eq('id', patient_id).execute()
                    if cur_count >= 3:
                        flash(f'No-Show flagged. ₱1,500 penalty recorded. Patient now has {cur_count} no-shows — portal booking restricted.', 'warning')
                    else:
                        flash(f'No-Show flagged. ₱1,500 penalty recorded. ({cur_count}/3 strikes)', 'warning')
            except Exception:
                flash('No-Show flagged. ₱1,500 penalty recorded.', 'warning')
    except Exception as e:
        flash(f'Error flagging no-show: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct1.dashboard'))


@ct1_bp.route('/appointment/<int:appointment_id>/mark-arrived', methods=['POST'])
@login_required
def mark_arrived(appointment_id):
    """Mark patient as having arrived for their appointment."""
    from datetime import datetime
    client = get_supabase_client()
    try:
        client.table('appointments').update({
            'status': 'Arrived',
            'checked_in_at': datetime.utcnow().isoformat()
        }).eq('id', appointment_id).execute()
        flash('Patient arrival confirmed.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct1.dashboard'))


# ─── §3.2 Reschedule appointment ─────────────────────────────────────────────
@ct1_bp.route('/appointment/<int:appointment_id>/reschedule', methods=['POST'])
@login_required
def reschedule_appointment(appointment_id):
    """Reschedule an existing appointment (max 1 reschedule, 24h-advance rule)."""
    from datetime import datetime, timedelta
    client = get_supabase_client()
    try:
        appt_res = client.table('appointments').select('*').eq('id', appointment_id).single().execute()
        if not appt_res.data:
            flash('Appointment not found.', 'danger')
            return redirect(request.referrer or url_for('ct1.dashboard'))

        appt = appt_res.data

        # Max 1 reschedule rule
        if int(appt.get('reschedule_count') or 0) >= 1:
            flash('This appointment has already been rescheduled once. Further rescheduling is not allowed.', 'danger')
            return redirect(request.referrer or url_for('ct1.dashboard'))

        # 24-hour advance notice rule
        appt_date_str = appt.get('appointment_date', '')
        if appt_date_str:
            try:
                appt_dt = datetime.fromisoformat(appt_date_str.replace('Z', '+00:00').replace(' ', 'T')).replace(tzinfo=None)
                if (appt_dt - datetime.now()).total_seconds() < 86400:
                    flash('Rescheduling requires at least 24 hours advance notice.', 'danger')
                    return redirect(request.referrer or url_for('ct1.dashboard'))
            except Exception:
                pass

        new_date_str = request.form.get('new_appointment_date', '')
        if not new_date_str:
            flash('New appointment date is required.', 'danger')
            return redirect(request.referrer or url_for('ct1.dashboard'))

        # Validate new date time window (7AM–3PM)
        try:
            new_dt = datetime.fromisoformat(new_date_str.replace('T', ' '))
            if new_dt < datetime.now():
                flash('New appointment date cannot be in the past.', 'danger')
                return redirect(request.referrer or url_for('ct1.dashboard'))
            if not (7 <= new_dt.hour < 15):
                flash('New appointment must be between 7:00 AM and 3:00 PM.', 'danger')
                return redirect(request.referrer or url_for('ct1.dashboard'))
        except ValueError:
            flash('Invalid date/time format for reschedule.', 'danger')
            return redirect(request.referrer or url_for('ct1.dashboard'))

        # Check new slot isn't already taken
        dup = client.table('appointments').select('id').eq(
            'doctor_id', appt.get('doctor_id')).eq('appointment_date', new_date_str).in_(
            'status', ['Scheduled', 'Arrived']).neq('id', appointment_id).execute()
        if dup.data:
            flash('The selected doctor is already booked at that time. Please choose a different slot.', 'danger')
            return redirect(request.referrer or url_for('ct1.dashboard'))

        client.table('appointments').update({
            'appointment_date': new_date_str,
            'status': 'Scheduled',
            'reschedule_count': int(appt.get('reschedule_count') or 0) + 1,
            'last_rescheduled_at': datetime.utcnow().isoformat(),
            'original_date': appt_date_str,
        }).eq('id', appointment_id).execute()

        # Notify patient
        try:
            from utils.hms_models import Notification
            portal_user = client.table('users').select('id').eq('patient_id', appt.get('patient_id')).execute()
            if portal_user.data:
                Notification.create(
                    user_id=portal_user.data[0]['id'],
                    subsystem='patient',
                    title='Appointment Rescheduled',
                    message=f'Your appointment has been rescheduled to {new_date_str}.',
                    n_type='info',
                    sender_subsystem=BLUEPRINT_NAME,
                    target_url=url_for('ct1.dashboard')
                )
        except Exception:
            pass

        flash('Appointment rescheduled successfully.', 'success')
    except Exception as e:
        flash(f'Reschedule error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct1.dashboard'))


# ─── §3.4 Auto no-show check (called on dashboard load or via AJAX) ────────
@ct1_bp.route('/appointment/auto-noshow-check', methods=['POST'])
@login_required
def auto_noshow_check():
    """Mark past-due Scheduled appointments as No-Show (15-min grace period)."""
    from datetime import datetime, timedelta
    from flask import jsonify
    client = get_supabase_client()
    flagged = []
    try:
        cutoff = (datetime.utcnow() - timedelta(minutes=15)).isoformat()
        overdue = client.table('appointments').select('*').eq('status', 'Scheduled').lt(
            'appointment_date', cutoff).execute()
        for appt in (overdue.data or []):
            appt_id = appt['id']
            patient_id = appt.get('patient_id')
            client.table('appointments').update({'status': 'No-Show'}).eq('id', appt_id).execute()
            if patient_id:
                try:
                    client.table('billing_records').insert({
                        'patient_id': patient_id,
                        'description': 'No-Show Penalty (auto)',
                        'total_amount': 1500.00,
                        'status': 'Pending',
                        'category': 'Administrative Fee'
                    }).execute()
                    p_res = client.table('patients').select('no_show_count, insurance_info, is_banned').eq(
                        'id', patient_id).single().execute()
                    if p_res.data:
                        cur = int(p_res.data.get('no_show_count') or 0) + 1
                        info = p_res.data.get('insurance_info') or {}
                        info['no_show_count'] = cur
                        client.table('patients').update({
                            'no_show_count': cur, 'insurance_info': info,
                            'is_banned': cur >= 3,
                            'ban_reason': 'Exceeded 3 no-show limit' if cur >= 3 else None
                        }).eq('id', patient_id).execute()
                except Exception:
                    pass
            flagged.append(appt_id)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    return jsonify({'flagged': flagged, 'count': len(flagged)})


# ─── §3.1 / §4.3 AJAX: booked slots per doctor+date ──────────────────────────
@ct1_bp.route('/appointment/booked-slots')
@login_required
def booked_slots():
    """Return list of booked datetime strings for a given doctor on a given date."""
    from flask import jsonify
    doctor_id = request.args.get('doctor_id')
    date_str  = request.args.get('date')          # YYYY-MM-DD
    if not doctor_id or not date_str:
        return jsonify({'slots': []})
    try:
        client = get_supabase_client()
        # Fetch all scheduled/arrived appointments for that doctor on that date
        res = client.table('appointments').select('appointment_date').eq(
            'doctor_id', doctor_id).in_('status', ['Scheduled', 'Arrived']).execute()
        slots = []
        for row in (res.data or []):
            d = row.get('appointment_date', '')
            if d.startswith(date_str):
                # Return just the time portion HH:MM
                try:
                    t = d[11:16] if 'T' in d else d[11:16]
                    slots.append(t)
                except Exception:
                    pass
        return jsonify({'slots': slots})
    except Exception as e:
        return jsonify({'slots': [], 'error': str(e)})


# ─── §4.7 Digital prescription PDF ───────────────────────────────────────────
@ct1_bp.route('/telehealth/<int:session_id>/prescription-pdf')
@login_required
def prescription_pdf(session_id):
    """Generate and return a ReportLab PDF prescription for a completed session."""
    from flask import make_response
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    import io, textwrap

    client = get_supabase_client()
    try:
        sess = client.table('telehealth_sessions').select(
            '*, patients(first_name, last_name, dob, contact_number), users!telehealth_sessions_doctor_id_fkey(full_name)'
        ).eq('id', session_id).single().execute()
        if not sess.data:
            flash('Session not found.', 'danger')
            return redirect(url_for('ct1.telehealth'))
        s = sess.data
        patient = s.get('patients') or {}
        doctor  = s.get('users')    or {}

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        story  = []

        # Header
        story.append(Paragraph('<b>HMS — Hospital Management System</b>', styles['Title']))
        story.append(Paragraph('<b>DIGITAL PRESCRIPTION / SESSION SUMMARY</b>', styles['Heading2']))
        story.append(HRFlowable(width='100%', color=colors.HexColor('#10B981')))
        story.append(Spacer(1, 0.4*cm))

        # Patient / session info table
        pname = f"{patient.get('first_name','')} {patient.get('last_name','')}".strip()
        info_data = [
            ['Patient', pname,          'Session ID',  f'#{session_id}'],
            ['DOB',     patient.get('dob','—'),  'Doctor',      doctor.get('full_name','—')],
            ['Contact', patient.get('contact_number','—'), 'Date', (s.get('scheduled_at','') or '')[:10]],
            ['Status',  s.get('status','—'),     'Duration',    f"{s.get('duration_minutes','—')} min"],
        ]
        t = Table(info_data, colWidths=[3*cm, 6*cm, 3*cm, 6*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F0FDF4')),
            ('TEXTCOLOR',  (0,0), (0,-1), colors.HexColor('#065F46')),
            ('TEXTCOLOR',  (2,0), (2,-1), colors.HexColor('#065F46')),
            ('FONTNAME',   (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE',   (0,0), (-1,-1), 9),
            ('GRID',       (0,0), (-1,-1), 0.5, colors.HexColor('#D1FAE5')),
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, colors.HexColor('#F0FDF4')]),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.6*cm))

        # Notes / diagnosis / prescription
        for label, field in [('Clinical Notes', 'notes'), ('Diagnosis', 'diagnosis'),
                              ('Prescription', 'prescription_url')]:
            val = s.get(field) or '—'
            story.append(Paragraph(f'<b>{label}</b>', styles['Heading3']))
            story.append(Paragraph(val, styles['Normal']))
            story.append(Spacer(1, 0.3*cm))

        story.append(Spacer(1, 1*cm))
        story.append(HRFlowable(width='100%', color=colors.HexColor('#D1FAE5')))
        story.append(Paragraph('This document was auto-generated by HMS. Not valid without attending physician signature.', styles['Italic']))

        doc.build(story)
        buf.seek(0)
        resp = make_response(buf.read())
        resp.headers['Content-Type']        = 'application/pdf'
        resp.headers['Content-Disposition'] = f'attachment; filename="prescription_session_{session_id}.pdf"'
        return resp
    except Exception as e:
        flash(f'PDF error: {str(e)}', 'danger')
        return redirect(url_for('ct1.telehealth'))


# ─── §4.8 Upload medical document for a patient ──────────────────────────────
@ct1_bp.route('/patient/<int:patient_id>/upload-document', methods=['POST'])
@login_required
def upload_patient_document(patient_id):
    """Upload a medical document to patient-documents storage bucket."""
    file = request.files.get('document')
    if not file or not file.filename:
        flash('No file selected.', 'danger')
        return redirect(request.referrer or url_for('ct1.list_patients'))

    allowed = {'pdf', 'jpg', 'jpeg', 'png'}
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in allowed:
        flash('Only PDF, JPG, PNG files are accepted.', 'danger')
        return redirect(request.referrer or url_for('ct1.list_patients'))

    file.seek(0, 2)
    size = file.tell(); file.seek(0)
    if size > 10 * 1024 * 1024:
        flash('File must be smaller than 10 MB.', 'danger')
        return redirect(request.referrer or url_for('ct1.list_patients'))

    try:
        from datetime import datetime
        client = get_supabase_client()
        ts    = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        label = (request.form.get('label') or 'document').replace(' ', '_')[:40]
        path  = f"patients/{patient_id}/{label}_{ts}.{ext}"
        data  = file.read()
        client.storage.from_('patient-documents').upload(
            path, data,
            {'content-type': file.content_type or 'application/octet-stream'}
        )
        pub = client.storage.from_('patient-documents').get_public_url(path)
        url = pub if isinstance(pub, str) else pub.get('publicUrl', path)
        # Store URL in medical_records
        client.table('medical_records').insert({
            'patient_id': patient_id,
            'record_type': 'Document',
            'notes': f'Uploaded: {label}',
            'prescription': url,
            'recorded_by': current_user.id,
        }).execute()
        flash(f'Document "{label}" uploaded successfully.', 'success')
    except Exception as e:
        flash(f'Upload error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct1.list_patients'))


# ─── §4.12 Follow-up scheduling from completed telehealth session ─────────────
@ct1_bp.route('/telehealth/<int:session_id>/follow-up', methods=['GET', 'POST'])
@login_required
def telehealth_follow_up(session_id):
    """Pre-filled appointment booking form from a completed telehealth session."""
    from utils.hms_models import Patient, Appointment
    client = get_supabase_client()
    sess_res = client.table('telehealth_sessions').select('*').eq('id', session_id).single().execute()
    if not sess_res.data:
        flash('Session not found.', 'danger')
        return redirect(url_for('ct1.telehealth'))

    sess = sess_res.data

    if request.method == 'POST':
        appt_dt_str = request.form.get('appointment_date', '')
        try:
            appt_dt = datetime.fromisoformat(appt_dt_str.replace('T', ' '))
            if appt_dt < datetime.now():
                flash('Follow-up date cannot be in the past.', 'danger')
            elif not (7 <= appt_dt.hour < 15):
                flash('Appointments must be between 7:00 AM and 3:00 PM.', 'danger')
            else:
                Appointment.create({
                    'patient_id': sess.get('patient_id'),
                    'doctor_id':  sess.get('doctor_id'),
                    'appointment_date': appt_dt_str,
                    'type': 'Follow-up',
                    'visit_type': 'Follow-up',
                    'status': 'Scheduled',
                    'notes': request.form.get('notes', ''),
                    'terms_agreed': True,
                })
                flash('Follow-up appointment scheduled.', 'success')
                return redirect(url_for('ct1.dashboard'))
        except ValueError:
            flash('Invalid date format.', 'danger')

    patients = Patient.get_all()
    doctors  = client.table('users').select('*').in_('subsystem', ['ct2', 'ct3']).execute().data or []
    return render_template('subsystems/core_transaction/ct1/book_appointment.html',
                           now=datetime.utcnow,
                           doctors=doctors,
                           patients=patients,
                           prefill_session=sess,
                           selected_patient_id=str(sess.get('patient_id', '')),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)
