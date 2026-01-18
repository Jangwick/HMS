from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error, get_supabase_client
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
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
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('shared/login.html', 
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
                        flash('Your account is awaiting approval from HR3 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('shared/login.html',
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           subsystem_icon=SUBSYSTEM_ICON,
                                           blueprint_name=BLUEPRINT_NAME,
                                           hub_route='portal.ct_hub')

                # Clear IP lockout attempts on successful login
                register_successful_login()
                user.register_successful_login()
                
                if login_user(user):
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
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
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

@ct1_bp.route('/register', methods=['GET', 'POST'])
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
                return redirect(url_for('ct1.login'))
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
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    today_end = datetime.now().replace(hour=23, minute=59, second=59, microsecond=999).isoformat()
    appointments_today = client.table('appointments').select('id', count='exact').gte('appointment_date', today_start).lte('appointment_date', today_end).execute().count or 0

    upcoming_appointments = Appointment.get_upcoming()
    
    metrics = {
        'total_patients': total_patients,
        'new_patients_week': new_patients_week,
        'appointments_today': appointments_today,
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
    patients = Patient.get_all()
    return render_template('subsystems/core_transaction/ct1/patient_list.html',
                           now=datetime.utcnow,
                           patients=patients,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct1_bp.route('/register-patient', methods=['GET', 'POST'])
@login_required
def register_patient():
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
                    'provider': request.form.get('insurance_provider'),
                    'policy_number': request.form.get('policy_number'),
                    'group_number': request.form.get('group_number')
                }
            }
            patient = Patient.create(patient_data)
            if patient:
                flash(f'Patient {patient.first_name} {patient.last_name} registered successfully! ID: {patient.patient_id_alt}', 'success')
                return redirect(url_for('ct1.list_patients'))
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
    response = client.table('patients').select('*, appointments(*)').eq('id', patient_id).single().execute()
    if not response.data:
        flash('Patient not found.', 'danger')
        return redirect(url_for('ct1.list_patients'))
    
    patient = response.data
    appointments = patient.pop('appointments', [])
    
    return render_template('subsystems/core_transaction/ct1/view_patient.html',
                           now=datetime.utcnow,
                           patient=patient,
                           appointments=appointments,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct1_bp.route('/book-appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    from datetime import datetime
    from utils.hms_models import Patient, Appointment
    if request.method == 'POST':
        try:
            appointment_data = {
                'patient_id': request.form.get('patient_id'),
                'doctor_id': request.form.get('doctor_id'), # Now selectable
                'appointment_date': request.form.get('appointment_date'),
                'type': request.form.get('type'),
                'status': 'Scheduled',
                'notes': request.form.get('notes')
            }
            appointment = Appointment.create(appointment_data)
            if appointment:
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
    
    return render_template('subsystems/core_transaction/ct1/book_appointment.html', 
                           now=datetime.utcnow,
                           doctors=doctors,
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

@ct1_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('ct1.login'))
