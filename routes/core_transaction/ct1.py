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
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
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
                        flash('Your account is awaiting approval from HR3 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('subsystems/core_transaction/ct1/login.html',
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
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    today_end = datetime.now().replace(hour=23, minute=59, second=59, microsecond=999).isoformat()
    appointments_today = client.table('appointments').select('id', count='exact').gte('appointment_date', today_start).lte('appointment_date', today_end).execute().count or 0

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
        updated_data = {
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
        client.table('patients').update(updated_data).eq('id', patient_id).execute()
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
        
        # Fetch patients for any future admission logic
        patients_resp = client.table('patients').select('id, first_name, last_name, patient_id_alt').execute()
        patients_list = patients_resp.data if patients_resp.data else []
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
        flash(f'Bed status updated to {new_status}.', 'success')
    except Exception as e:
        flash(f'Error updating bed: {str(e)}', 'danger')
        
    return redirect(url_for('ct1.bed_management'))

@ct1_bp.route('/beds/add', methods=['POST'])
@login_required
def add_bed():
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can add beds.', 'error')
        return redirect(url_for('ct1.bed_management'))
    
    client = get_supabase_client()
    try:
        bed_data = {
            'room_number': request.form.get('room_number'),
            'ward_name': request.form.get('ward_name'),
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
        flash('Bed deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error deleting bed: {str(e)}', 'danger')
    return redirect(url_for('ct1.bed_management'))

@ct1_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('ct1.login'))

@ct1_bp.route('/appointment/<int:appointment_id>/cancel', methods=['POST'])
@login_required
def cancel_appointment(appointment_id):
    client = get_supabase_client()
    try:
        client.table('appointments').update({'status': 'Cancelled'}).eq('id', appointment_id).execute()
        flash('Appointment cancelled.', 'info')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct1.dashboard'))
