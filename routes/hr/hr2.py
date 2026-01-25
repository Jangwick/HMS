from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from datetime import datetime

hr2_bp = Blueprint('hr2', __name__)

# Subsystem configuration
SUBSYSTEM_NAME = 'HR2 - Talent Development'
ACCENT_COLOR = '#0891B2'
BLUEPRINT_NAME = 'hr2'

@hr2_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/hr/hr2/login.html', remaining_seconds=remaining_seconds)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.get_by_username(username, BLUEPRINT_NAME)
        
        if user:
            now_utc = datetime.utcnow()
            
            if user.check_password(password):
                # Check if account is approved
                if user.status != 'Active':
                    if user.status == 'Pending':
                        flash('Your account is awaiting approval from HR3 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('subsystems/hr/hr2/login.html')

                # Check for password expiration - redirect to change password
                if user.password_expires_at and user.password_expires_at < now_utc:
                    session['expired_user_id'] = user.id
                    session['expired_subsystem'] = BLUEPRINT_NAME
                    flash('Your password has expired. Please set a new password to continue.', 'warning')
                    return redirect(url_for('hr2.change_password'))

                # Clear IP lockout attempts on successful login
                register_successful_login()
                user.register_successful_login()
                
                if login_user(user):
                    days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                    if days_left <= 7:
                        flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    return redirect(url_for('hr2.dashboard'))
                else:
                    flash('Login failed. Your account may be deactivated.', 'danger')
                    return render_template('subsystems/hr/hr2/login.html')
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/hr/hr2/login.html', remaining_seconds=remaining_seconds)
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
                return render_template('subsystems/hr/hr2/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/hr/hr2/login.html')

@hr2_bp.route('/register', methods=['GET', 'POST'])
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
                department='HR',
                status='Pending'
            )
            
            if new_user:
                flash('Registration successful! Your account is awaiting approval from HR3 Admin.', 'success')
                return redirect(url_for('hr2.login'))
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
                           hub_route='portal.hr_hub',
                           accent_color=ACCENT_COLOR)

@hr2_bp.route('/change-password', methods=['GET', 'POST'])
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
            return redirect(url_for('hr2.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('hr2.login'))
    
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
            return redirect(url_for('hr2.login'))
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html',
        subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@hr2_bp.route('/dashboard')
@login_required
@policy_required(BLUEPRINT_NAME)
def dashboard():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Get Talent Development stats
    try:
        # Get pending onboarding
        response = client.table('onboarding').select('id', count='exact').eq('status', 'Pending').execute()
        pending_onboarding = response.count if response.count is not None else 0
        
        # Get active trainings
        response = client.table('trainings').select('id', count='exact').execute()
        active_trainings = response.count if response.count is not None else 0
        
        # Get total competencies defined
        response = client.table('competencies').select('id', count='exact').execute()
        total_competencies = response.count if response.count is not None else 0
        
        # Recent onboarding items
        recent_onboarding_resp = client.table('onboarding').select('*, applicants(first_name, last_name)').order('created_at', desc=True).limit(5).execute()
        recent_onboarding = recent_onboarding_resp.data if recent_onboarding_resp.data else []
        
    except Exception as e:
        print(f"Error fetching stats: {e}")
        pending_onboarding = 0
        active_trainings = 0
        total_competencies = 0
        recent_onboarding = []
    
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
        
    return render_template('subsystems/hr/hr2/dashboard.html', 
                           now=datetime.utcnow,
                           pending_onboarding=pending_onboarding,
                           active_trainings=active_trainings,
                           total_competencies=total_competencies,
                           recent_onboarding=recent_onboarding,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/onboarding')
@login_required
@policy_required(BLUEPRINT_NAME)
def onboarding_pipeline():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch records from onboarding joined with applicants
    response = client.table('onboarding').select('*, applicants(*)').execute()
    onboarding_list = response.data if response.data else []
    
    return render_template('subsystems/hr/hr2/onboarding.html',
                           onboarding_list=onboarding_list,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/onboarding/start/<int:id>', methods=['POST'])
@login_required
def start_onboarding(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.onboarding_pipeline'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        client.table('onboarding').update({'status': 'In Progress'}).eq('id', id).execute()
        flash('Onboarding process started!', 'info')
    except Exception as e:
        flash(f'Error starting process: {str(e)}', 'danger')
    return redirect(url_for('hr2.onboarding_pipeline'))

@hr2_bp.route('/onboarding/complete', methods=['POST'])
@login_required
def complete_onboarding():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.onboarding_pipeline'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    onboarding_id = request.form.get('onboarding_id')
    start_date = request.form.get('start_date')
    
    try:
        # Update onboarding status and start date
        client.table('onboarding').update({
            'status': 'Completed',
            'start_date': start_date
        }).eq('id', onboarding_id).execute()
        
        # Also update the applicant status to reflect successful hire
        response = client.table('onboarding').select('applicant_id').eq('id', onboarding_id).single().execute()
        if response.data:
            client.table('applicants').update({'status': 'Hired'}).eq('id', response.data['applicant_id']).execute()
            
        flash('Onboarding completed! Candidate is now marked as Hired.', 'success')
    except Exception as e:
        flash(f'Error finishing onboarding: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.onboarding_pipeline'))

@hr2_bp.route('/trainings')
@login_required
def list_trainings():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch trainings with their participant counts
    response = client.table('trainings').select('*').order('schedule_date', desc=True).execute()
    trainings = response.data if response.data else []
    
    # Fetch participants for all trainings to show counts and details
    participants_response = client.table('training_participants').select('*, users(username, department, role)').execute()
    participants = participants_response.data if participants_response.data else []

    # Attach participant counts and ensure numeric values for template calculations
    for training in trainings:
        training['participant_count'] = len([p for p in participants if p['training_id'] == training['id']])
        training['max_participants'] = int(training.get('max_participants') or 0)

    # Fetch active staff for enrollment dropdown
    staff_response = client.table('users').select('id, username, department, role').eq('status', 'Active').execute()
    staff_members = staff_response.data if staff_response.data else []

    # Calculate basic stats
    stats = {
        'total': len(trainings),
        'scheduled': len([t for t in trainings if t['status'] == 'Scheduled']),
        'completed': len([t for t in trainings if t['status'] == 'Completed']),
        'total_participants': len(participants)
    }
    
    return render_template('subsystems/hr/hr2/trainings.html',
                           trainings=trainings,
                           participants=participants,
                           staff_members=staff_members,
                           stats=stats,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/trainings/add', methods=['GET', 'POST'])
@login_required
def add_training():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_trainings'))
        
    if request.method == 'POST':
        from utils.supabase_client import get_supabase_client
        client = get_supabase_client()
        
        data = {
            'title': request.form.get('title'),
            'type': request.form.get('type'),
            'schedule_date': request.form.get('schedule_date'),
            'description': request.form.get('description'),
            'location': request.form.get('location'),
            'trainer': request.form.get('trainer'),
            'target_department': request.form.get('target_department'),
            'max_participants': request.form.get('max_participants'),
            'materials_url': request.form.get('materials_url'),
            'status': 'Scheduled'
        }
        
        try:
            client.table('trainings').insert(data).execute()
            flash('Training session scheduled successfully!', 'success')
        except Exception as e:
            flash(f'Error scheduling training: {str(e)}', 'danger')
            
        return redirect(url_for('hr2.list_trainings'))
    
    return redirect(url_for('hr2.list_trainings'))

@hr2_bp.route('/trainings/edit/<int:id>', methods=['POST'])
@login_required
def edit_training(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_trainings'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    data = {
        'title': request.form.get('title'),
        'type': request.form.get('type'),
        'schedule_date': request.form.get('schedule_date'),
        'description': request.form.get('description'),
        'location': request.form.get('location'),
        'trainer': request.form.get('trainer'),
        'target_department': request.form.get('target_department'),
        'max_participants': request.form.get('max_participants'),
        'materials_url': request.form.get('materials_url')
    }
    
    try:
        client.table('trainings').update(data).eq('id', id).execute()
        flash('Training session updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating training: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_trainings'))

@hr2_bp.route('/trainings/delete/<int:id>', methods=['POST'])
@login_required
def delete_training(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_trainings'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('trainings').delete().eq('id', id).execute()
        flash('Training session removed.', 'info')
    except Exception as e:
        flash(f'Error deleting training: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_trainings'))

@hr2_bp.route('/trainings/complete/<int:id>', methods=['POST'])
@login_required
def complete_training(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_trainings'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('trainings').update({'status': 'Completed'}).eq('id', id).execute()
        flash('Training marked as completed!', 'success')
    except Exception as e:
        flash(f'Error updating training: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_trainings'))

@hr2_bp.route('/trainings/enroll', methods=['POST'])
@login_required
def enroll_staff():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    training_id = request.form.get('training_id')
    user_id = request.form.get('user_id')
    
    try:
        # Check capacity
        training = client.table('trainings').select('max_participants, status').eq('id', training_id).single().execute().data
        if not training:
            flash('Training session not found.', 'danger')
            return redirect(url_for('hr2.list_trainings'))
            
        if training['status'] == 'Completed':
            flash('Cannot enroll in a completed training session.', 'warning')
            return redirect(url_for('hr2.list_trainings'))

        count_resp = client.table('training_participants').select('id', count='exact').eq('training_id', training_id).execute()
        current_count = count_resp.count or 0
        max_p = int(training.get('max_participants') or 0)
        
        if max_p > 0 and current_count >= max_p:
            flash('Enrollment failed: This session has reached its maximum capacity.', 'danger')
            return redirect(url_for('hr2.list_trainings'))

        # Check if already enrolled
        client.table('training_participants').insert({
            'training_id': training_id,
            'user_id': user_id
        }).execute()
        flash('Staff member enrolled successfully!', 'success')
    except Exception as e:
        if 'unique_training_participant' in str(e):
            flash('This employee is already enrolled in this session.', 'warning')
        else:
            flash(f'Error enrolling staff: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_trainings'))

@hr2_bp.route('/trainings/mark-attendance', methods=['POST'])
@login_required
def mark_attendance():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    participant_id = request.form.get('participant_id')
    status = request.form.get('status') # Attended, Absent, Enrolled
    
    try:
        client.table('training_participants').update({'attendance_status': status}).eq('id', participant_id).execute()
        flash('Attendance updated.', 'success')
    except Exception as e:
        flash(f'Error updating attendance: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_trainings'))

@hr2_bp.route('/trainings/remove-participant/<int:id>', methods=['POST'])
@login_required
def remove_participant(id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('training_participants').delete().eq('id', id).execute()
        flash('Participant removed.', 'info')
    except Exception as e:
        flash(f'Error removing participant: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_trainings'))

@hr2_bp.route('/competencies')
@login_required
def list_competencies():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch competency definitions
    response = client.table('competencies').select('*').execute()
    competencies = response.data if response.data else []
    
    # Fetch all staff members (users) for the assessment dropdown
    # Filtering by those who are Active/Approved
    staff_response = client.table('users').select('id, username, email, department, role').eq('status', 'Active').execute()
    staff_members = staff_response.data if staff_response.data else []

    # Fetch staff assessments with user details
    # Explicitly specify the user_id relationship to avoid ambiguity with assessor_id
    assessments_response = client.table('staff_competencies').select('*, users:users!staff_competencies_user_id_fkey(username, department, role)').execute()
    assessments = assessments_response.data if assessments_response.data else []
    
    from datetime import datetime
    
    return render_template('subsystems/hr/hr2/competencies.html',
                           competencies=competencies,
                           staff_members=staff_members,
                           assessments=assessments,
                           current_date=datetime.now().strftime('%Y-%m-%d'),
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/competencies/add', methods=['POST'])
@login_required
def add_competency():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_competencies'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    data = {
        'skill_name': request.form.get('skill_name'),
        'role': request.form.get('role'),
        'description': request.form.get('description')
    }
    
    try:
        client.table('competencies').insert(data).execute()
        flash('Competency requirement added!', 'success')
    except Exception as e:
        flash(f'Error adding competency: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_competencies'))

@hr2_bp.route('/competencies/edit/<int:id>', methods=['POST'])
@login_required
def edit_competency(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_competencies'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    data = {
        'skill_name': request.form.get('skill_name'),
        'role': request.form.get('role'),
        'description': request.form.get('description')
    }
    
    try:
        client.table('competencies').update(data).eq('id', id).execute()
        flash('Competency updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating competency: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_competencies'))

@hr2_bp.route('/competencies/delete/<int:id>', methods=['POST'])
@login_required
def delete_competency(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_competencies'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('competencies').delete().eq('id', id).execute()
        flash('Competency removed.', 'info')
    except Exception as e:
        flash(f'Error deleting competency: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_competencies'))

@hr2_bp.route('/competencies/assess', methods=['POST'])
@login_required
def assess_staff():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    data = {
        'user_id': request.form.get('user_id'),
        'competency_id': request.form.get('competency_id'),
        'assessment_date': request.form.get('assessment_date'),
        'level': request.form.get('level'),
        'assessor_id': current_user.id
    }
    
    try:
        client.table('staff_competencies').insert(data).execute()
        flash('Staff assessment recorded!', 'success')
    except Exception as e:
        flash(f'Error recording assessment: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_competencies'))

@hr2_bp.route('/settings', methods=['GET', 'POST'])
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

@hr2_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hr2.login'))

