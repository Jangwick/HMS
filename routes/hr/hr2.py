from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error, SUBSYSTEM_CONFIG
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from datetime import datetime
import random
import string

hr2_bp = Blueprint('hr2', __name__)

def _gen_cert_number():
    """Generate a unique certificate number: HMS-TRN-YYYY-XXXXXXXX"""
    yr = datetime.utcnow().year
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return f'HMS-TRN-{yr}-{code}'

# Subsystem configuration
SUBSYSTEM_NAME = 'HR2 - Talent Development'
ACCENT_COLOR = '#0891B2'
BLUEPRINT_NAME = 'hr2'

@hr2_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked(subsystem=BLUEPRINT_NAME)
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
                        flash('Your account is awaiting approval from HR2 Admin.', 'info')
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
                register_successful_login(subsystem=BLUEPRINT_NAME)
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
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt(subsystem=BLUEPRINT_NAME)
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/hr/hr2/login.html', remaining_seconds=remaining_seconds)
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
                return render_template('subsystems/hr/hr2/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/hr/hr2/login.html')


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
        
        # New stats for Career and Succession
        resp = client.table('career_paths').select('id', count='exact').execute()
        active_paths = resp.count if resp.count is not None else 0
        
        resp = client.table('succession_plans').select('id', count='exact').execute()
        total_plans = resp.count if resp.count is not None else 0
        
        # Recent onboarding items
        recent_onboarding_resp = client.table('onboarding').select('*, applicants(first_name, last_name)').order('created_at', desc=True).limit(5).execute()
        recent_onboarding = recent_onboarding_resp.data if recent_onboarding_resp.data else []
        
        # User management stats (moved from HR3)
        pending_users_count = 0
        if current_user.is_super_admin() or (current_user.is_admin() and current_user.subsystem == 'hr2'):
            pending_users_count = len([u for u in User.get_all() if u.status == 'Pending'])
        
    except Exception as e:
        print(f"Error fetching stats: {e}")
        pending_onboarding = 0
        active_trainings = 0
        total_competencies = 0
        active_paths = 0
        total_plans = 0
        recent_onboarding = []
        pending_users_count = 0
    
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
        
    return render_template('subsystems/hr/hr2/dashboard.html', 
                           now=datetime.utcnow,
                           pending_onboarding=pending_onboarding,
                           active_trainings=active_trainings,
                           total_competencies=total_competencies,
                           active_paths=active_paths,
                           total_plans=total_plans,
                           recent_onboarding=recent_onboarding,
                           pending_users_count=pending_users_count,
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

    # Fetch active hospital staff for enrollment dropdown (exclude patients/portal users)
    staff_response = client.table('users').select('id, username, department, role') \
        .eq('status', 'Active') \
        .not_.in_('role', ['Applicant', 'Patient', 'Administrator', 'SuperAdmin']) \
        .not_.in_('department', ['PATIENT_PORTAL', 'FINANCIALS']) \
        .order('username') \
        .execute()
    staff_members = staff_response.data if staff_response.data else []

    # Calculate basic stats
    stats = {
        'total': len(trainings),
        'scheduled': len([t for t in trainings if t['status'] == 'Scheduled']),
        'completed': len([t for t in trainings if t['status'] == 'Completed']),
        'total_participants': len(participants),
        'pending_evidence': len([p for p in participants if p.get('evidence_flagged')])
    }

    # Fetch pending evidence rows with full context for review table
    try:
        ev_resp = client.table('training_participants') \
            .select('id, evidence_url, evidence_flagged, training_id, user_id, users(username, department, role), training:trainings(title, schedule_date)') \
            .eq('evidence_flagged', True) \
            .execute()
        pending_evidence_rows = ev_resp.data or []
    except Exception:
        pending_evidence_rows = []
    
    # Competencies for linking dropdown
    try:
        comp_resp = client.table('competencies').select('id, skill_name, category').order('skill_name').execute()
        competencies_list = comp_resp.data or []
    except Exception:
        competencies_list = []

    return render_template('subsystems/hr/hr2/trainings.html',
                           trainings=trainings,
                           participants=participants,
                           staff_members=staff_members,
                           stats=stats,
                           pending_evidence_rows=pending_evidence_rows,
                           competencies_list=competencies_list,
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
        import os
        from utils.supabase_client import get_supabase_client
        client = get_supabase_client()

        # Handle requirements file upload
        requirements_file_url = None
        req_file = request.files.get('requirements_file')
        if req_file and req_file.filename:
            ext = os.path.splitext(req_file.filename)[1].lower()
            if ext in ['.pdf', '.doc', '.docx']:
                try:
                    from utils.supabase_client import get_supabase_service_client
                    sc = get_supabase_service_client()
                    ts = int(datetime.utcnow().timestamp())
                    file_path = f"training_requirements/{ts}_{req_file.filename.replace(' ','_')}"
                    sc.storage.from_('hr2-assessments').upload(
                        path=file_path, file=req_file.read(),
                        file_options={'content-type': req_file.content_type, 'x-upsert': 'true'}
                    )
                    requirements_file_url = sc.storage.from_('hr2-assessments').get_public_url(file_path)
                except Exception as ue:
                    flash(f'Requirement file upload failed: {ue}. Training saved without file.', 'warning')

        competency_id_raw = request.form.get('competency_id') or None
        data = {
            'title': request.form.get('title'),
            'type': request.form.get('type'),
            'schedule_date': request.form.get('schedule_date'),
            'description': request.form.get('description'),
            'location': request.form.get('location'),
            'location_type': request.form.get('location_type', 'On-site'),
            'start_time': request.form.get('start_time') or None,
            'end_time': request.form.get('end_time') or None,
            'trainer': request.form.get('trainer'),
            'target_department': request.form.get('target_department'),
            'max_participants': request.form.get('max_participants') or None,
            'materials_url': request.form.get('materials_url') or None,
            'requirements_file_url': requirements_file_url,
            'competency_id': int(competency_id_raw) if competency_id_raw else None,
            'status': 'Scheduled'
        }
        
        try:
            resp = client.table('trainings').insert(data).execute()
            training_id = resp.data[0]['id'] if resp.data else None

            # Notify target department staff about new scheduled training
            if training_id:
                try:
                    from utils.hms_models import Notification
                    target_dept = data['target_department']
                    Notification.create(
                        subsystem='hr2',
                        title=f'New Training: {data["title"]}',
                        message=f'A new training session "{data["title"]}" has been scheduled on {data["schedule_date"]}. Check Training Management for details.',
                        n_type='info',
                        sender_subsystem='hr2',
                        target_url='/hr/hr2/trainings'
                    )
                except Exception:
                    pass

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
        
    import os
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    # Handle requirements file upload
    requirements_file_url = request.form.get('existing_requirements_file_url') or None
    req_file = request.files.get('requirements_file')
    if req_file and req_file.filename:
        ext = os.path.splitext(req_file.filename)[1].lower()
        if ext in ['.pdf', '.doc', '.docx']:
            try:
                from utils.supabase_client import get_supabase_service_client
                sc = get_supabase_service_client()
                ts = int(datetime.utcnow().timestamp())
                file_path = f"training_requirements/{ts}_{req_file.filename.replace(' ','_')}"
                sc.storage.from_('hr2-assessments').upload(
                    path=file_path, file=req_file.read(),
                    file_options={'content-type': req_file.content_type, 'x-upsert': 'true'}
                )
                requirements_file_url = sc.storage.from_('hr2-assessments').get_public_url(file_path)
            except Exception as ue:
                flash(f'Requirement file upload failed: {ue}.', 'warning')

    data = {
        'title': request.form.get('title'),
        'type': request.form.get('type'),
        'schedule_date': request.form.get('schedule_date'),
        'description': request.form.get('description'),
        'location': request.form.get('location'),
        'location_type': request.form.get('location_type', 'On-site'),
        'start_time': request.form.get('start_time') or None,
        'end_time': request.form.get('end_time') or None,
        'trainer': request.form.get('trainer'),
        'target_department': request.form.get('target_department'),
        'max_participants': request.form.get('max_participants') or None,
        'materials_url': request.form.get('materials_url') or None,
        'requirements_file_url': requirements_file_url,
        'competency_id': int(request.form.get('competency_id')) if request.form.get('competency_id') else None,
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
    from utils.hms_models import Notification
    client = get_supabase_client()
    
    try:
        # Mark training as completed
        client.table('trainings').update({'status': 'Completed'}).eq('id', id).execute()
        training = client.table('trainings').select('title').eq('id', id).single().execute().data
        training_title = training.get('title', 'Training') if training else 'Training'

        # Issue certifications and notify all attended participants
        participants_resp = client.table('training_participants')\
            .select('id, user_id, attendance_status')\
            .eq('training_id', id)\
            .execute()
        participants = participants_resp.data or []

        cert_issued = 0
        for p in participants:
            if p.get('attendance_status') == 'Attended':
                try:
                    client.table('training_certifications').insert({
                        'training_id': id,
                        'user_id': p['user_id'],
                        'issued_date': datetime.utcnow().strftime('%Y-%m-%d'),
                        'certificate_number': _gen_cert_number(),
                    }).execute()
                    cert_issued += 1
                except Exception:
                    pass  # cert may already exist

            # Notify all enrolled participants
            try:
                msg = (f'You have been issued a certificate of completion for "{training_title}".'
                       if p.get('attendance_status') == 'Attended'
                       else f'The training "{training_title}" has been completed.')
                Notification.create(
                    user_id=p['user_id'],
                    subsystem='hr2',
                    title=f'Training Completed: {training_title}',
                    message=msg,
                    n_type='success' if p.get('attendance_status') == 'Attended' else 'info',
                    sender_subsystem='hr2'
                )
            except Exception:
                pass

        flash(f'Training marked as completed! {cert_issued} certificate(s) issued to attending staff.', 'success')

        # ── Feedback loop: schedule reassessment for linked competency ──────
        try:
            t_meta = client.table('trainings').select('competency_id').eq('id', id).maybe_single().execute()
            comp_link = t_meta.data.get('competency_id') if t_meta and t_meta.data else None
            if comp_link:
                for p in participants:
                    if p.get('attendance_status') == 'Attended':
                        nyc = client.table('staff_competencies').select('id') \
                            .eq('user_id', p['user_id']) \
                            .eq('competency_id', comp_link) \
                            .eq('status', 'Not Yet Competent') \
                            .execute()
                        if nyc.data:
                            client.table('staff_competencies').insert({
                                'user_id': p['user_id'],
                                'competency_id': comp_link,
                                'status': 'Scheduled',
                                'notes': f'Reassessment after remediation training: {training_title}',
                            }).execute()
                            Notification.create(
                                user_id=p['user_id'],
                                subsystem='hr2',
                                title='Reassessment Scheduled',
                                message=f'A reassessment has been scheduled following your completion of the remediation training "{training_title}".',
                                n_type='info',
                                sender_subsystem='hr2'
                            )
        except Exception:
            pass  # Non-critical

    except Exception as e:
        flash(f'Error updating training: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_trainings'))


@hr2_bp.route('/trainings/issue-cert', methods=['POST'])
@login_required
def issue_certification():
    """Manually issue a training certification to a specific participant."""
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_trainings'))

    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()

    training_id = request.form.get('training_id')
    user_id = request.form.get('user_id')
    expiry_date = request.form.get('expiry_date') or None

    try:
        training = client.table('trainings').select('title').eq('id', training_id).single().execute().data
        training_title = training.get('title', 'Training') if training else 'Training'

        client.table('training_certifications').upsert({
            'training_id': int(training_id),
            'user_id': int(user_id),
            'issued_date': datetime.utcnow().strftime('%Y-%m-%d'),
            'expiry_date': expiry_date,
            'certificate_number': _gen_cert_number(),
        }, on_conflict='training_id,user_id').execute()

        Notification.create(
            user_id=int(user_id),
            subsystem='hr2',
            title=f'Certificate Issued: {training_title}',
            message=f'A training certificate for "{training_title}" has been issued to you by HR.',
            n_type='success',
            sender_subsystem='hr2'
        )
        flash('Certification issued successfully!', 'success')
    except Exception as e:
        flash(f'Error issuing certification: {str(e)}', 'danger')

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
        
        # Notify the user
        try:
            from utils.hms_models import Notification
            Notification.create(
                user_id=user_id,
                title="New Training Enrollment",
                message=f"You have been enrolled in the training: {training.get('title', 'Professional Development')}.",
                n_type="info",
                sender_subsystem=BLUEPRINT_NAME
            )
        except:
            pass
            
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
    
    # Fetch active hospital staff for assessment dropdown (exclude patients/portal users)
    staff_response = client.table('users').select('id, username, email, department, role') \
        .eq('status', 'Active') \
        .not_.in_('role', ['Applicant', 'Patient', 'Administrator', 'SuperAdmin']) \
        .not_.in_('department', ['PATIENT_PORTAL', 'FINANCIALS']) \
        .order('username') \
        .execute()
    staff_members = staff_response.data if staff_response.data else []

    # Fetch administrators/supervisors for the assessor dropdown
    supervisors_response = client.table('users').select('id, username, department, role') \
        .eq('status', 'Active') \
        .in_('role', ['Administrator', 'SuperAdmin']) \
        .order('username') \
        .execute()
    supervisors = supervisors_response.data if supervisors_response.data else []

    # Fetch staff assessments with user details
    # Explicitly specify the user_id relationship to avoid ambiguity with assessor_id
    assessments_response = client.table('staff_competencies').select('*, users:users!staff_competencies_user_id_fkey(username, department, role)').execute()
    assessments = assessments_response.data if assessments_response.data else []
    
    from datetime import datetime
    
    return render_template('subsystems/hr/hr2/competencies.html',
                           competencies=competencies,
                           staff_members=staff_members,
                           supervisors=supervisors,
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
        'category': request.form.get('category', 'Technical'),  # Clinical / Technical / Behavioral
        'description': request.form.get('description'),
        'license_required': request.form.get('license_required') == '1',
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
        'category': request.form.get('category', 'Technical'),
        'description': request.form.get('description'),
        'license_required': request.form.get('license_required') == '1',
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


# ── Question Bank ────────────────────────────────────────────────────────────

@hr2_bp.route('/competencies/<int:competency_id>/questions', methods=['GET'])
@login_required
def get_questions(competency_id):
    """Returns JSON list of questions for a competency."""
    from utils.supabase_client import get_supabase_client
    from flask import jsonify
    client = get_supabase_client()
    try:
        resp = client.table('competency_questions') \
            .select('*') \
            .eq('competency_id', competency_id) \
            .order('order_num') \
            .execute()
        return jsonify(resp.data or [])
    except Exception as e:
        return jsonify({'error': str(e), 'hint': 'Run the HR2 migration SQL in Supabase first.'}), 500


@hr2_bp.route('/competencies/add-question', methods=['POST'])
@login_required
def add_question():
    if not current_user.is_admin():
        from flask import jsonify
        return jsonify({'error': 'Unauthorized'}), 403
    from utils.supabase_client import get_supabase_client
    from flask import jsonify
    import json
    client = get_supabase_client()

    competency_id  = request.form.get('competency_id')
    question_text  = request.form.get('question_text', '').strip()
    question_type  = request.form.get('question_type', 'text')
    options_raw    = request.form.get('options', '')
    points         = request.form.get('points') or 1

    if not question_text:
        return jsonify({'error': 'Question text is required'}), 400

    # Parse comma-separated options for multiple_choice
    options = None
    if question_type == 'multiple_choice':
        options = [o.strip() for o in options_raw.split('\n') if o.strip()]

    try:
        # Get next order number
        existing = client.table('competency_questions') \
            .select('order_num') \
            .eq('competency_id', competency_id) \
            .order('order_num', desc=True) \
            .limit(1) \
            .execute()
        next_order = (existing.data[0]['order_num'] + 1) if existing.data else 1

        result = client.table('competency_questions').insert({
            'competency_id': int(competency_id),
            'question_text': question_text,
            'question_type': question_type,
            'options': options,
            'points': int(points),
            'order_num': next_order,
        }).execute()
        return jsonify({'success': True, 'question': result.data[0] if result.data else {}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@hr2_bp.route('/competencies/delete-question/<int:question_id>', methods=['POST'])
@login_required
def delete_question(question_id):
    if not current_user.is_admin():
        from flask import jsonify
        return jsonify({'error': 'Unauthorized'}), 403
    from utils.supabase_client import get_supabase_client
    from flask import jsonify
    client = get_supabase_client()
    try:
        client.table('competency_questions').delete().eq('id', question_id).execute()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@hr2_bp.route('/competencies/assessment-answers/<int:assessment_id>', methods=['GET'])
@login_required
def get_assessment_answers(assessment_id):
    """Returns JSON of submitted answers with question text — for supervisor evaluation."""
    from utils.supabase_client import get_supabase_client
    from flask import jsonify
    client = get_supabase_client()
    try:
        resp = client.table('assessment_answers') \
            .select('*, question:competency_questions(question_text, question_type, options, points)') \
            .eq('assessment_id', assessment_id) \
            .execute()
        return jsonify(resp.data or [])
    except Exception as e:
        return jsonify({'error': str(e), 'hint': 'Run the HR2 migration SQL in Supabase first.'}), 500


@hr2_bp.route('/competencies/schedule-assessment', methods=['POST'])
@login_required
def assess_staff():
    """Schedule a competency assessment — checks license validity, notifies supervisor."""
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_competencies'))

    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()

    user_id       = request.form.get('user_id')
    competency_id = request.form.get('competency_id')
    scheduled_date= request.form.get('scheduled_date')
    assessment_type = request.form.get('assessment_type', 'Practical')
    location_type = request.form.get('location_type', 'On-site')
    supervisor_id = request.form.get('supervisor_id')
    location      = request.form.get('location') or None
    license_verified = request.form.get('license_verified') == '1'
    license_expiry   = request.form.get('license_expiry') or None

    try:
        # License expiry check — block if expired
        if license_expiry:
            from datetime import date
            exp_date = date.fromisoformat(license_expiry)
            if exp_date < date.today():
                flash('Assessment blocked: Staff member\'s license has expired. Please renew before scheduling.', 'danger')
                return redirect(url_for('hr2.list_competencies'))

        # Get competency name for notifications
        comp = client.table('competencies').select('skill_name').eq('id', competency_id).maybe_single().execute()
        skill_name = comp.data.get('skill_name', 'Competency') if comp and comp.data else 'Competency'

        # Insert scheduled assessment record
        client.table('staff_competencies').insert({
            'user_id': int(user_id),
            'competency_id': int(competency_id),
            'assessment_date': scheduled_date,
            'assessment_type': assessment_type,
            'location_type': location_type,
            'supervisor_id': int(supervisor_id) if supervisor_id else None,
            'location': location if location_type == 'On-site' else None,
            'license_verified': license_verified,
            'license_expiry': license_expiry,
            'status': 'Scheduled',
            'assessor_id': current_user.id,
        }).execute()

        # Notify staff member
        Notification.create(
            user_id=int(user_id),
            subsystem='hr2',
            title=f'Assessment Scheduled: {skill_name}',
            message=f'A competency assessment for "{skill_name}" has been scheduled on {scheduled_date}.',
            n_type='info',
            sender_subsystem='hr2'
        )

        # Notify supervisor
        if supervisor_id:
            Notification.create(
                user_id=int(supervisor_id),
                subsystem='hr2',
                title=f'Competency Assessment Assigned: {skill_name}',
                message=f'You have been assigned to supervise a competency assessment for "{skill_name}" on {scheduled_date}.',
                n_type='info',
                sender_subsystem='hr2'
            )

        flash('Competency assessment scheduled and supervisor notified!', 'success')
    except Exception as e:
        flash(f'Error scheduling assessment: {str(e)}', 'danger')

    return redirect(url_for('hr2.list_competencies'))


@hr2_bp.route('/competencies/submit-result/<int:assessment_id>', methods=['POST'])
@login_required
def submit_assessment_result(assessment_id):
    """Employee submits their assessment score/notes — moves to Submitted state."""
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()

    score       = request.form.get('score')
    notes       = request.form.get('notes')

    try:
        rec = client.table('staff_competencies').select('supervisor_id, competency_id').eq('id', assessment_id).maybe_single().execute()
        data_rec = rec.data if rec else {}

        client.table('staff_competencies').update({
            'score': float(score) if score else None,
            'notes': notes,
            'status': 'Submitted',
        }).eq('id', assessment_id).execute()

        # Notify supervisor that results are ready for evaluation
        supervisor_id = data_rec.get('supervisor_id')
        if supervisor_id:
            comp_id = data_rec.get('competency_id')
            comp = client.table('competencies').select('skill_name').eq('id', comp_id).maybe_single().execute()
            skill_name = comp.data.get('skill_name', 'Competency') if comp and comp.data else 'Competency'

            Notification.create(
                user_id=int(supervisor_id),
                subsystem='hr2',
                title=f'Assessment Result Submitted: {skill_name}',
                message=f'A staff member has submitted their result for the "{skill_name}" competency assessment. Please review and evaluate.',
                n_type='info',
                sender_subsystem='hr2'
            )

        flash('Assessment result submitted successfully!', 'success')
    except Exception as e:
        flash(f'Error submitting result: {str(e)}', 'danger')

    return redirect(url_for('hr2.list_competencies'))


@hr2_bp.route('/competencies/evaluate/<int:assessment_id>', methods=['POST'])
@login_required
def evaluate_assessment(assessment_id):
    """Supervisor evaluates a submitted assessment — Competent or Not Yet Competent."""
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()

    outcome          = request.form.get('outcome')  # 'Competent' or 'Not Yet Competent'
    level            = request.form.get('level')
    corrective_action= request.form.get('corrective_action') or None
    evaluator_notes  = request.form.get('evaluator_notes') or None

    try:
        rec = client.table('staff_competencies').select('user_id, competency_id').eq('id', assessment_id).maybe_single().execute()
        data_rec = rec.data if rec else {}
        user_id   = data_rec.get('user_id')
        comp_id   = data_rec.get('competency_id')

        comp = client.table('competencies').select('skill_name').eq('id', comp_id).maybe_single().execute()
        skill_name = comp.data.get('skill_name', 'Competency') if comp and comp.data else 'Competency'

        update_data = {
            'level': level,
            'status': outcome,
            'corrective_action': corrective_action,
            'evaluator_notes': evaluator_notes,
            'evaluated_by': current_user.id,
            'evaluated_at': datetime.utcnow().isoformat(),
        }
        client.table('staff_competencies').update(update_data).eq('id', assessment_id).execute()

        # Notify employee of outcome
        if user_id:
            if outcome == 'Competent':
                msg = f'Congratulations! You have been evaluated as Competent in "{skill_name}". Your profile has been updated.'
                n_type = 'success'
            else:
                msg = (f'Your "{skill_name}" competency assessment has been reviewed. Outcome: Not Yet Competent.'
                       + (f' Corrective action required: {corrective_action}' if corrective_action else ''))
                n_type = 'warning'

            Notification.create(
                user_id=int(user_id),
                subsystem='hr2',
                title=f'Assessment Evaluated: {skill_name}',
                message=msg,
                n_type=n_type,
                sender_subsystem='hr2'
            )

        # ── Not Yet Competent → auto-enroll in linked remediation training ─
        if outcome == 'Not Yet Competent' and comp_id and user_id:
            try:
                linked = client.table('trainings').select('id, title') \
                    .eq('competency_id', comp_id).eq('status', 'Scheduled').execute()
                if linked.data:
                    t = linked.data[0]
                    existing_enroll = client.table('training_participants').select('id') \
                        .eq('training_id', t['id']).eq('user_id', user_id).execute()
                    if not existing_enroll.data:
                        client.table('training_participants').insert({
                            'training_id': t['id'],
                            'user_id': int(user_id),
                        }).execute()
                        Notification.create(
                            user_id=int(user_id),
                            subsystem='hr2',
                            title=f'Enrolled in Remediation: {t["title"]}',
                            message=f'You have been enrolled in "{t["title"]}" as a remediation step following your "{skill_name}" assessment outcome.',
                            n_type='info',
                            sender_subsystem='hr2'
                        )
            except Exception:
                pass  # Non-critical

        flash(f'Assessment evaluated as {outcome}!', 'success')
    except Exception as e:
        flash(f'Error evaluating assessment: {str(e)}', 'danger')

    return redirect(url_for('hr2.list_competencies'))


@hr2_bp.route('/competencies/record-onsite/<int:assessment_id>', methods=['POST'])
@login_required
def record_onsite_result(assessment_id):
    """HR/Assessor directly records the result of an on-site assessment (bypasses employee submission)."""
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()

    outcome           = request.form.get('outcome')          # 'Competent' or 'Not Yet Competent'
    score             = request.form.get('score') or None
    level             = request.form.get('level') or None
    evaluator_notes   = request.form.get('evaluator_notes') or None
    corrective_action = request.form.get('corrective_action') or None

    try:
        rec = client.table('staff_competencies') \
            .select('user_id, competency_id, status, location_type') \
            .eq('id', assessment_id).maybe_single().execute()
        data_rec = rec.data if rec else {}

        if not data_rec:
            flash('Assessment record not found.', 'danger')
            return redirect(url_for('hr2.list_competencies'))

        if data_rec.get('location_type') != 'On-site':
            flash('This action is only valid for On-site assessments.', 'warning')
            return redirect(url_for('hr2.list_competencies'))

        if data_rec.get('status') not in ('Scheduled',):
            flash('This assessment has already been evaluated.', 'warning')
            return redirect(url_for('hr2.list_competencies'))

        user_id  = data_rec.get('user_id')
        comp_id  = data_rec.get('competency_id')

        comp = client.table('competencies').select('skill_name').eq('id', comp_id).maybe_single().execute()
        skill_name = comp.data.get('skill_name', 'Competency') if comp and comp.data else 'Competency'

        update_data = {
            'status': outcome,
            'evaluated_by': current_user.id,
            'evaluated_at': datetime.utcnow().isoformat(),
        }
        if score is not None:
            try:
                update_data['score'] = float(score)
            except (ValueError, TypeError):
                pass
        if level:
            update_data['level'] = level
        if evaluator_notes:
            update_data['evaluator_notes'] = evaluator_notes
        if corrective_action:
            update_data['corrective_action'] = corrective_action

        client.table('staff_competencies').update(update_data).eq('id', assessment_id).execute()

        # Notify employee of outcome
        if user_id:
            if outcome == 'Competent':
                msg = f'Congratulations! You have been assessed as Competent in "{skill_name}" (On-site). Your profile has been updated.'
                n_type = 'success'
            else:
                msg = (f'Your "{skill_name}" on-site assessment has been recorded. Outcome: Not Yet Competent.'
                       + (f' Corrective action: {corrective_action}' if corrective_action else ''))
                n_type = 'warning'

            Notification.create(
                user_id=int(user_id),
                subsystem='hr2',
                title=f'On-site Assessment Result: {skill_name}',
                message=msg,
                n_type=n_type,
                sender_subsystem='hr2'
            )

        # Not Yet Competent → auto-enroll in linked remediation training
        if outcome == 'Not Yet Competent' and comp_id and user_id:
            try:
                linked = client.table('trainings').select('id, title') \
                    .eq('competency_id', comp_id).eq('status', 'Scheduled').execute()
                if linked.data:
                    t = linked.data[0]
                    existing_enroll = client.table('training_participants').select('id') \
                        .eq('training_id', t['id']).eq('user_id', user_id).execute()
                    if not existing_enroll.data:
                        client.table('training_participants').insert({
                            'training_id': t['id'],
                            'user_id': int(user_id),
                        }).execute()
                        Notification.create(
                            user_id=int(user_id),
                            subsystem='hr2',
                            title=f'Enrolled in Remediation: {t["title"]}',
                            message=f'You have been enrolled in "{t["title"]}" as a remediation step following your "{skill_name}" on-site assessment outcome.',
                            n_type='info',
                            sender_subsystem='hr2'
                        )
            except Exception:
                pass  # Non-critical

        flash(f'On-site assessment recorded as {outcome}!', 'success')
    except Exception as e:
        flash(f'Error recording on-site result: {str(e)}', 'danger')

    return redirect(url_for('hr2.list_competencies'))


@hr2_bp.route('/my-assessments')
@login_required
def my_assessments():
    """Staff-facing page: view all scheduled/submitted assessments for the current user."""
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    context = request.args.get('context', BLUEPRINT_NAME)
    subsystem_map = {
        'hr1': ('HR1 - Recruitment', '#6366F1'),
        'hr2': ('HR2 - Talent Development', '#0891B2'),
        'hr3': ('HR3 - Workforce Ops', '#8B5CF6'),
    }
    display_name, accent = subsystem_map.get(context, (SUBSYSTEM_NAME, ACCENT_COLOR))

    resp = client.table('staff_competencies') \
        .select('*, competency:competencies(id, skill_name, category, description), supervisor:users!staff_competencies_supervisor_id_fkey(username)') \
        .eq('user_id', current_user.id) \
        .order('assessment_date', desc=True) \
        .execute()
    assessments = resp.data if resp.data else []

    # Attach questions and submitted answers per assessment
    for a in assessments:
        comp_id = a.get('competency', {}).get('id') if a.get('competency') else None
        a['questions'] = []
        a['submitted_answers'] = {}
        if comp_id:
            try:
                q_resp = client.table('competency_questions').select('*') \
                    .eq('competency_id', comp_id).order('order_num').execute()
                a['questions'] = q_resp.data or []
            except Exception:
                pass  # Table not yet created — run migration SQL

        # Fetch previously submitted answers if status == Submitted
        if a.get('status') in ('Submitted', 'Competent', 'Not Yet Competent'):
            try:
                ans_resp = client.table('assessment_answers').select('*') \
                    .eq('assessment_id', a['id']).execute()
                a['submitted_answers'] = {str(r['question_id']): r['answer_text'] for r in (ans_resp.data or [])}
            except Exception:
                pass  # Table not yet created — run migration SQL

    return render_template('subsystems/hr/hr2/my_assessments.html',
                           assessments=assessments,
                           subsystem_name=display_name,
                           accent_color=accent,
                           blueprint_name=context)


@hr2_bp.route('/my-assessments/submit/<int:assessment_id>', methods=['POST'])
@login_required
def submit_my_assessment(assessment_id):
    """Staff submits questionnaire answers + optional file for their assessment."""
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    import os, uuid, json
    client = get_supabase_client()

    context = request.form.get('context', BLUEPRINT_NAME)

    # Verify ownership
    rec = client.table('staff_competencies').select('user_id, supervisor_id, competency_id, assessment_type, status') \
        .eq('id', assessment_id).maybe_single().execute()
    if not rec or not rec.data or rec.data['user_id'] != current_user.id:
        flash('Assessment not found or access denied.', 'danger')
        return redirect(url_for('hr2.my_assessments', context=context))

    if rec.data['status'] not in ('Scheduled',):
        flash('This assessment has already been submitted or evaluated.', 'warning')
        return redirect(url_for('hr2.my_assessments', context=context))

    submission_file_url = None

    # Handle file upload
    file = request.files.get('portfolio_file')
    if file and file.filename:
        try:
            ext = os.path.splitext(file.filename)[1]
            filename = f"portfolio_{current_user.id}_{uuid.uuid4().hex}{ext}"
            file_bytes = file.read()
            client.storage.from_('hr2-assessments').upload(filename, file_bytes,
                file_options={"content-type": file.content_type or "application/octet-stream"})
            submission_file_url = client.storage.from_('hr2-assessments').get_public_url(filename)
        except Exception as e:
            flash(f'File upload failed: {str(e)}', 'warning')

    try:
        comp_id = rec.data['competency_id']

        # Fetch questions for this competency
        q_resp = client.table('competency_questions').select('id') \
            .eq('competency_id', comp_id).execute()
        questions = q_resp.data or []

        # Save per-question answers
        answer_rows = []
        summary_parts = []
        for q in questions:
            qid = str(q['id'])
            answer = request.form.get(f'answer_{qid}', '').strip()
            if answer:
                answer_rows.append({
                    'assessment_id': assessment_id,
                    'question_id': q['id'],
                    'answer_text': answer,
                })
                summary_parts.append(answer)

        if answer_rows:
            client.table('assessment_answers').insert(answer_rows).execute()

        # Also store a plain-text written_answer summary for backward compatibility
        combined = '\n\n'.join(summary_parts) if summary_parts else request.form.get('written_answer') or None

        client.table('staff_competencies').update({
            'written_answer': combined,
            'submission_file_url': submission_file_url,
            'status': 'Submitted',
        }).eq('id', assessment_id).execute()

        # Notify supervisor
        supervisor_id = rec.data.get('supervisor_id')
        if supervisor_id:
            comp = client.table('competencies').select('skill_name').eq('id', comp_id).maybe_single().execute()
            skill_name = comp.data.get('skill_name', 'Competency') if comp and comp.data else 'Competency'
            Notification.create(
                user_id=int(supervisor_id),
                subsystem='hr2',
                title=f'Assessment Submitted: {skill_name}',
                message=f'{current_user.username} has submitted their "{skill_name}" assessment. Please evaluate.',
                n_type='info',
                sender_subsystem='hr2'
            )

        flash('Assessment submitted successfully! Your supervisor has been notified.', 'success')
    except Exception as e:
        flash(f'Error submitting assessment: {str(e)}', 'danger')

    return redirect(url_for('hr2.my_assessments', context=context))


# ─────────────────────────────────────────────────────────────────────────────
#  MY TRAININGS  (staff-facing)
# ─────────────────────────────────────────────────────────────────────────────
@hr2_bp.route('/my-trainings')
@login_required
def my_trainings():
    """Staff-facing page: view all training enrollments, progress, certificates."""
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    context = request.args.get('context', BLUEPRINT_NAME)
    subsystem_map = {
        'hr1': ('HR1 - Recruitment', '#6366F1'),
        'hr2': ('HR2 - Talent Development', '#0891B2'),
        'hr3': ('HR3 - Workforce Ops', '#8B5CF6'),
    }
    display_name, accent = subsystem_map.get(context, (SUBSYSTEM_NAME, ACCENT_COLOR))

    try:
        enroll_resp = client.table('training_participants') \
            .select('*, training:trainings(id, title, schedule_date, trainer, location, location_type, status, target_department, competency_id, requirements_file_url, description, type, start_time, end_time)') \
            .eq('user_id', current_user.id) \
            .execute()
        enrollments = enroll_resp.data or []
    except Exception:
        enrollments = []

    try:
        cert_resp = client.table('training_certifications') \
            .select('*, training:trainings(title, schedule_date)') \
            .eq('user_id', current_user.id) \
            .execute()
        certifications = {str(r['training_id']): r for r in (cert_resp.data or [])}
    except Exception:
        certifications = {}

    return render_template('subsystems/hr/hr2/my_trainings.html',
                           enrollments=enrollments,
                           certifications=certifications,
                           subsystem_name=display_name,
                           accent_color=accent,
                           blueprint_name=context)


@hr2_bp.route('/my-trainings/progress', methods=['POST'])
@login_required
def update_training_progress():
    """Staff self-reports progress percentage on a training."""
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    participant_id = request.form.get('participant_id')
    progress_pct = request.form.get('progress_pct', 0)
    self_completed = request.form.get('self_completed') == '1'
    context = request.form.get('context', BLUEPRINT_NAME)
    try:
        upd = {'progress_pct': int(progress_pct), 'self_completed': self_completed}
        client.table('training_participants').update(upd) \
            .eq('id', participant_id).eq('user_id', current_user.id).execute()
        flash('Progress updated!', 'success')
    except Exception as e:
        flash(f'Error updating progress: {str(e)}', 'danger')
    return redirect(url_for('hr2.my_trainings', context=context))


@hr2_bp.route('/my-trainings/evidence', methods=['POST'])
@login_required
def upload_training_evidence():
    """Staff uploads completion evidence; flags it for Dept Head / HR review."""
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    import os, uuid
    client = get_supabase_client()
    participant_id = request.form.get('participant_id')
    context = request.form.get('context', BLUEPRINT_NAME)

    file = request.files.get('evidence_file')
    if not file or not file.filename:
        flash('Please select a file to upload.', 'warning')
        return redirect(url_for('hr2.my_trainings', context=context))
    try:
        ext = os.path.splitext(file.filename)[1]
        fname = f"training_evidence/{current_user.id}_{uuid.uuid4().hex}{ext}"
        client.storage.from_('hr2-assessments').upload(fname, file.read(),
            file_options={'content-type': file.content_type or 'application/octet-stream'})
        evidence_url = client.storage.from_('hr2-assessments').get_public_url(fname)
        client.table('training_participants').update({
            'evidence_url': evidence_url,
            'evidence_flagged': True,
        }).eq('id', participant_id).eq('user_id', current_user.id).execute()
        Notification.create(
            subsystem='hr2',
            title='Training Evidence Submitted',
            message=f'{current_user.username} submitted completion evidence for a training — please review.',
            n_type='info',
            sender_subsystem='hr2',
            target_url='/hr/hr2/trainings'
        )
        flash('Evidence uploaded and flagged for review.', 'success')
    except Exception as e:
        flash(f'Upload failed: {str(e)}', 'danger')
    return redirect(url_for('hr2.my_trainings', context=context))


@hr2_bp.route('/trainings/evidence/approve/<int:id>', methods=['POST'])
@login_required
def approve_evidence(id):
    """Admin approves submitted training evidence and auto-issues a certificate."""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()
    try:
        row = client.table('training_participants') \
            .select('user_id, training_id') \
            .eq('id', id).single().execute().data
        # Clear the pending flag
        client.table('training_participants').update({'evidence_flagged': False}).eq('id', id).execute()
        if row:
            t = client.table('trainings').select('title').eq('id', row['training_id']).single().execute().data
            training_title = t.get('title', 'Training') if t else 'Training'
            # Auto-issue certificate
            try:
                client.table('training_certifications').upsert({
                    'training_id': row['training_id'],
                    'user_id': row['user_id'],
                    'issued_date': datetime.utcnow().strftime('%Y-%m-%d'),
                    'certificate_number': _gen_cert_number(),
                }, on_conflict='training_id,user_id').execute()
                cert_msg = f' A certificate of completion has been issued to you.'
            except Exception:
                cert_msg = ''
            Notification.create(
                user_id=row['user_id'],
                subsystem='hr2',
                title='Evidence Approved — Certificate Issued',
                message=f'Your completion evidence for "{training_title}" has been approved by HR.{cert_msg}',
                n_type='success',
                sender_subsystem='hr2'
            )
        flash('Evidence approved and certificate issued to the participant.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr2.list_trainings'))


@hr2_bp.route('/trainings/evidence/reject/<int:id>', methods=['POST'])
@login_required
def reject_evidence(id):
    """Admin rejects submitted training evidence — clears it so staff can re-upload."""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()
    try:
        row = client.table('training_participants').select('user_id, training_id').eq('id', id).single().execute().data
        client.table('training_participants').update({'evidence_flagged': False, 'evidence_url': None}).eq('id', id).execute()
        if row:
            t = client.table('trainings').select('title').eq('id', row['training_id']).single().execute().data
            Notification.create(
                user_id=row['user_id'],
                subsystem='hr2',
                title='Evidence Rejected — Please Re-submit',
                message=f'Your completion evidence for "{t.get("title", "training") if t else "training"}" was not accepted. Please upload a clearer or correct file.',
                n_type='warning',
                sender_subsystem='hr2'
            )
        flash('Evidence rejected and staff notified to re-submit.', 'warning')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr2.list_trainings'))


# ─────────────────────────────────────────────────────────────────────────────
#  MY LEARNING  (LMS dashboard — staff-facing)
# ─────────────────────────────────────────────────────────────────────────────
@hr2_bp.route('/my-learning')
@login_required
def my_learning():
    """LMS dashboard: gaps, recommended trainings, progress, certificates."""
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    context = request.args.get('context', BLUEPRINT_NAME)
    subsystem_map = {
        'hr1': ('HR1 - Recruitment', '#6366F1'),
        'hr2': ('HR2 - Talent Development', '#0891B2'),
        'hr3': ('HR3 - Workforce Ops', '#8B5CF6'),
    }
    display_name, accent = subsystem_map.get(context, (SUBSYSTEM_NAME, ACCENT_COLOR))

    # Competency gaps
    try:
        gaps_resp = client.table('staff_competencies') \
            .select('*, competency:competencies(id, skill_name, category)') \
            .eq('user_id', current_user.id).eq('status', 'Not Yet Competent').execute()
        gaps = gaps_resp.data or []
        recommended = {}
        for g in gaps:
            cid = g.get('competency', {}).get('id')
            if cid:
                t_resp = client.table('trainings').select('id, title, schedule_date, trainer, status') \
                    .eq('competency_id', cid).eq('status', 'Scheduled').execute()
                recommended[cid] = t_resp.data or []
    except Exception:
        gaps, recommended = [], {}

    # My enrollments
    try:
        enroll_resp = client.table('training_participants') \
            .select('*, training:trainings(id, title, schedule_date, status, competency_id, type)') \
            .eq('user_id', current_user.id).execute()
        enrollments = enroll_resp.data or []
    except Exception:
        enrollments = []

    enrolled_ids = {str(e['training_id']) for e in enrollments}

    # Certifications
    try:
        cert_resp = client.table('training_certifications') \
            .select('*, training:trainings(title, schedule_date)') \
            .eq('user_id', current_user.id).execute()
        certifications = cert_resp.data or []
    except Exception:
        certifications = []

    # Available (not yet enrolled) scheduled trainings
    try:
        avail_resp = client.table('trainings').select('id, title, schedule_date, trainer, target_department, competency_id, max_participants') \
            .eq('status', 'Scheduled').execute()
        available = [t for t in (avail_resp.data or []) if str(t['id']) not in enrolled_ids]
    except Exception:
        available = []

    return render_template('subsystems/hr/hr2/my_learning.html',
                           gaps=gaps,
                           recommended=recommended,
                           enrollments=enrollments,
                           certifications=certifications,
                           available=available,
                           subsystem_name=display_name,
                           accent_color=accent,
                           blueprint_name=context)


# ─────────────────────────────────────────────────────────────────────────────
#  EMPLOYEE SELF SERVICE HUB
# ─────────────────────────────────────────────────────────────────────────────
@hr2_bp.route('/my-ess')
@login_required
def employee_self_service():
    """Aggregated ESS hub — career, assessments, trainings, learning in one view."""
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    context = request.args.get('context', BLUEPRINT_NAME)
    subsystem_map = {
        'hr1': ('HR1 - Recruitment', '#6366F1'),
        'hr2': ('HR2 - Talent Development', '#0891B2'),
        'hr3': ('HR3 - Workforce Ops', '#8B5CF6'),
        'hr4': ('HR4 - Compensation', '#EC4899'),
        'ct1': ('CT1 - Patient Access', '#10B981'),
        'ct2': ('CT2 - Clinical Ops', '#059669'),
        'ct3': ('CT3 - Medical Records', '#10B981'),
        'log1': ('LOG1 - Supply Chain', '#F59E0B'),
        'log2': ('LOG2 - Fleet Ops', '#F97316'),
        'financials': ('FIN1 - Revenue & Expenditure', '#0891B2'),
        'admin': ('System Admin', '#1F2937'),
    }
    display_name, accent = subsystem_map.get(context, (SUBSYSTEM_NAME, ACCENT_COLOR))
    uid = current_user.id

    # ── Career ──
    career_assignment = None
    try:
        ca_resp = client.table('staff_career_paths') \
            .select('status, updated_at, completed_requirements, path:career_paths(title, requirements)') \
            .eq('user_id', uid) \
            .in_('status', ['Active', 'Pending Approval']) \
            .limit(1).execute()
        career_assignment = ca_resp.data[0] if ca_resp.data else None
        if career_assignment:
            reqs_raw = career_assignment.get('path', {}).get('requirements', '') or ''
            all_reqs = [r.strip() for r in reqs_raw.replace(';', ',').split(',') if r.strip()]
            done = career_assignment.get('completed_requirements') or []
            career_assignment['_total_reqs'] = len(all_reqs)
            career_assignment['_done_reqs'] = len([r for r in all_reqs if r in done])
            career_assignment['_pct'] = int((career_assignment['_done_reqs'] / len(all_reqs) * 100) if all_reqs else 0)
    except Exception:
        career_assignment = None

    # ── Assessments ──
    assessment_counts = {'Scheduled': 0, 'Submitted': 0, 'Competent': 0, 'Not Yet Competent': 0}
    recent_assessments = []
    try:
        a_resp = client.table('staff_competencies') \
            .select('status, assessment_date, competency:competencies(skill_name)') \
            .eq('user_id', uid).order('assessment_date', desc=True).execute()
        for r in (a_resp.data or []):
            s = r.get('status', '')
            if s in assessment_counts:
                assessment_counts[s] += 1
        recent_assessments = (a_resp.data or [])[:3]
    except Exception:
        pass

    # ── Trainings ──
    training_counts = {'enrolled': 0, 'completed': 0, 'certs': 0}
    recent_trainings = []
    try:
        t_resp = client.table('training_participants') \
            .select('attendance_status, training:trainings(title, schedule_date, status)') \
            .eq('user_id', uid).execute()
        for r in (t_resp.data or []):
            training_counts['enrolled'] += 1
            if r.get('attendance_status') == 'Attended':
                training_counts['completed'] += 1
        cert_resp = client.table('training_certifications').select('id').eq('user_id', uid).execute()
        training_counts['certs'] = len(cert_resp.data or [])
        recent_trainings = sorted(
            t_resp.data or [],
            key=lambda x: x.get('training', {}).get('schedule_date') or '',
            reverse=True
        )[:3]
    except Exception:
        pass

    # ── Learning gaps ──
    gap_count = assessment_counts.get('Not Yet Competent', 0)

    # ── Notifications ──
    notifications = []
    try:
        from utils.hms_models import Notification
        notifications = Notification.get_for_user(current_user, limit=5)
    except Exception:
        pass

    # ── My Attendance (recent logs) ──
    recent_attendance = []
    attendance_summary = {'On-time': 0, 'Late': 0, 'Absent': 0}
    try:
        att_resp = client.table('attendance_logs') \
            .select('id, clock_in, clock_out, status, remarks, overtime_hours') \
            .eq('user_id', uid) \
            .order('clock_in', desc=True) \
            .limit(10).execute()
        recent_attendance = att_resp.data or []
        for a in recent_attendance:
            s = a.get('status', '')
            if s in attendance_summary:
                attendance_summary[s] += 1
    except Exception:
        pass

    # ── My Leave Requests — fetch ALL for accurate summary + full modal ──
    all_leaves = []
    recent_leaves = []
    leave_summary = {'Pending': 0, 'Approved': 0, 'Rejected': 0}
    leave_days_used = {}   # {leave_type: total calendar days used (approved only)}
    try:
        lv_resp = client.table('leave_requests') \
            .select('id, leave_type, start_date, end_date, status, workflow_step, remarks, document_url, created_at') \
            .eq('user_id', uid) \
            .order('created_at', desc=True) \
            .execute()
        all_leaves = lv_resp.data or []
        recent_leaves = all_leaves[:5]
        for lv in all_leaves:
            s = lv.get('status', '')
            if s in leave_summary:
                leave_summary[s] += 1
            # compute calendar days per leave entry
            try:
                from datetime import date as _date
                sd = _date.fromisoformat(lv['start_date'][:10])
                ed = _date.fromisoformat(lv['end_date'][:10])
                days = (ed - sd).days + 1
            except Exception:
                days = 0
            lv['_days'] = days
            # tally approved days per type for balance calc
            if lv.get('status') == 'Approved' and lv.get('leave_type') and days > 0:
                lt = lv['leave_type']
                leave_days_used[lt] = leave_days_used.get(lt, 0) + days
    except Exception:
        pass

    # Standard annual entitlements (days per year)
    leave_entitlements = {
        'Vacation Leave': 15,
        'Sick Leave': 15,
        'Emergency Leave': 5,
        'Maternity Leave': 105,
        'Paternity Leave': 7,
        'Solo Parent Leave': 7,
        'Study Leave': 6,
    }

    # ── My Schedule ──
    my_schedules = []
    try:
        sched_resp = client.table('staff_schedules') \
            .select('day_of_week, start_time, end_time, is_active') \
            .eq('user_id', uid) \
            .eq('is_active', True) \
            .execute()
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday', 'Daily']
        my_schedules = sorted(
            sched_resp.data or [],
            key=lambda x: day_order.index(x['day_of_week']) if x.get('day_of_week') in day_order else 99
        )
    except Exception:
        pass

    return render_template('subsystems/hr/hr2/ess.html',
                           career_assignment=career_assignment,
                           assessment_counts=assessment_counts,
                           recent_assessments=recent_assessments,
                           training_counts=training_counts,
                           recent_trainings=recent_trainings,
                           gap_count=gap_count,
                           notifications=notifications,
                           recent_attendance=recent_attendance,
                           attendance_summary=attendance_summary,
                           all_leaves=all_leaves,
                           recent_leaves=recent_leaves,
                           leave_summary=leave_summary,
                           leave_days_used=leave_days_used,
                           leave_entitlements=leave_entitlements,
                           my_schedules=my_schedules,
                           subsystem_name=display_name,
                           accent_color=accent,
                           blueprint_name=context)


# ─────────────────────────────────────────────────────────────────────────────
#  COMPLIANCE REPORT  (admin-facing)
# ─────────────────────────────────────────────────────────────────────────────
@hr2_bp.route('/competencies/compliance-report')
@login_required
def compliance_report():
    """Department-level competency compliance report for Dept Heads / HR."""
    if not current_user.is_admin():
        flash('Admin access required.', 'danger')
        return redirect(url_for('hr2.list_competencies'))
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    # ── Fetch users map (avoid ambiguous multi-FK join on staff_competencies) ──
    try:
        users_resp = client.table('users') \
            .select('id, username, department, role') \
            .not_.in_('role', ['Applicant', 'Patient']) \
            .order('username').execute()
        users_map = {u['id']: u for u in (users_resp.data or [])}
    except Exception:
        users_map = {}

    # ── Competency assessments (join competencies only — unambiguous FK) ──
    try:
        rec_resp = client.table('staff_competencies') \
            .select('id, user_id, status, assessment_date, competency:competencies(skill_name, category)') \
            .execute()
        raw_records = rec_resp.data or []
    except Exception:
        raw_records = []

    # Attach user info from users_map
    records = []
    for r in raw_records:
        uid = r.get('user_id')
        u = users_map.get(uid)
        if u:
            r['user'] = u
        records.append(r)

    # ── All competencies (for coverage matrix) ──
    try:
        comp_resp = client.table('competencies').select('id, skill_name, category').order('skill_name').execute()
        all_competencies = comp_resp.data or []
    except Exception:
        all_competencies = []

    # ── Training compliance data ──
    try:
        tp_resp = client.table('training_participants') \
            .select('user_id, attendance_status, training:trainings(id, title, schedule_date, status, competency_id)') \
            .execute()
        tp_raw = tp_resp.data or []
    except Exception:
        tp_raw = []

    # Build training compliance per-department
    training_dept_map = {}
    for r in tp_raw:
        uid = r.get('user_id')
        u = users_map.get(uid)
        if not u:
            continue
        dept = u.get('department', 'Unknown')
        att = r.get('attendance_status', 'Enrolled')
        tr = r.get('training') or {}
        if dept not in training_dept_map:
            training_dept_map[dept] = {'Attended': 0, 'Enrolled': 0, 'Absent': 0, 'total': 0}
        training_dept_map[dept]['total'] += 1
        training_dept_map[dept][att] = training_dept_map[dept].get(att, 0) + 1

    # ── Certification counts per department ──
    try:
        cert_resp = client.table('training_certifications').select('user_id').execute()
        cert_raw = cert_resp.data or []
    except Exception:
        cert_raw = []

    cert_dept_counts = {}
    for c in cert_raw:
        u = users_map.get(c.get('user_id'))
        if u:
            dept = u.get('department', 'Unknown')
            cert_dept_counts[dept] = cert_dept_counts.get(dept, 0) + 1

    # ── Build competency department map ──
    dept_map = {}
    for r in records:
        if not r.get('user') or not r.get('competency'):
            continue
        dept = r['user'].get('department', 'Unknown')
        status = r.get('status', 'Scheduled')
        if dept not in dept_map:
            dept_map[dept] = {'Competent': 0, 'Not Yet Competent': 0, 'Scheduled': 0, 'Submitted': 0, 'total': 0, 'staff': {}}
        dept_map[dept][status] = dept_map[dept].get(status, 0) + 1
        dept_map[dept]['total'] += 1
        uid = r['user']['id']
        if uid not in dept_map[dept]['staff']:
            dept_map[dept]['staff'][uid] = {
                'username': r['user']['username'],
                'role': r['user']['role'],
                'assessments': []
            }
        dept_map[dept]['staff'][uid]['assessments'].append({
            'skill': r['competency']['skill_name'],
            'category': r['competency']['category'],
            'status': status,
            'date': r.get('assessment_date'),
        })

    # Summary totals
    total_staff = len(users_map)
    total_certs = len(cert_raw)
    total_trainings_enrolled = len(tp_raw)
    total_trainings_attended = sum(1 for r in tp_raw if r.get('attendance_status') == 'Attended')

    return render_template('subsystems/hr/hr2/compliance_report.html',
                           records=records,
                           dept_map=dept_map,
                           all_competencies=all_competencies,
                           training_dept_map=training_dept_map,
                           cert_dept_counts=cert_dept_counts,
                           total_staff=total_staff,
                           total_certs=total_certs,
                           total_trainings_enrolled=total_trainings_enrolled,
                           total_trainings_attended=total_trainings_attended,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr2_bp.route('/career-paths')
@login_required
def list_career_paths():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch paths
    response = client.table('career_paths').select('*').execute()
    paths = response.data if response.data else []
    
    # Fetch active hospital staff for assignment (exclude patients/portal users)
    users_resp = client.table('users').select('id, username, department, role') \
        .eq('status', 'Active') \
        .not_.in_('role', ['Applicant', 'Patient', 'Administrator', 'SuperAdmin']) \
        .not_.in_('department', ['PATIENT_PORTAL', 'FINANCIALS']) \
        .order('username') \
        .execute()
    employees = users_resp.data if users_resp.data else []
    
    # Fetch existing assignments with full user and path details
    assign_resp = client.table('staff_career_paths').select('*, user:users(username), path:career_paths(*)').execute()
    assignments = assign_resp.data if assign_resp.data else []
    
    return render_template('subsystems/hr/hr2/career_paths.html',
                           paths=paths,
                           employees=employees,
                           assignments=assignments,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/career-paths/add', methods=['POST'])
@login_required
def add_career_path():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_career_paths'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Process steps from form
    roles = request.form.getlist('step_role[]')
    durations = request.form.getlist('step_duration[]')
    descriptions = request.form.getlist('step_description[]')
    requirements = request.form.getlist('step_requirements[]')
    
    steps = []
    for i in range(len(roles)):
        if roles[i]:
            steps.append({
                'role': roles[i],
                'duration': durations[i] if i < len(durations) else '',
                'description': descriptions[i] if i < len(descriptions) else '',
                'requirements': requirements[i] if i < len(requirements) else ''
            })
    
    data = {
        'path_name': request.form.get('path_name'),
        'department': request.form.get('department'),
        'description': request.form.get('description'),
        'steps': steps
    }
    
    try:
        client.table('career_paths').insert(data).execute()
        flash('Career path progression defined!', 'success')
    except Exception as e:
        flash(f'Error adding career path: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_career_paths'))

@hr2_bp.route('/career-paths/edit/<int:id>', methods=['POST'])
@login_required
def edit_career_path(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_career_paths'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Process steps from form
    roles = request.form.getlist('step_role[]')
    durations = request.form.getlist('step_duration[]')
    descriptions = request.form.getlist('step_description[]')
    requirements = request.form.getlist('step_requirements[]')
    
    steps = []
    for i in range(len(roles)):
        if roles[i]:
            steps.append({
                'role': roles[i],
                'duration': durations[i] if i < len(durations) else '',
                'description': descriptions[i] if i < len(descriptions) else '',
                'requirements': requirements[i] if i < len(requirements) else ''
            })
    
    data = {
        'path_name': request.form.get('path_name'),
        'department': request.form.get('department'),
        'description': request.form.get('description'),
        'steps': steps
    }
    
    try:
        client.table('career_paths').update(data).eq('id', id).execute()
        flash('Career path updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating career path: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_career_paths'))

@hr2_bp.route('/career-paths/delete/<int:id>', methods=['POST'])
@login_required
def delete_career_path(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_career_paths'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('career_paths').delete().eq('id', id).execute()
        flash('Career path removed.', 'info')
    except Exception as e:
        flash(f'Error deleting career path: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_career_paths'))

@hr2_bp.route('/career-paths/assign', methods=['POST'])
@login_required
def assign_career_path():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_career_paths'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    user_id = request.form.get('user_id')
    path_id = request.form.get('path_id')
    
    try:
        # First, set any existing 'Active' paths to 'Paused' to make room for the new focus
        client.table('staff_career_paths').update({
            'status': 'Paused',
            'updated_at': 'now()'
        }).eq('user_id', user_id).eq('status', 'Active').execute()

        data = {
            'user_id': user_id, 
            'path_id': path_id, 
            'current_step_index': 0,
            'status': 'Active',
            'updated_at': 'now()'
        }
        client.table('staff_career_paths').upsert(data, on_conflict='user_id,path_id').execute()
        flash('Career path assigned successfully! This is now the employee\'s primary focus.', 'success')
    except Exception as e:
        flash(f'Error assigning path: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_career_paths'))

@hr2_bp.route('/career-paths/update-progress/<int:id>', methods=['POST'])
@login_required
def update_career_progress(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_career_paths'))
        
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()
    
    new_step = int(request.form.get('current_step_index', 0))
    new_status = request.form.get('status', 'Active')
    
    try:
        # Get current state and path details
        resp = client.table('staff_career_paths').select('*, path:career_paths(steps), user:users(username)').eq('id', id).single().execute()
        if not resp.data:
            flash('Record not found.', 'danger')
            return redirect(url_for('hr2.list_career_paths'))
            
        record = resp.data
        steps = record['path']['steps']
        user_id = record['user_id']
        username = record['user']['username']
        
        data = {
            'current_step_index': new_step,
            'status': new_status,
            'updated_at': 'now()'
        }
        
        # Check if completed
        if new_step >= len(steps) - 1 and new_status == 'Active':
             # If they were pending and we just kept them at the last step, maybe mark as Completed?
             # Or let admin decide. For now, let's just notify.
             pass

        client.table('staff_career_paths').update(data).eq('id', id).execute()
        
        # Notify the user
        Notification.create(
            subsystem='hr2',
            user_id=user_id,
            title='Career Milestone Approved!',
            message=f'Congratulations! Your request has been approved. You are now at step: {steps[new_step]["role"] if new_step < len(steps) else "Completion"}.',
            n_type='success',
            sender_subsystem='hr2',
            target_url='/hr2/my-career'
        )
        
        # If fully completed last step
        if new_step == len(steps) - 1 and new_status == 'Completed':
            Notification.create(
                subsystem='hr2',
                role='Admin',
                title='Career Path Completed',
                message=f'Staff member {username} has successfully completed all milestones in their career path!',
                n_type='info',
                sender_subsystem='hr2'
            )

        flash('Staff progression updated and notification sent!', 'success')
    except Exception as e:
        flash(f'Error updating progress: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_career_paths'))

@hr2_bp.route('/my-career')
@login_required
def my_career():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Contextual awareness for the sidebar header
    context = request.args.get('context', BLUEPRINT_NAME)
    
    # Subsystem settings mapping for global pages
    subsystem_map = {
        'hr1': ('HR1 - recruitment', '#6366F1'),
        'hr2': ('HR2 - Talent Development', '#0891B2'),
        'hr3': ('HR3 - Workforce Ops', '#8B5CF6'),
        'hr4': ('HR4 - Compensation', '#EC4899'),
        'ct1': ('CT1 - Patient Access', '#10B981'),
        'ct2': ('CT2 - Clinical Ops', '#059669'),
        'ct3': ('CT3 - medical records', '#10B981'),
        'log1': ('LOG1 - Supply Chain', '#F59E0B'),
        'log2': ('LOG2 - Fleet Operations', '#F97316'),
        'financials': ('FIN1 - Revenue & Expenditure', '#0891B2'),
        'admin': ('System Admin', '#1F2937')
    }
    
    display_name, accent_color = subsystem_map.get(context, (SUBSYSTEM_NAME, ACCENT_COLOR))

    # Get user's assignments - prioritize Active/Pending, then most recently updated
    resp = client.table('staff_career_paths')\
        .select('*, path:career_paths(*)')\
        .eq('user_id', current_user.id)\
        .order('updated_at', desc=True)\
        .execute()
    
    assignments = resp.data if resp.data else []
    
    # Selection logic:
    # 1. Look for an Active or Pending Approval path
    # 2. Otherwise take the most recently updated one (could be Completed or Paused)
    assignment = next((a for a in assignments if a['status'] in ['Active', 'Pending Approval']), 
                      assignments[0] if assignments else None)

    # Fetch user's competency profile for requirement status badges
    competent_skills = set()
    nyc_skills = set()
    try:
        sc_resp = client.table('staff_competencies') \
            .select('status, competency:competencies(skill_name)') \
            .eq('user_id', current_user.id) \
            .in_('status', ['Competent', 'Not Yet Competent']) \
            .execute()
        for r in (sc_resp.data or []):
            if r.get('competency'):
                sn = r['competency']['skill_name'].lower().strip()
                if r['status'] == 'Competent':
                    competent_skills.add(sn)
                else:
                    nyc_skills.add(sn)
    except Exception:
        pass

    return render_template('subsystems/hr/hr2/my_career.html',
                           assignment=assignment,
                           competent_skills=competent_skills,
                           nyc_skills=nyc_skills,
                           subsystem_name=display_name,
                           accent_color=accent_color,
                           blueprint_name=context)

@hr2_bp.route('/career-paths/toggle-requirement', methods=['POST'])
@login_required
def toggle_career_requirement():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    context = request.form.get('context', BLUEPRINT_NAME)
    requirement = request.form.get('requirement')
    is_checked = request.form.get('checked') == 'true'
    
    # Get current assignment
    resp = client.table('staff_career_paths')\
        .select('*')\
        .eq('user_id', current_user.id)\
        .order('updated_at', desc=True)\
        .execute()
        
    if not resp.data:
        return {"error": "No assignment found"}, 404
        
    assignments = resp.data
    # Use same priority logic as my_career
    assignment = next((a for a in assignments if a['status'] in ['Active', 'Pending Approval']), assignments[0])
    
    completed = assignment.get('completed_requirements', [])
    
    if is_checked:
        if requirement not in completed:
            completed.append(requirement)
    else:
        if requirement in completed:
            completed.remove(requirement)
            
    client.table('staff_career_paths').update({
        'completed_requirements': completed,
        'updated_at': 'now()'
    }).eq('id', assignment['id']).execute()
    
    return {"status": "success", "completed": completed}

@hr2_bp.route('/career-paths/upload-evidence', methods=['POST'])
@login_required
def upload_requirement_evidence():
    import os
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    context = request.form.get('context', BLUEPRINT_NAME)
    requirement = request.form.get('requirement', '').strip()
    
    if not requirement:
        flash('Requirement name is missing.', 'danger')
        return redirect(url_for('hr2.my_career', context=context))
    
    file = request.files['proof_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('hr2.my_career', context=context))
        
    try:
        # Get active assignment
        resp = client.table('staff_career_paths')\
            .select('*')\
            .eq('user_id', current_user.id)\
            .order('updated_at', desc=True)\
            .execute()
            
        if not resp.data:
            flash('No active roadmap found.', 'warning')
            return redirect(url_for('hr2.my_career', context=context))
            
        assignments = resp.data
        assignment = next((a for a in assignments if a['status'] in ['Active', 'Pending Approval']), assignments[0])
        
        # Upload to Storage
        ext = os.path.splitext(file.filename)[1].lower()
        file_path = f"career_evidence/{current_user.id}_{assignment['id']}_{requirement.replace(' ', '_')}{ext}"
        bucket_name = 'career_proofs'
        
        file_content = file.read()
        
        # Upload
        try:
            client.storage.from_(bucket_name).upload(
                path=file_path,
                file=file_content,
                file_options={"content-type": file.content_type, "x-upsert": "true"}
            )
        except Exception as storage_err:
            if 'Bucket not found' in str(storage_err):
                flash(f'Upload failed: Storage bucket "{bucket_name}" does not exist. Please contact your administrator to create the bucket in Supabase storage.', 'danger')
            else:
                flash(f'Storage error: {str(storage_err)}', 'danger')
            return redirect(url_for('hr2.my_career', context=context))
        
        # Get public URL
        file_url = client.storage.from_(bucket_name).get_public_url(file_path)
        
        # Update JSONB requirement_evidence
        evidence = assignment.get('requirement_evidence') or {}
        if not isinstance(evidence, dict): evidence = {}
        
        evidence[requirement] = file_url
        
        client.table('staff_career_paths').update({
            'requirement_evidence': evidence,
            'updated_at': 'now()'
        }).eq('id', assignment['id']).execute()
        
        flash(f'Proof uploaded for {requirement}!', 'success')
        
    except Exception as e:
        flash(f'Upload failed: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.my_career', context=context))

@hr2_bp.route('/career-paths/request-completion', methods=['POST'])
@login_required
def request_career_milestone():
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()
    
    context = request.form.get('context', BLUEPRINT_NAME)
    notes = request.form.get('milestone_notes', '')
    
    # Get active assignment
    resp = client.table('staff_career_paths')\
        .select('*')\
        .eq('user_id', current_user.id)\
        .order('updated_at', desc=True)\
        .execute()
        
    if not resp.data:
        flash('No active career path found.', 'warning')
        return redirect(url_for('hr2.my_career', context=context))
        
    assignments = resp.data
    assignment = next((a for a in assignments if a['status'] in ['Active', 'Pending Approval']), assignments[0])
    
    try:
        # Update status and add notes
        client.table('staff_career_paths').update({
            'status': 'Pending Approval', 
            'milestone_notes': notes,
            'updated_at': 'now()'
        }).eq('id', assignment['id']).execute()
        
        # Notify HR Admins
        Notification.create(
            subsystem='hr2',
            role='Admin',
            title='Career Milestone Completion Request',
            message=f'Employee {current_user.username} has requested completion with notes: {notes[:50]}...',
            n_type='info',
            sender_subsystem='hr2',
            target_url='/hr2/career-paths'
        )
        
        flash('Completion request and evidence submitted to HR!', 'success')
    except Exception as e:
        flash(f'Submission failed: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.my_career', context=context))

@hr2_bp.route('/succession')
@login_required
def list_succession_plans():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch active hospital staff for selection (exclude patients/portal users)
    staff_response = client.table('users').select('id, username, department, role') \
        .eq('status', 'Active') \
        .not_.in_('role', ['Applicant', 'Patient', 'Administrator', 'SuperAdmin']) \
        .not_.in_('department', ['PATIENT_PORTAL', 'FINANCIALS']) \
        .order('username') \
        .execute()
    staff_members = staff_response.data if staff_response.data else []
    
    # Fetch succession plans with joined user data (using explicit foreign keys)
    plans_response = client.table('succession_plans').select('*, incumbent:users!incumbent_id(username), successor:users!successor_id(username)').execute()
    plans = plans_response.data if plans_response.data else []
    
    return render_template('subsystems/hr/hr2/succession.html',
                           plans=plans,
                           staff_members=staff_members,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/succession/add', methods=['POST'])
@login_required
def add_succession_plan():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_succession_plans'))
        
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()
    
    incumbent_id  = request.form.get('incumbent_id')
    successor_id  = request.form.get('successor_id')
    is_critical   = request.form.get('is_critical') == '1'
    role_title    = request.form.get('role_title')

    data = {
        'role_title': role_title,
        'incumbent_id': int(incumbent_id) if incumbent_id and incumbent_id.isdigit() else None,
        'successor_id': int(successor_id) if successor_id and successor_id.isdigit() else None,
        'readiness_level': request.form.get('readiness_level'),
        'risk_of_vacancy': request.form.get('risk_of_vacancy'),
        'development_notes': request.form.get('development_notes'),
        'is_critical': is_critical,
        'status': 'Pending Review',
    }
    
    try:
        client.table('succession_plans').insert(data).execute()

        # Notify successor that they have been identified
        if successor_id and successor_id.isdigit():
            Notification.create(
                user_id=int(successor_id),
                subsystem='hr2',
                title='You Have Been Identified as a Successor',
                message=f'You have been identified by HR as a potential successor for the role of "{role_title}". Please review your development plan.',
                n_type='info',
                sender_subsystem='hr2'
            )

        flash('Succession plan recorded!', 'success')
    except Exception as e:
        flash(f'Error adding succession plan: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_succession_plans'))

@hr2_bp.route('/succession/edit/<int:id>', methods=['POST'])
@login_required
def edit_succession_plan(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_succession_plans'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    incumbent_id = request.form.get('incumbent_id')
    successor_id = request.form.get('successor_id')
    is_critical  = request.form.get('is_critical') == '1'

    data = {
        'role_title': request.form.get('role_title'),
        'incumbent_id': int(incumbent_id) if incumbent_id and incumbent_id.isdigit() else None,
        'successor_id': int(successor_id) if successor_id and successor_id.isdigit() else None,
        'readiness_level': request.form.get('readiness_level'),
        'risk_of_vacancy': request.form.get('risk_of_vacancy'),
        'development_notes': request.form.get('development_notes'),
        'is_critical': is_critical,
    }
    
    try:
        client.table('succession_plans').update(data).eq('id', id).execute()
        flash('Succession plan updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating succession plan: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_succession_plans'))

@hr2_bp.route('/succession/delete/<int:id>', methods=['POST'])
@login_required
def delete_succession_plan(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_succession_plans'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('succession_plans').delete().eq('id', id).execute()
        flash('Succession plan removed.', 'info')
    except Exception as e:
        flash(f'Error deleting plan: {str(e)}', 'danger')
        
    return redirect(url_for('hr2.list_succession_plans'))


@hr2_bp.route('/succession/review/<int:id>', methods=['POST'])
@login_required
def review_succession(id):
    """HR reviews the succession plan and marks successor as Ready or Not Ready."""
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_succession_plans'))

    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()

    ready     = request.form.get('ready')  # '1' = Ready, '0' = Not Ready
    review_notes = request.form.get('review_notes') or None

    try:
        plan = client.table('succession_plans').select('successor_id, role_title').eq('id', id).maybe_single().execute()
        plan_data = plan.data if plan else {}
        successor_id = plan_data.get('successor_id')
        role_title   = plan_data.get('role_title', 'Role')

        new_status = 'Ready' if ready == '1' else 'Not Ready'
        client.table('succession_plans').update({
            'status': new_status,
            'review_notes': review_notes,
            'reviewed_by': current_user.id,
            'reviewed_at': datetime.utcnow().isoformat(),
        }).eq('id', id).execute()

        if successor_id:
            if ready == '1':
                msg  = f'You have been reviewed and marked as Ready for the role of "{role_title}".' + (f' Notes: {review_notes}' if review_notes else '')
                n_type = 'success'
            else:
                msg  = f'Your succession plan for "{role_title}" has been reviewed. Status: Not Yet Ready.' + (f' Notes: {review_notes}' if review_notes else '')
                n_type = 'warning'

            Notification.create(
                user_id=int(successor_id),
                subsystem='hr2',
                title=f'Succession Plan Reviewed: {role_title}',
                message=msg,
                n_type=n_type,
                sender_subsystem='hr2'
            )

        flash(f'Succession plan marked as {new_status}.', 'success')
    except Exception as e:
        flash(f'Error reviewing plan: {str(e)}', 'danger')

    return redirect(url_for('hr2.list_succession_plans'))


@hr2_bp.route('/succession/finalize/<int:id>', methods=['POST'])
@login_required
def finalize_succession(id):
    """HR finalizes a succession plan — notifies successor and incumbent."""
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr2.list_succession_plans'))

    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()

    try:
        plan = client.table('succession_plans').select('successor_id, incumbent_id, role_title').eq('id', id).maybe_single().execute()
        plan_data = plan.data if plan else {}
        successor_id = plan_data.get('successor_id')
        incumbent_id = plan_data.get('incumbent_id')
        role_title   = plan_data.get('role_title', 'Role')

        client.table('succession_plans').update({
            'status': 'Finalized',
            'finalized_by': current_user.id,
            'finalized_at': datetime.utcnow().isoformat(),
        }).eq('id', id).execute()

        if successor_id:
            Notification.create(
                user_id=int(successor_id),
                subsystem='hr2',
                title=f'Succession Plan Finalized: {role_title}',
                message=f'Your succession plan for the role of "{role_title}" has been finalized. You are the designated successor.',
                n_type='success',
                sender_subsystem='hr2'
            )

        if incumbent_id:
            Notification.create(
                user_id=int(incumbent_id),
                subsystem='hr2',
                title=f'Succession Plan Finalized: {role_title}',
                message=f'A succession plan for your role "{role_title}" has been finalized by HR.',
                n_type='info',
                sender_subsystem='hr2'
            )

        flash('Succession plan finalized and all parties notified!', 'success')
    except Exception as e:
        flash(f'Error finalizing plan: {str(e)}', 'danger')

    return redirect(url_for('hr2.list_succession_plans'))


@hr2_bp.route('/succession/update-notes/<int:id>', methods=['POST'])
@login_required
def update_succession_status(id):
    """Employee updates their own readiness notes on a succession plan."""
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    notes = request.form.get('development_notes') or None
    readiness = request.form.get('readiness_level') or None

    try:
        plan = client.table('succession_plans').select('successor_id').eq('id', id).maybe_single().execute()
        plan_data = plan.data if plan else {}
        if plan_data.get('successor_id') != current_user.id and not current_user.is_admin():
            flash('Unauthorized: You can only update your own succession notes.', 'danger')
            return redirect(url_for('hr2.list_succession_plans'))

        update_data = {}
        if notes is not None:
            update_data['development_notes'] = notes
        if readiness:
            update_data['readiness_level'] = readiness

        if update_data:
            client.table('succession_plans').update(update_data).eq('id', id).execute()
            flash('Development notes updated!', 'success')
    except Exception as e:
        flash(f'Error updating notes: {str(e)}', 'danger')

    return redirect(url_for('hr2.list_succession_plans'))

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

# Admin: User Management & Approvals
@hr2_bp.route('/admin/users')
@login_required
def user_list():
    if not current_user.is_super_admin() and (not current_user.is_admin() or current_user.subsystem != 'hr2'):
        flash('Access denied.', 'danger')
        return redirect(url_for('hr2.dashboard'))

    all_users = User.get_all()
    # Exclude Patient accounts — those are managed exclusively by CT1 (Core Transactions)
    users = [u for u in all_users if u.role != 'Patient' and u.department != 'PATIENT_PORTAL']
    return render_template('subsystems/hr/hr2/admin/user_list.html', 
                           users=users, 
                           subsystem_name=SUBSYSTEM_NAME, 
                           accent_color=ACCENT_COLOR,
                           subsystem_config=SUBSYSTEM_CONFIG,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_super_admin() and (not current_user.is_admin() or current_user.subsystem != 'hr2'):
        flash('Access denied.', 'danger')
        return redirect(url_for('hr2.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        subsystem = request.form.get('subsystem')
        role = request.form.get('role')
        status = request.form.get('status')
        
        config = SUBSYSTEM_CONFIG.get(subsystem)
        if not config:
            flash('Invalid subsystem selected.', 'danger')
            return render_template('subsystems/hr/hr2/admin/user_form.html', 
                                   subsystem_name=SUBSYSTEM_NAME, 
                                   subsystem_config=SUBSYSTEM_CONFIG,
                                   user=None,
                                   blueprint_name=BLUEPRINT_NAME)
        
        try:
            new_user = User.create(
                username=username,
                email=email,
                password=password,
                subsystem=subsystem,
                department=config['department'],
                role=role,
                status=status
            )
            
            if new_user:
                from utils.hms_models import AuditLog
                AuditLog.log(current_user.id, "Register User", BLUEPRINT_NAME, {"username": username, "subsystem": subsystem})
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'status': 'success', 'message': f'User {username} created successfully.'})
                flash(f'User {username} created successfully.', 'success')
                return redirect(url_for('hr2.user_list'))
            else:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'status': 'error', 'message': 'Failed to create user.'}), 400
                flash('Failed to create user.', 'danger')
        except PasswordValidationError as e:
            error_msg = ', '.join(e.errors)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': error_msg}), 400
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            error_msg = format_db_error(e)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': error_msg}), 400
            flash(error_msg, 'danger')
            
    return render_template('subsystems/hr/hr2/admin/user_form.html', 
                           subsystem_name=SUBSYSTEM_NAME, 
                           subsystem_config=SUBSYSTEM_CONFIG,
                           user=None,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_super_admin() and (current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr2'):
        flash('Access denied.', 'danger')
        return redirect(url_for('hr2.dashboard'))
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('hr2.user_list'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        subsystem = request.form.get('subsystem')
        role = request.form.get('role')
        status = request.form.get('status')
        password = request.form.get('password')
        
        config = SUBSYSTEM_CONFIG.get(subsystem)
        if not config:
            flash('Invalid subsystem selected.', 'danger')
            return redirect(url_for('hr2.user_list'))
        
        update_data = {
            'username': username,
            'email': email,
            'subsystem': subsystem,
            'department': config['department'],
            'role': role,
            'status': status,
            'is_active': status == 'Active'
        }
        
        try:
            if password:
                user.set_password(password)
                flash('Password updated.', 'info')
            
            if user.update(**update_data):
                from utils.hms_models import AuditLog
                AuditLog.log(current_user.id, "Update User", BLUEPRINT_NAME, {"target_user_id": user_id, "username": username})
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'status': 'success', 'message': f'User {username} updated successfully.'})
                flash(f'User {username} updated successfully.', 'success')
            else:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'status': 'error', 'message': 'Failed to update user.'}), 400
                flash('Failed to update user.', 'danger')
            
            return redirect(url_for('hr2.user_list'))
        except PasswordValidationError as e:
            error_msg = ', '.join(e.errors)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': error_msg}), 400
            for error in e.errors:
                flash(error, 'danger')
            return redirect(url_for('hr2.user_list'))
        except Exception as e:
            error_msg = format_db_error(e)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': error_msg}), 400
            flash(error_msg, 'danger')
            return redirect(url_for('hr2.user_list'))
            
    return render_template('subsystems/hr/hr2/admin/user_form.html', 
                           subsystem_name=SUBSYSTEM_NAME, 
                           subsystem_config=SUBSYSTEM_CONFIG,
                           user=user,
                           blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_super_admin() and (not current_user.is_admin() or current_user.subsystem != 'hr2'):
        flash('Access denied.', 'danger')
        return redirect(url_for('hr2.dashboard'))
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('hr2.user_list'))
    
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('hr2.user_list'))
        
    if user.delete():
        flash(f'User {user.username} deleted successfully.', 'success')
    else:
        flash('Failed to delete user.', 'danger')
        
    return redirect(url_for('hr2.user_list'))

@hr2_bp.route('/admin/approvals')
@login_required
def pending_approvals():
    if not current_user.is_super_admin() and (not current_user.is_admin() or current_user.subsystem != 'hr2'):
        flash('Access denied.', 'danger')
        return redirect(url_for('hr2.dashboard'))
    
    # Filter for pending users
    all_users = User.get_all()
    pending_users = [u for u in all_users if u.status == 'Pending']
    
    # Calculate stats for the dashboard
    approved_today = len([u for u in all_users if u.status == 'Active' and u.role != 'Administrator'])
    rejected_today = len([u for u in all_users if u.status == 'Rejected'])
    
    return render_template('subsystems/hr/hr2/admin/approvals.html', 
                          users=pending_users,
                          approved_count=approved_today,
                          rejected_count=rejected_today,
                          subsystem_name=SUBSYSTEM_NAME, 
                          accent_color=ACCENT_COLOR,
                          blueprint_name=BLUEPRINT_NAME)

@hr2_bp.route('/admin/approvals/<int:user_id>/<action>')
@login_required
def process_approval(user_id, action):
    if not current_user.is_super_admin() and (not current_user.is_admin() or current_user.subsystem != 'hr2'):
        flash('Access denied.', 'danger')
        return redirect(url_for('hr2.dashboard'))
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('hr2.pending_approvals'))
    
    try:
        if action == 'approve':
            user.update(status='Active', is_active=True)
            flash(f'User {user.username} has been approved.', 'success')
        elif action == 'deny':
            user.update(status='Rejected', is_active=False)
            flash(f'User {user.username} has been rejected.', 'warning')
    except Exception as e:
        flash(format_db_error(e), 'danger')
    
    return redirect(url_for('hr2.pending_approvals'))

@hr2_bp.route('/admin/users/<int:user_id>/toggle')
@login_required
def toggle_user_status(user_id):
    if not current_user.is_super_admin() and (not current_user.is_admin() or current_user.subsystem != 'hr2'):
        flash('Access denied.', 'danger')
        return redirect(url_for('hr2.dashboard'))
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('hr2.user_list'))
    
    try:
        # Toggle the status
        if user.status == 'Active':
            user.update(status='Rejected', is_active=False)
            flash(f'User {user.username} has been deactivated.', 'warning')
        else:
            user.update(status='Active', is_active=True)
            flash(f'User {user.username} has been activated.', 'success')
    except Exception as e:
        flash(format_db_error(e), 'danger')
    
    return redirect(url_for('hr2.user_list'))

@hr2_bp.route('/admin/users/<int:user_id>/reset-password')
@login_required
def reset_user_password(user_id):
    if not current_user.is_super_admin() and (not current_user.is_admin() or current_user.subsystem != 'hr2'):
        flash('Access denied.', 'danger')
        return redirect(url_for('hr2.dashboard'))
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('hr2.user_list'))
    
    try:
        # Reset to default password
        default_pw = "HMSPassword@123"
        user.set_password(default_pw, skip_validation=True)
        flash(f'Password for {user.username} has been reset to: {default_pw}', 'success')
    except Exception as e:
        flash(format_db_error(e), 'danger')
    return redirect(url_for('hr2.user_list'))

@hr2_bp.route('/admin/users/<int:user_id>/change-password', methods=['POST'])
@login_required
def admin_change_password(user_id):
    if not current_user.is_super_admin() and (not current_user.is_admin() or current_user.subsystem != 'hr2'):
        flash('Access denied.', 'danger')
        return redirect(url_for('hr2.dashboard'))
    
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('hr2.user_list'))
    
    new_password = request.form.get('new_password')
    if not new_password or len(new_password) < 8:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters long.'}), 400
        flash('Password must be at least 8 characters long.', 'warning')
        return redirect(url_for('hr2.user_list'))
    
    try:
        user.set_password(new_password, skip_validation=True)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'success', 'message': f'Password for {user.username} has been updated.'})
        flash(f'Password for {user.username} has been updated.', 'success')
    except Exception as e:
        error_msg = format_db_error(e)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': error_msg}), 400
        flash(error_msg, 'danger')
    return redirect(url_for('hr2.user_list'))



