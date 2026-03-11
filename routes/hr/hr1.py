from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error, get_supabase_client
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from utils.role_guards import HRRoles, prevent_applicant_access, supervisor_required, validate_interviewer
from datetime import datetime, timedelta

hr1_bp = Blueprint('hr1', __name__)

# Subsystem configuration
SUBSYSTEM_NAME = 'HR1 - Personnel Management'
ACCENT_COLOR = '#3B82F6'
SUBSYSTEM_ICON = 'person-plus-fill'
BLUEPRINT_NAME = 'hr1'

@hr1_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked(subsystem=BLUEPRINT_NAME)
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/hr/hr1/login.html', 
                               remaining_seconds=remaining_seconds,
                               subsystem_name=SUBSYSTEM_NAME,
                               accent_color=ACCENT_COLOR,
                               subsystem_icon=SUBSYSTEM_ICON,
                               blueprint_name=BLUEPRINT_NAME,
                               hub_route='portal.hr_hub')
    
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
                    return render_template('subsystems/hr/hr1/login.html',
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           subsystem_icon=SUBSYSTEM_ICON,
                                           blueprint_name=BLUEPRINT_NAME,
                                           hub_route='portal.hr_hub')

                # Check for password expiration - redirect to change password
                if user.password_expires_at and user.password_expires_at < now_utc:
                    # Store user info in session for password change
                    session['expired_user_id'] = user.id
                    session['expired_subsystem'] = BLUEPRINT_NAME
                    flash('Your password has expired. Please set a new password to continue.', 'warning')
                    return redirect(url_for('hr1.change_password'))

                # Clear IP lockout attempts on successful login
                register_successful_login(subsystem=BLUEPRINT_NAME)
                user.register_successful_login()
                
                if login_user(user):
                    days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                    if days_left <= 7:
                        flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    return redirect(url_for('hr1.dashboard'))
                else:
                    flash('Login failed. Your account may be deactivated.', 'danger')
                    return render_template('subsystems/hr/hr1/login.html',
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           subsystem_icon=SUBSYSTEM_ICON,
                                           blueprint_name=BLUEPRINT_NAME,
                                           hub_route='portal.hr_hub')
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt(subsystem=BLUEPRINT_NAME)
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/hr/hr1/login.html', 
                                           remaining_seconds=remaining_seconds,
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           subsystem_icon=SUBSYSTEM_ICON,
                                           blueprint_name=BLUEPRINT_NAME,
                                           hub_route='portal.hr_hub')
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
                
            # Register failed attempt even for non-existent users (prevents user enumeration)
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt(subsystem=BLUEPRINT_NAME)
            
            if is_now_locked:
                return render_template('subsystems/hr/hr1/login.html', 
                                       remaining_seconds=remaining_seconds,
                                       subsystem_name=SUBSYSTEM_NAME,
                                       accent_color=ACCENT_COLOR,
                                       subsystem_icon=SUBSYSTEM_ICON,
                                       blueprint_name=BLUEPRINT_NAME,
                                       hub_route='portal.hr_hub')
            
    return render_template('subsystems/hr/hr1/login.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           subsystem_icon=SUBSYSTEM_ICON,
                           blueprint_name=BLUEPRINT_NAME,
                           hub_route='portal.hr_hub')


@hr1_bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Check if this is an expired password change (from session) or logged-in user
    expired_user_id = session.get('expired_user_id')
    expired_subsystem = session.get('expired_subsystem')
    is_expired = expired_user_id is not None and expired_subsystem == BLUEPRINT_NAME
    
    # Determine the user
    if is_expired:
        user = User.get_by_id(expired_user_id)
        if not user:
            session.pop('expired_user_id', None)
            session.pop('expired_subsystem', None)
            flash('Session expired. Please login again.', 'danger')
            return redirect(url_for('hr1.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('hr1.login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # For expired passwords, we don't require current password verification
        if not is_expired:
            if not user.check_password(current_password):
                flash('Current password is incorrect.', 'danger')
                return render_template('shared/change_password.html',
                    subsystem_name=SUBSYSTEM_NAME,
                    accent_color=ACCENT_COLOR,
                    blueprint_name=BLUEPRINT_NAME,
                    is_expired=is_expired)
        
        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('shared/change_password.html',
                subsystem_name=SUBSYSTEM_NAME,
                accent_color=ACCENT_COLOR,
                blueprint_name=BLUEPRINT_NAME,
                is_expired=is_expired)
        
        # Validate and set new password
        try:
            user.set_password(new_password)
            
            # Clear expired session data
            session.pop('expired_user_id', None)
            session.pop('expired_subsystem', None)
            
            flash('Password updated successfully! Please login with your new password.', 'success')
            
            # Logout if currently logged in, so they can login fresh
            if current_user.is_authenticated:
                logout_user()
            
            return redirect(url_for('hr1.login'))
            
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html',
        subsystem_name=SUBSYSTEM_NAME,
        accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME,
        is_expired=is_expired)

@hr1_bp.route('/dashboard')
@login_required
@policy_required(BLUEPRINT_NAME)
def dashboard():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    # Fetch some stats for the dashboard
    vacancies_count = client.table('vacancies').select('id', count='exact').eq('status', 'Open').execute().count
    applicants_count = client.table('applicants').select('id', count='exact').execute().count
    
    # Fetch interviews today
    today = datetime.utcnow().strftime('%Y-%m-%d')
    interviews_today_resp = client.table('interviews').select('*, applicants(first_name, last_name)').gte('interview_date', today).order('interview_date').limit(5).execute()
    interviews_today_count = client.table('interviews').select('id', count='exact').gte('interview_date', today).execute().count or 0
    recent_interviews = interviews_today_resp.data if interviews_today_resp.data else []
    
    # Recent applicants
    recent_applicants_resp = client.table('applicants').select('*').order('created_at', desc=True).limit(5).execute()
    recent_applicants = recent_applicants_resp.data if recent_applicants_resp.data else []

    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    
    return render_template('subsystems/hr/hr1/dashboard.html', 
                           now=datetime.utcnow,
                           vacancies_count=vacancies_count,
                           applicants_count=applicants_count,
                           interviews_today=interviews_today_count,
                           recent_applicants=recent_applicants,
                           recent_interviews=recent_interviews,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr1_bp.route('/vacancies')
@login_required
def list_vacancies():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch all vacancies
    response = client.table('vacancies').select('*').order('created_at', desc=True).execute()
    vacancies = response.data if response.data else []
    
    # Calculate summary stats for the dashboard
    stats = {
        'total': len(vacancies),
        'open': len([v for v in vacancies if v['status'] == 'Open']),
        'closed': len([v for v in vacancies if v['status'] != 'Open'])
    }
    
    return render_template('subsystems/hr/hr1/vacancies.html', 
                           vacancies=vacancies,
                           stats=stats,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr1_bp.route('/applicants')
@login_required
def list_applicants():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    status_filter = request.args.get('status')
    vacancy_id_filter = request.args.get('vacancy_id')
    
    # Fetch all applicants for stats calculation
    all_resp = client.table('applicants').select('*').execute()
    all_applicants = all_resp.data if all_resp.data else []
    
    # Calculate stats
    stats = {
        'total': len(all_applicants),
        'screening': len([a for a in all_applicants if a['status'] == 'Screening']),
        'initial_interview': len([a for a in all_applicants if a['status'] == 'Initial Interview']),
        'final_interview': len([a for a in all_applicants if a['status'] == 'Final Interview']),
        'offer': len([a for a in all_applicants if a['status'] == 'Offer']),
        'reject': len([a for a in all_applicants if a['status'] == 'Rejected'])
    }
    
    query = client.table('applicants').select('*')
    if status_filter:
        query = query.eq('status', status_filter)
    if vacancy_id_filter:
        query = query.eq('vacancy_id', vacancy_id_filter)
        
    response = query.order('created_at', desc=True).execute()
        
    applicants = response.data if response.data else []
    
    # Fetch vacancies for mapping (since FK might be missing)
    vacancies_all_resp = client.table('vacancies').select('id, position_name').execute()
    vacancies_map = {v['id']: v['position_name'] for v in vacancies_all_resp.data} if vacancies_all_resp.data else {}
    
    # Add vacancy title to applicants manually
    for applicant in applicants:
        applicant['job_title'] = vacancies_map.get(applicant.get('vacancy_id'), 'N/A')
    
    # Fetch open vacancies for the "Add Applicant" modal
    vacancies_resp = client.table('vacancies').select('id, position_name').eq('status', 'Open').execute()
    vacancies = vacancies_resp.data if vacancies_resp.data else []

    return render_template('subsystems/hr/hr1/applicants.html', 
                           applicants=applicants,
                           stats=stats,
                           vacancies=vacancies,
                           status_filter=status_filter,
                           vacancy_id_filter=vacancy_id_filter,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr1_bp.route('/applicants/add', methods=['GET', 'POST'])
@login_required
def add_applicant():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr1.list_applicants'))
        
    if request.method == 'POST':
        from utils.supabase_client import get_supabase_client
        client = get_supabase_client()
        data = {
            'first_name': request.form.get('first_name'),
            'last_name': request.form.get('last_name'),
            'email': request.form.get('email'),
            'phone': request.form.get('phone'),
            'source': request.form.get('source'),
            'vacancy_id': request.form.get('vacancy_id'),
            'status': 'Screening'
        }
        client.table('applicants').insert(data).execute()
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Add Applicant", BLUEPRINT_NAME, {"name": f"{data['first_name']} {data['last_name']}"})
        flash('Applicant added successfully!', 'success')
        return redirect(url_for('hr1.list_applicants'))
    
    # If GET, redirect to the list with the add action to open the modal
    return redirect(url_for('hr1.list_applicants', action='add'))

@hr1_bp.route('/vacancies/add', methods=['GET', 'POST'])
@login_required
def add_vacancy():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr1.list_vacancies'))
        
    if request.method == 'POST':
        from utils.supabase_client import get_supabase_client
        client = get_supabase_client()
        
        data = {
            'position_name': request.form.get('position_name'),
            'department': request.form.get('department'),
            'reason': request.form.get('reason'),
            'requirements': request.form.get('requirements'),
            'qualifications': request.form.get('qualifications'),
            'status': 'Open',
            'approved_by': current_user.id
        }
        
        try:
            client.table('vacancies').insert(data).execute()
            from utils.hms_models import AuditLog
            AuditLog.log(current_user.id, "Post Vacancy", BLUEPRINT_NAME, {"position": data['position_name']})
            flash('New role has been posted to the recruitment board.', 'success')
        except Exception as e:
            flash(f'Failed to post vacancy: {str(e)}', 'danger')
            
        return redirect(url_for('hr1.list_vacancies'))
    
    return redirect(url_for('hr1.list_vacancies'))

@hr1_bp.route('/vacancies/edit/<int:id>', methods=['POST'])
@login_required
def edit_vacancy(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr1.list_vacancies'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    data = {
        'position_name': request.form.get('position_name'),
        'department': request.form.get('department'),
        'reason': request.form.get('reason'),
        'requirements': request.form.get('requirements'),
        'qualifications': request.form.get('qualifications'),
        'status': request.form.get('status', 'Open')
    }
    
    try:
        client.table('vacancies').update(data).eq('id', id).execute()
        flash('Vacancy details updated.', 'success')
    except Exception as e:
        flash(f'Error updating vacancy: {str(e)}', 'danger')
        
    return redirect(url_for('hr1.list_vacancies'))

@hr1_bp.route('/interviews')
@login_required
def list_interviews():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch all interviews with applicant names
    response = client.table('interviews').select('*, applicants(first_name, last_name)').order('interview_date', desc=False).execute()
    interviews = response.data if response.data else []
    
    # Get stats
    stats = {
        'total': len(interviews),
        'upcoming': len([i for i in interviews if i['status'] == 'Scheduled']),
        'completed': len([i for i in interviews if i['status'] == 'Completed']),
        'cancelled': len([i for i in interviews if i['status'] == 'Cancelled'])
    }
    
    return render_template('subsystems/hr/hr1/interviews.html', 
                           interviews=interviews,
                           stats=stats,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr1_bp.route('/interviews/<int:id>/update', methods=['POST'])
@login_required
def update_interview_status(id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    status = request.form.get('status')
    notes = request.form.get('notes')
    
    try:
        # Update interview record
        client.table('interviews').update({
            'status': status,
            'notes': notes
        }).eq('id', id).execute()
        
        # Logic for status progression
        # Fetch interview to get applicant_id
        intv_resp = client.table('interviews').select('applicant_id').eq('id', id).single().execute()
        if intv_resp.data:
            app_id = intv_resp.data['applicant_id']
            if status == 'Cancelled':
                client.table('applicants').update({'status': 'Rejected'}).eq('id', app_id).execute()
            # If completed, the user would usually use the details page to move to 'Offer'
        
        flash(f'Interview updated successfully.', 'success')
    except Exception as e:
        flash(f'Error updating interview: {str(e)}', 'danger')
        
    return redirect(url_for('hr1.list_interviews'))

@hr1_bp.route('/interviews/schedule', methods=['GET', 'POST'])
@login_required
@prevent_applicant_access
def schedule_interview():
    client = get_supabase_client()
    
    if request.method == 'POST':
        applicant_id = request.form.get('applicant_id')
        interview_date = request.form.get('interview_date')
        location = request.form.get('location')
        notes = request.form.get('notes')
        interviewer_id = current_user.id
        
        # Validate interviewer role
        try:
            validate_interviewer(interviewer_id)
        except ValueError as e:
            flash(str(e), 'danger')
            return redirect(url_for('hr1.schedule_interview'))
        
        data = {
            'applicant_id': applicant_id,
            'interviewer_id': interviewer_id,
            'interview_date': interview_date,
            'location': location,
            'notes': notes,
            'status': 'Scheduled'
        }
        
        try:
            client.table('interviews').insert(data).execute()
            client.table('applicants').update({'status': 'Initial Interview'}).eq('id', applicant_id).execute()
            flash('Interview scheduled successfully!', 'success')
            return redirect(url_for('hr1.list_applicants'))
        except Exception as e:
            flash(f'Error scheduling interview: {str(e)}', 'danger')
            
    # GET: fetch only schedulable applicants (Screening or Interview stage)
    applicants = client.table('applicants').select('*').in_('status', ['Screening', 'Initial Interview', 'Final Interview']).order('first_name').execute().data
    # Interviewers: only active HR1 users with roles capable of conducting interviews (no Applicants)
    interviewers = client.table('users').select('id, username, role').eq('subsystem', 'hr1').eq('status', 'Active').in_('role', ['Staff', 'HR_Staff', 'Interviewer', 'Manager', 'Admin', 'Administrator', 'SuperAdmin']).order('username').execute().data
    
    selected_applicant_id = request.args.get('applicant_id')
    
    return render_template('subsystems/hr/hr1/schedule_interview.html',
                           applicants=applicants,
                           interviewers=interviewers,
                           selected_applicant_id=selected_applicant_id,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr1_bp.route('/applicants/<int:id>/upload-cv', methods=['POST'])
@login_required
def upload_applicant_cv(id):
    if 'resume' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('hr1.applicant_details', id=id))
    
    file = request.files['resume']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('hr1.applicant_details', id=id))
    
    if file:
        try:
            from utils.supabase_client import get_supabase_client
            import os
            client = get_supabase_client()
            
            # Fetch current applicant to get documents
            applicant_resp = client.table('applicants').select('first_name, last_name, documents').eq('id', id).single().execute()
            if not applicant_resp.data:
                flash('Applicant not found.', 'danger')
                return redirect(url_for('hr1.list_applicants'))
            
            applicant = applicant_resp.data
            documents = applicant.get('documents') or []
            
            # File extension validation
            ext = os.path.splitext(file.filename)[1].lower()
            if ext not in ['.pdf', '.doc', '.docx']:
                flash('Invalid file type. Please upload a PDF or specialist document.', 'danger')
                return redirect(url_for('hr1.applicant_details', id=id))

            # Read file content
            file_content = file.read()
            # Max 5MB
            if len(file_content) > 5 * 1024 * 1024:
                flash('File too large (Max 5MB).', 'danger')
                return redirect(url_for('hr1.applicant_details', id=id))

            timestamp = int(datetime.utcnow().timestamp())
            safe_name = f"{applicant['first_name']}_{applicant['last_name']}".replace(' ', '_').lower()
            file_path = f"{safe_name}_{timestamp}{ext}"
            bucket_name = 'resumes'
            
            # Upload to Supabase Storage
            try:
                from utils.supabase_client import get_supabase_service_client
                storage_client = get_supabase_service_client()
                storage_client.storage.from_(bucket_name).upload(
                    path=file_path,
                    file=file_content,
                    file_options={"content-type": file.content_type, "x-upsert": "true"}
                )
                
                # Get public URL
                resume_url = storage_client.storage.from_(bucket_name).get_public_url(file_path)
                
                # Update documents list (either update existing resume or add new one)
                resume_exists = False
                for doc in documents:
                    if doc.get('type') == 'resume':
                        doc['url'] = resume_url
                        doc['filename'] = file.filename
                        resume_exists = True
                        break
                
                if not resume_exists:
                    documents.append({
                        'type': 'resume',
                        'filename': file.filename,
                        'url': resume_url
                    })
                
                # Update applicant in database
                client.table('applicants').update({'documents': documents}).eq('id', id).execute()
                
                from utils.hms_models import AuditLog
                AuditLog.log(current_user.id, "Upload CV", BLUEPRINT_NAME, {"applicant_id": id, "file": file.filename})
                
                flash('CV / Resume uploaded successfully!', 'success')
            except Exception as e:
                flash(f'Storage Error: {str(e)}', 'danger')
                
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')
            
    return redirect(url_for('hr1.applicant_details', id=id))

@hr1_bp.route('/applicants/<int:id>/status/<string:status>', methods=['POST'])
@login_required
def update_applicant_status_quick(id, status):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('applicants').update({'status': status}).eq('id', id).execute()
        flash(f'Applicant status updated to {status}.', 'success')
    except Exception as e:
        flash(f'Error updating status: {str(e)}', 'danger')
        
    return redirect(url_for('hr1.list_applicants'))

@hr1_bp.route('/applicants/<int:id>/handoff', methods=['POST'])
@login_required
def handoff_hr2(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr1.list_applicants'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Fetch applicant to get their vacancy_id
        applicant_resp = client.table('applicants').select('first_name, last_name, vacancy_id').eq('id', id).single().execute()
        if not applicant_resp.data:
            flash('Applicant not found', 'danger')
            return redirect(url_for('hr1.list_applicants'))
        
        applicant = applicant_resp.data
        
        # Update applicant status
        client.table('applicants').update({'status': 'Hired'}).eq('id', id).execute()
        
        # Create onboarding record in HR2
        onboarding_data = {
            'applicant_id': id,
            'position_id': applicant.get('vacancy_id'),
            'status': 'Pending'
        }
        client.table('onboarding').insert(onboarding_data).execute()

        # Notify HR2 for onboarding
        from utils.hms_models import Notification
        Notification.create(
            subsystem='hr2',
            title="Personnel Handoff",
            message=f"{applicant['first_name']} {applicant['last_name']} has been handed off for onboarding.",
            n_type="info",
            sender_subsystem=BLUEPRINT_NAME,
            target_url=url_for('hr2.onboarding_pipeline')
        )
        
        flash(f'Success! {applicant["first_name"]} {applicant["last_name"]} has been handed off to HR2 for onboarding.', 'success')
    except Exception as e:
        flash(f'Error during handoff: {str(e)}', 'danger')
        
    return redirect(url_for('hr1.list_applicants'))

@hr1_bp.route('/applicants/<int:id>/schedule', methods=['POST'])
@login_required
def schedule_interview_quick(id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    interview_date = request.form.get('interview_date')
    location = request.form.get('location')
    
    try:
        # Create interview record
        interview_data = {
            'applicant_id': id,
            'interviewer_id': current_user.id,
            'interview_date': interview_date,
            'location': location,
            'status': 'Scheduled'
        }
        client.table('interviews').insert(interview_data).execute()
        
        # Update applicant status
        client.table('applicants').update({'status': 'Interview'}).eq('id', id).execute()
        
        flash('Interview scheduled successfully!', 'success')
    except Exception as e:
        flash(f'Error scheduling interview: {str(e)}', 'danger')
        
    return redirect(url_for('hr1.list_applicants'))

@hr1_bp.route('/applicants/<int:id>')
@login_required
def applicant_details(id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch applicant details
    applicant_resp = client.table('applicants').select('*').eq('id', id).single().execute()
    if not applicant_resp.data:
        flash('Applicant not found.', 'danger')
        return redirect(url_for('hr1.list_applicants'))
    
    applicant = applicant_resp.data
    
    # Fetch interviews for this applicant
    interviews_resp = client.table('interviews').select('*, users(username)').eq('applicant_id', id).execute()
    interviews = interviews_resp.data if interviews_resp.data else []
    
    # Fetch open vacancies for handoff
    vacancies_resp = client.table('vacancies').select('id, position_name').eq('status', 'Open').execute()
    vacancies = vacancies_resp.data if vacancies_resp.data else []
    
    return render_template('subsystems/hr/hr1/applicant_details.html',
                           applicant=applicant,
                           interviews=interviews,
                           vacancies=vacancies,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr1_bp.route('/applicants/<int:id>/update-status', methods=['POST'])
@login_required
def update_applicant_status(id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    new_status = request.form.get('status')
    try:
        client.table('applicants').update({'status': new_status}).eq('id', id).execute()
        flash(f'Applicant status updated to {new_status}.', 'success')
    except Exception as e:
        flash(f'Error updating status: {str(e)}', 'danger')
        
    return redirect(url_for('hr1.applicant_details', id=id))

@hr1_bp.route('/applicants/<int:id>/delete', methods=['POST'])
@login_required
def delete_applicant(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr1.list_applicants'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('applicants').delete().eq('id', id).execute()
        flash('Applicant deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error deleting applicant: {str(e)}', 'danger')
        
    return redirect(url_for('hr1.list_applicants'))

@hr1_bp.route('/vacancies/<int:id>/delete', methods=['POST'])
@login_required
def delete_vacancy(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr1.list_vacancies'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('vacancies').delete().eq('id', id).execute()
        flash('Vacancy deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error deleting vacancy: {str(e)}', 'danger')
        
    return redirect(url_for('hr1.list_vacancies'))

@hr1_bp.route('/handoff/hr2', methods=['POST'])
@login_required
def legacy_handoff_hr2():
    # Keep as a redirect to unified flow if needed, or remove later
    applicant_id = request.form.get('applicant_id')
    return redirect(url_for('hr1.handoff_hr2', id=applicant_id))

@hr1_bp.route('/settings', methods=['GET', 'POST'])
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

@hr1_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hr1.login'))


# =====================================================
# FEATURE 2: EMPLOYEE PORTAL / PERSONAL DASHBOARD
# =====================================================

@hr1_bp.route('/my-dashboard')
@login_required
@policy_required(BLUEPRINT_NAME)
def employee_dashboard():
    client = get_supabase_client()
    user = current_user

    # Announcements
    try:
        ann_resp = client.table('announcements').select('*').eq('is_active', True).order('created_at', desc=True).limit(5).execute()
        announcements = ann_resp.data or []
    except Exception:
        announcements = []

    # Pending tasks
    try:
        tasks_resp = client.table('employee_tasks').select('*').eq('user_id', user.id).eq('status', 'Pending').order('due_date').limit(10).execute()
        pending_tasks = tasks_resp.data or []
    except Exception:
        pending_tasks = []

    # Team data for supervisors
    team_data = None
    if user.role in ['Manager', 'Admin', 'Administrator', 'SuperAdmin', 'HR_Staff']:
        try:
            team_resp = client.table('users').select('id, full_name, username, role, status, last_login').eq('department', user.department).neq('id', user.id).eq('status', 'Active').execute()
            team_data = team_resp.data or []
        except Exception:
            team_data = []

    # My probation cycles
    try:
        prob_resp = client.table('probation_cycles').select('*').eq('employee_id', user.id).eq('status', 'Active').execute()
        my_probation = prob_resp.data[0] if prob_resp.data else None
    except Exception:
        my_probation = None

    # My recognitions
    try:
        rec_resp = client.table('recognition_nominations').select('*, recognition_types(name, icon)').eq('nominee_id', user.id).eq('status', 'Approved').order('created_at', desc=True).limit(5).execute()
        my_recognitions = rec_resp.data or []
    except Exception:
        my_recognitions = []

    # Leave balance info + recent leave requests
    try:
        leave_resp = client.table('leave_requests').select('id', count='exact').eq('user_id', user.id).eq('status', 'Approved').execute()
        leaves_used = leave_resp.count or 0
    except Exception:
        leaves_used = 0

    try:
        my_leaves_resp = client.table('leave_requests').select('*').eq('user_id', user.id).order('created_at', desc=True).limit(5).execute()
        my_leaves = my_leaves_resp.data or []
    except Exception:
        my_leaves = []

    # Today's attendance status
    try:
        today_str = datetime.now().strftime('%Y-%m-%d')
        today_att_resp = client.table('attendance_logs').select('*').eq('user_id', user.id).gte('clock_in', today_str).order('clock_in', desc=True).limit(1).execute()
        today_attendance = today_att_resp.data[0] if today_att_resp.data else None
        is_clocked_in = today_attendance is not None and today_attendance.get('clock_out') is None
    except Exception:
        today_attendance = None
        is_clocked_in = False

    # My schedule for today
    try:
        day_name = datetime.now().strftime('%A')
        sched_resp = client.table('staff_schedules').select('*').eq('user_id', user.id).eq('is_active', True).or_(f"day_of_week.eq.{day_name},day_of_week.eq.Daily").execute()
        my_schedule = sched_resp.data[0] if sched_resp.data else None
    except Exception:
        my_schedule = None

    # All weekly schedules for the schedule modal
    try:
        all_sched_resp = client.table('staff_schedules').select('*').eq('user_id', user.id).execute()
        schedules = all_sched_resp.data or []
    except Exception:
        schedules = []

    # Upcoming interviews where user is the interviewer
    try:
        interview_now = datetime.now().isoformat()
        upcoming_interviews_resp = client.table('interviews').select('*, applicants(first_name, last_name)').eq('interviewer_id', user.id).eq('status', 'Scheduled').gte('interview_date', interview_now).order('interview_date').limit(5).execute()
        my_upcoming_interviews = upcoming_interviews_resp.data or []
    except Exception:
        my_upcoming_interviews = []

    return render_template('subsystems/hr/hr1/employee_dashboard.html',
                           announcements=announcements,
                           pending_tasks=pending_tasks,
                           team_data=team_data,
                           my_probation=my_probation,
                           my_recognitions=my_recognitions,
                           leaves_used=leaves_used,
                           my_leaves=my_leaves,
                           today_attendance=today_attendance,
                           is_clocked_in=is_clocked_in,
                           my_schedule=my_schedule,
                           schedules=schedules,
                           my_upcoming_interviews=my_upcoming_interviews,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr1_bp.route('/announcements', methods=['GET', 'POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def announcements():
    client = get_supabase_client()

    can_announce = current_user.is_admin() or current_user.role in ['Staff', 'HR_Staff']

    if request.method == 'POST' and can_announce:
        ann_title = request.form.get('title', '').strip()
        ann_content = request.form.get('content', '').strip()
        ann_priority = request.form.get('priority', 'Normal')
        ann_dept = request.form.get('target_department') or None

        data = {
            'title': ann_title,
            'content': ann_content,
            'priority': ann_priority,
            'target_department': ann_dept,
            'target_subsystem': request.form.get('target_subsystem') or None,
            'published_by': current_user.id,
            'is_active': True
        }
        try:
            client.table('announcements').insert(data).execute()
            flash('Announcement published successfully!', 'success')

            # --- Fire notifications ---
            from utils.hms_models import Notification
            n_type = 'danger' if ann_priority == 'Urgent' else ('warning' if ann_priority == 'Important' else 'info')
            preview = (ann_content[:100] + '…') if len(ann_content) > 100 else ann_content
            notif_msg = f"[{ann_priority}] {preview}"
            target_url = url_for('hr1.announcements')

            if ann_dept:
                # Notify every user in the target department individually
                try:
                    dept_users = client.table('users').select('id').eq('department', ann_dept).eq('status', 'Active').execute().data or []
                    for u in dept_users:
                        Notification.create(
                            user_id=u['id'],
                            title=f"📢 {ann_title}",
                            message=notif_msg,
                            n_type=n_type,
                            sender_subsystem=BLUEPRINT_NAME,
                            target_url=target_url
                        )
                except Exception as ne:
                    print(f"Notification error (dept broadcast): {ne}")
            else:
                # Broadcast to all active subsystems
                ALL_SUBSYSTEMS = ['hr1', 'hr2', 'hr3', 'superadmin', 'portal']
                for sub in ALL_SUBSYSTEMS:
                    try:
                        Notification.create(
                            subsystem=sub,
                            title=f"📢 {ann_title}",
                            message=notif_msg,
                            n_type=n_type,
                            sender_subsystem=BLUEPRINT_NAME,
                            target_url=target_url
                        )
                    except Exception as ne:
                        print(f"Notification error (subsystem {sub}): {ne}")

        except Exception as e:
            flash(f'Error publishing announcement: {str(e)}', 'danger')
        return redirect(url_for('hr1.announcements'))

    # Filter params
    filter_priority = request.args.get('priority', '')
    filter_dept = request.args.get('department', '')
    filter_status = request.args.get('status', '')
    search_q = request.args.get('q', '').strip()

    query = client.table('announcements').select('*, users(username)').order('created_at', desc=True)
    if filter_priority:
        query = query.eq('priority', filter_priority)
    if filter_dept:
        query = query.eq('target_department', filter_dept)
    if filter_status == 'active':
        query = query.eq('is_active', True)
    elif filter_status == 'inactive':
        query = query.eq('is_active', False)

    all_ann = query.limit(100).execute().data or []

    # Client-side search filter
    if search_q:
        sq = search_q.lower()
        all_ann = [a for a in all_ann if sq in (a.get('title') or '').lower() or sq in (a.get('content') or '').lower()]

    # Get distinct departments from users for the dropdown
    try:
        dept_resp = client.table('users').select('department').execute()
        departments = sorted(set(u['department'] for u in (dept_resp.data or []) if u.get('department')))
    except Exception:
        departments = []

    return render_template('subsystems/hr/hr1/announcements.html',
                           announcements=all_ann,
                           departments=departments,
                           filter_priority=filter_priority,
                           filter_dept=filter_dept,
                           filter_status=filter_status,
                           search_q=search_q,
                           can_announce=can_announce,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr1_bp.route('/announcements/<int:ann_id>/update', methods=['POST'])
@login_required
def update_announcement(ann_id):
    client = get_supabase_client()
    # Admins can edit any; Staff can only edit their own
    if not current_user.is_admin():
        owner = client.table('announcements').select('published_by').eq('id', ann_id).single().execute()
        if not owner.data or owner.data.get('published_by') != current_user.id:
            flash('Unauthorized.', 'danger')
            return redirect(url_for('hr1.announcements'))
    try:
        client.table('announcements').update({
            'title': request.form.get('title'),
            'content': request.form.get('content'),
            'priority': request.form.get('priority', 'Normal'),
            'target_department': request.form.get('target_department') or None,
        }).eq('id', ann_id).execute()
        flash('Announcement updated.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.announcements'))


@hr1_bp.route('/announcements/<int:ann_id>/toggle', methods=['POST'])
@login_required
def toggle_announcement(ann_id):
    client = get_supabase_client()
    if not current_user.is_admin():
        owner = client.table('announcements').select('published_by').eq('id', ann_id).single().execute()
        if not owner.data or owner.data.get('published_by') != current_user.id:
            flash('Unauthorized.', 'danger')
            return redirect(url_for('hr1.announcements'))
    try:
        current = client.table('announcements').select('is_active').eq('id', ann_id).single().execute()
        new_state = not current.data.get('is_active', True)
        client.table('announcements').update({'is_active': new_state}).eq('id', ann_id).execute()
        flash(f'Announcement {"activated" if new_state else "deactivated"}.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.announcements'))


@hr1_bp.route('/announcements/<int:ann_id>/delete', methods=['POST'])
@login_required
def delete_announcement(ann_id):
    client = get_supabase_client()
    if not current_user.is_admin():
        owner = client.table('announcements').select('published_by').eq('id', ann_id).single().execute()
        if not owner.data or owner.data.get('published_by') != current_user.id:
            flash('Unauthorized.', 'danger')
            return redirect(url_for('hr1.announcements'))
    try:
        client.table('announcements').delete().eq('id', ann_id).execute()
        flash('Announcement deleted.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.announcements'))


@hr1_bp.route('/tasks/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(task_id):
    client = get_supabase_client()
    try:
        client.table('employee_tasks').update({'status': 'Completed'}).eq('id', task_id).eq('user_id', current_user.id).execute()
        flash('Task completed!', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.employee_dashboard'))


# =====================================================
# FEATURE 3: PERFORMANCE MANAGEMENT (PROBATIONARY CYCLE)
# =====================================================

@hr1_bp.route('/probation')
@login_required
@policy_required(BLUEPRINT_NAME)
@prevent_applicant_access
def probation_list():
    client = get_supabase_client()
    user = current_user

    if user.is_admin() or user.is_super_admin():
        cycles_resp = client.table('probation_cycles').select('*, users!probation_cycles_employee_id_fkey(id, username, full_name)').order('created_at', desc=True).execute()
    elif HRRoles.can_supervise(user.role):
        cycles_resp = client.table('probation_cycles').select('*, users!probation_cycles_employee_id_fkey(id, username, full_name)').eq('supervisor_id', user.id).order('created_at', desc=True).execute()
    else:
        cycles_resp = client.table('probation_cycles').select('*, users!probation_cycles_supervisor_id_fkey(id, username, full_name)').eq('employee_id', user.id).order('created_at', desc=True).execute()

    cycles = cycles_resp.data or []

    # Stats
    stats = {
        'total': len(cycles),
        'active': len([c for c in cycles if c['status'] == 'Active']),
        'completed': len([c for c in cycles if c['status'] == 'Completed']),
        'extended': len([c for c in cycles if c['status'] == 'Extended']),
        'terminated': len([c for c in cycles if c['status'] == 'Terminated']),
    }

    # Fetch active staff employees only — exclude patients and applicants
    employees = []
    if user.is_admin() or HRRoles.can_supervise(user.role):
        emp_resp = client.table('users').select('id, username, full_name, department')\
            .eq('status', 'Active')\
            .not_.in_('role', ['Applicant', 'Patient'])\
            .neq('department', 'PATIENT_PORTAL')\
            .order('full_name').execute()
        employees = emp_resp.data or []

    return render_template('subsystems/hr/hr1/probation/list.html',
                           cycles=cycles,
                           stats=stats,
                           employees=employees,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr1_bp.route('/probation/<int:cycle_id>/cancel', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def probation_cancel(cycle_id):
    if not (current_user.is_admin() or current_user.is_super_admin()):
        flash('Only HR Administrators can cancel probation cycles.', 'danger')
        return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))
    client = get_supabase_client()
    try:
        reason = request.form.get('reason', 'Cancelled by administrator.')
        client.table('probation_cycles').update({
            'status': 'Cancelled',
            'updated_at': datetime.utcnow().isoformat()
        }).eq('id', cycle_id).execute()
        # Log a note
        client.table('performance_notes').insert({
            'cycle_id': cycle_id,
            'author_id': current_user.id,
            'note_type': 'Admin',
            'content': f'Cycle cancelled. Reason: {reason}',
            'is_published': True
        }).execute()
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Cancel Probation Cycle", BLUEPRINT_NAME, {"cycle_id": cycle_id, "reason": reason})
        flash('Probation cycle has been cancelled.', 'info')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.probation_list'))


@hr1_bp.route('/probation/<int:cycle_id>/kpis/<int:kpi_id>/delete', methods=['POST'])
@login_required
@supervisor_required
def probation_delete_kpi(cycle_id, kpi_id):
    client = get_supabase_client()
    try:
        # Only allow deletion if cycle is still in setup stages
        cycle = client.table('probation_cycles').select('current_stage, supervisor_id').eq('id', cycle_id).single().execute().data
        if not cycle:
            flash('Cycle not found.', 'danger')
            return redirect(url_for('hr1.probation_list'))
        if cycle['supervisor_id'] != current_user.id and not current_user.is_admin():
            flash('Unauthorized.', 'danger')
            return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))
        if cycle['current_stage'] not in ['ASSIGNED', 'KPI_SETUP']:
            flash('KPIs cannot be removed after the setup stage.', 'warning')
            return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))
        client.table('probation_kpis').delete().eq('id', kpi_id).eq('cycle_id', cycle_id).execute()
        flash('KPI removed.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


@hr1_bp.route('/probation/<int:cycle_id>/kpis/<int:kpi_id>/score', methods=['POST'])
@login_required
@supervisor_required
def probation_log_kpi_progress(cycle_id, kpi_id):
    """Log a periodic KPI progress score during the MONITORING stage."""
    client = get_supabase_client()
    try:
        score = float(request.form.get('score', 0))
        notes = request.form.get('notes', '')
        client.table('probation_kpi_progress').insert({
            'cycle_id': cycle_id,
            'kpi_id': kpi_id,
            'logged_by': current_user.id,
            'score': score,
            'notes': notes
        }).execute()
        flash('KPI progress logged.', 'success')
    except Exception as e:
        flash(f'Error logging progress: {str(e)}', 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


@hr1_bp.route('/probation/create', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
@supervisor_required
def probation_create():
    from utils.probation_engine import create_probation_cycle
    try:
        employee_id = int(request.form.get('employee_id'))
        supervisor_id = int(request.form.get('supervisor_id', current_user.id))
        cycle_type = request.form.get('cycle_type', 'New Hire')
        start_date = request.form.get('start_date')
        duration = int(request.form.get('duration_days', 90))

        cycle = create_probation_cycle(employee_id, supervisor_id, cycle_type, start_date, duration)
        if cycle:
            from utils.hms_models import AuditLog
            AuditLog.log(current_user.id, "Create Probation Cycle", BLUEPRINT_NAME, {"cycle_id": cycle['id'], "employee_id": employee_id})
            flash('Probation cycle created successfully!', 'success')
        else:
            flash('Failed to create probation cycle.', 'danger')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.probation_list'))


@hr1_bp.route('/probation/<int:cycle_id>')
@login_required
@policy_required(BLUEPRINT_NAME)
@prevent_applicant_access
def probation_detail(cycle_id):
    from utils.probation_engine import ProbationStage, get_stage_progress, get_stage_index
    client = get_supabase_client()

    cycle_resp = client.table('probation_cycles').select('*').eq('id', cycle_id).single().execute()
    if not cycle_resp.data:
        flash('Probation cycle not found.', 'danger')
        return redirect(url_for('hr1.probation_list'))
    cycle = cycle_resp.data

    # Fetch related data
    employee = User.get_by_id(cycle['employee_id'])
    supervisor = User.get_by_id(cycle['supervisor_id'])
    kpis = client.table('probation_kpis').select('*').eq('cycle_id', cycle_id).order('created_at').execute().data or []
    ack_resp = client.table('kpi_acknowledgements').select('*').eq('cycle_id', cycle_id).execute()
    acknowledgement = ack_resp.data[0] if ack_resp.data else None
    notes = client.table('performance_notes').select('*, users(username)').eq('cycle_id', cycle_id).order('created_at', desc=True).execute().data or []
    checkin_resp = client.table('mid_probation_checkins').select('*').eq('cycle_id', cycle_id).execute()
    checkin = checkin_resp.data[0] if checkin_resp.data else None
    eval_resp = client.table('final_evaluations').select('*').eq('cycle_id', cycle_id).execute()
    evaluation = eval_resp.data[0] if eval_resp.data else None
    rec_resp = client.table('probation_recommendations').select('*').eq('cycle_id', cycle_id).execute()
    recommendation = rec_resp.data[0] if rec_resp.data else None
    dec_resp = client.table('hr_decisions').select('*').eq('cycle_id', cycle_id).execute()
    decision = dec_resp.data[0] if dec_resp.data else None

    # Filter unpublished notes for employees
    if current_user.id == cycle['employee_id']:
        notes = [n for n in notes if n.get('is_published', False)]

    progress = get_stage_progress(cycle['current_stage'])
    current_stage_idx = get_stage_index(cycle['current_stage'])

    return render_template('subsystems/hr/hr1/probation/detail.html',
                           cycle=cycle,
                           employee=employee,
                           supervisor=supervisor,
                           kpis=kpis,
                           acknowledgement=acknowledgement,
                           notes=notes,
                           checkin=checkin,
                           evaluation=evaluation,
                           recommendation=recommendation,
                           decision=decision,
                           progress=progress,
                           current_stage_idx=current_stage_idx,
                           stages=ProbationStage,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr1_bp.route('/probation/<int:cycle_id>/kpis', methods=['POST'])
@login_required
@supervisor_required
def probation_add_kpi(cycle_id):
    from utils.probation_engine import advance_stage, ProbationStage
    client = get_supabase_client()
    try:
        data = {
            'cycle_id': cycle_id,
            'category': request.form.get('category'),
            'kpi_name': request.form.get('kpi_name'),
            'description': request.form.get('description'),
            'target_value': request.form.get('target_value'),
            'weight': float(request.form.get('weight', 0)),
            'created_by': current_user.id
        }
        client.table('probation_kpis').insert(data).execute()

        # Auto-advance from ASSIGNED to KPI_SETUP on first KPI creation
        cycle = client.table('probation_cycles').select('current_stage').eq('id', cycle_id).single().execute()
        if cycle.data and cycle.data['current_stage'] == ProbationStage.ASSIGNED:
            advance_stage(cycle_id, ProbationStage.KPI_SETUP, current_user.id)

        flash('KPI added successfully!', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


@hr1_bp.route('/probation/<int:cycle_id>/kpis/finalize', methods=['POST'])
@login_required
@supervisor_required
def probation_finalize_kpis(cycle_id):
    from utils.probation_engine import advance_stage, ProbationStage
    try:
        advance_stage(cycle_id, ProbationStage.KPI_ACKNOWLEDGED, current_user.id)
        # Create acknowledgement record
        client = get_supabase_client()
        cycle = client.table('probation_cycles').select('employee_id').eq('id', cycle_id).single().execute()
        if cycle.data:
            client.table('kpi_acknowledgements').insert({
                'cycle_id': cycle_id,
                'employee_id': cycle.data['employee_id'],
                'status': 'Pending'
            }).execute()
            # Create a task for the employee
            client.table('employee_tasks').insert({
                'user_id': cycle.data['employee_id'],
                'title': 'Acknowledge your Performance KPIs',
                'description': 'Review and digitally sign your probation KPIs.',
                'task_type': 'kpi_acknowledge',
                'reference_id': cycle_id,
                'reference_table': 'probation_cycles'
            }).execute()
        flash('KPIs finalized. Employee has been notified to acknowledge.', 'success')
    except ValueError as e:
        flash(str(e), 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


@hr1_bp.route('/probation/<int:cycle_id>/acknowledge', methods=['POST'])
@login_required
def probation_acknowledge_kpis(cycle_id):
    from utils.probation_engine import advance_stage, ProbationStage
    client = get_supabase_client()
    try:
        digital_signature = request.form.get('digital_signature')
        if not digital_signature:
            flash('Please type your full name as digital signature.', 'danger')
            return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))

        client.table('kpi_acknowledgements').update({
            'acknowledged_at': datetime.utcnow().isoformat(),
            'digital_signature': digital_signature,
            'status': 'Acknowledged'
        }).eq('cycle_id', cycle_id).eq('employee_id', current_user.id).execute()

        advance_stage(cycle_id, ProbationStage.MONITORING, current_user.id)

        # Complete the task
        client.table('employee_tasks').update({'status': 'Completed'}).eq('reference_id', cycle_id).eq('task_type', 'kpi_acknowledge').eq('user_id', current_user.id).execute()

        flash('KPIs acknowledged successfully!', 'success')
    except ValueError as e:
        flash(str(e), 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


@hr1_bp.route('/probation/<int:cycle_id>/notes', methods=['POST'])
@login_required
@supervisor_required
def probation_add_note(cycle_id):
    client = get_supabase_client()
    try:
        data = {
            'cycle_id': cycle_id,
            'author_id': current_user.id,
            'note_type': request.form.get('note_type'),
            'content': request.form.get('content'),
            'is_published': request.form.get('is_published') == 'on'
        }
        client.table('performance_notes').insert(data).execute()
        flash('Performance note added.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


@hr1_bp.route('/probation/<int:cycle_id>/advance-to-midcheck', methods=['POST'])
@login_required
@supervisor_required
def probation_advance_midcheck(cycle_id):
    from utils.probation_engine import advance_stage, ProbationStage
    try:
        advance_stage(cycle_id, ProbationStage.MID_CHECK_IN, current_user.id)
        flash('Advanced to Mid-Probation Check-in stage.', 'success')
    except ValueError as e:
        flash(str(e), 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


@hr1_bp.route('/probation/<int:cycle_id>/mid-checkin', methods=['POST'])
@login_required
@supervisor_required
def probation_submit_checkin(cycle_id):
    from utils.probation_engine import advance_stage, ProbationStage
    client = get_supabase_client()
    try:
        overall_rating = request.form.get('overall_rating')
        has_gaps = overall_rating in ['Needs Improvement', 'At Risk']

        data = {
            'cycle_id': cycle_id,
            'supervisor_id': current_user.id,
            'gap_analysis': request.form.get('gap_analysis'),
            'improvement_plan': request.form.get('improvement_plan'),
            'overall_rating': overall_rating
        }
        client.table('mid_probation_checkins').insert(data).execute()

        if has_gaps:
            advance_stage(cycle_id, ProbationStage.IMPROVEMENT_PLAN, current_user.id)
            flash('Mid-probation check-in submitted. Performance gaps detected — employee must acknowledge the improvement plan before HR review.', 'warning')
        else:
            advance_stage(cycle_id, ProbationStage.DOCUMENTATION, current_user.id)
            flash('Mid-probation check-in submitted. No performance gaps — moved to Documentation stage.', 'success')
    except ValueError as e:
        flash(str(e), 'danger')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


@hr1_bp.route('/probation/<int:cycle_id>/acknowledge-ip', methods=['POST'])
@login_required
def probation_acknowledge_ip(cycle_id):
    """Employee acknowledges the Improvement Plan generated from mid-probation check-in."""
    client = get_supabase_client()
    try:
        cycle = client.table('probation_cycles').select('employee_id, supervisor_id, current_stage').eq('id', cycle_id).single().execute()
        if not cycle.data or cycle.data['employee_id'] != current_user.id:
            flash('Only the assigned employee can acknowledge the improvement plan.', 'danger')
            return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))
        if cycle.data['current_stage'] != 'IMPROVEMENT_PLAN':
            flash('Improvement plan acknowledgement is not applicable at this stage.', 'danger')
            return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))

        # Record acknowledgement as a performance note
        client.table('performance_notes').insert({
            'cycle_id': cycle_id,
            'author_id': current_user.id,
            'note_type': 'IP_Acknowledged',
            'content': f"Employee acknowledged the improvement plan. Digital signature: {request.form.get('digital_signature', current_user.full_name or current_user.username)}",
            'is_published': True
        }).execute()

        # Notify HR Admins to review the improvement plan
        from utils.hms_models import Notification
        Notification.create(
            subsystem='hr1',
            role='Admin',
            title="Improvement Plan Acknowledged — HR Review Required",
            message=f"An employee has acknowledged their improvement plan and is awaiting HR approval to continue.",
            n_type="warning",
            sender_subsystem='hr1'
        )

        flash('Improvement plan acknowledged. HR will now review before continuing.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


@hr1_bp.route('/probation/<int:cycle_id>/hr-review-ip', methods=['POST'])
@login_required
def probation_hr_review_ip(cycle_id):
    """HR reviews the acknowledged improvement plan and either approves (advance to DOCUMENTATION)
    or rejects (supervisor must revise the checkin/plan)."""
    if not current_user.is_admin() and not current_user.is_super_admin():
        flash('Only HR Administrators can review improvement plans.', 'danger')
        return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))

    from utils.probation_engine import advance_stage, ProbationStage
    client = get_supabase_client()
    try:
        action = request.form.get('action')  # 'approve' or 'reject'
        hr_notes = request.form.get('hr_notes', '')

        if action == 'approve':
            # Log HR approval note
            client.table('performance_notes').insert({
                'cycle_id': cycle_id,
                'author_id': current_user.id,
                'note_type': 'IP_HR_Approved',
                'content': f"HR approved the improvement plan. Notes: {hr_notes}",
                'is_published': True
            }).execute()
            advance_stage(cycle_id, ProbationStage.DOCUMENTATION, current_user.id)

            # Notify supervisor and employee
            cycle = client.table('probation_cycles').select('employee_id, supervisor_id').eq('id', cycle_id).single().execute()
            if cycle.data:
                from utils.hms_models import Notification
                Notification.create(user_id=cycle.data['supervisor_id'], subsystem='hr1', title="Improvement Plan Approved", message="HR has approved the improvement plan. The cycle has advanced to Documentation.", n_type="success", sender_subsystem='hr1')
                Notification.create(user_id=cycle.data['employee_id'], subsystem='hr1', title="Improvement Plan Approved", message="HR has reviewed and approved your improvement plan. Continue monitoring.", n_type="success", sender_subsystem='hr1')
            flash('Improvement plan approved. Cycle advanced to Documentation stage.', 'success')

        elif action == 'reject':
            # Log HR rejection — supervisor must revise
            client.table('performance_notes').insert({
                'cycle_id': cycle_id,
                'author_id': current_user.id,
                'note_type': 'IP_HR_Rejected',
                'content': f"HR rejected the improvement plan — revision required. Notes: {hr_notes}",
                'is_published': True
            }).execute()

            # Notify supervisor to revise the improvement plan
            cycle = client.table('probation_cycles').select('supervisor_id').eq('id', cycle_id).single().execute()
            if cycle.data:
                from utils.hms_models import Notification
                Notification.create(user_id=cycle.data['supervisor_id'], subsystem='hr1', title="Improvement Plan Needs Revision", message=f"HR has rejected the improvement plan. Please revise it. Notes: {hr_notes}", n_type="danger", sender_subsystem='hr1')

            # Delete previous IP_Acknowledged notes so employee can re-acknowledge after revision
            client.table('performance_notes').delete().eq('cycle_id', cycle_id).eq('note_type', 'IP_Acknowledged').execute()
            flash('Improvement plan sent back for revision. Supervisor has been notified.', 'warning')

    except ValueError as e:
        flash(str(e), 'danger')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


@hr1_bp.route('/probation/<int:cycle_id>/advance-to-eval', methods=['POST'])
@login_required
@supervisor_required
def probation_advance_eval(cycle_id):
    from utils.probation_engine import advance_stage, ProbationStage
    try:
        advance_stage(cycle_id, ProbationStage.FINAL_EVALUATION, current_user.id)
        flash('Advanced to Final Evaluation stage.', 'success')
    except ValueError as e:
        flash(str(e), 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


@hr1_bp.route('/probation/<int:cycle_id>/evaluate', methods=['POST'])
@login_required
@supervisor_required
def probation_submit_evaluation(cycle_id):
    from utils.probation_engine import advance_stage, ProbationStage
    client = get_supabase_client()
    try:
        kpis = client.table('probation_kpis').select('id, kpi_name, weight').eq('cycle_id', cycle_id).execute().data or []
        kpi_scores = []
        for kpi in kpis:
            score = request.form.get(f'kpi_score_{kpi["id"]}', 0)
            kpi_scores.append({'kpi_id': kpi['id'], 'name': kpi['kpi_name'], 'score': float(score), 'weight': float(kpi['weight'])})

        import json
        data = {
            'cycle_id': cycle_id,
            'evaluator_id': current_user.id,
            'kpi_scores': json.dumps(kpi_scores),
            'competency_rating': float(request.form.get('competency_rating', 0)),
            'conduct_rating': float(request.form.get('conduct_rating', 0)),
            'attendance_rating': float(request.form.get('attendance_rating', 0)),
            'overall_score': float(request.form.get('overall_score', 0)),
            'comments': request.form.get('comments')
        }
        client.table('final_evaluations').insert(data).execute()
        advance_stage(cycle_id, ProbationStage.RECOMMENDATION, current_user.id)
        flash('Final evaluation submitted. Please submit your recommendation.', 'success')
    except ValueError as e:
        flash(str(e), 'danger')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


@hr1_bp.route('/probation/<int:cycle_id>/recommend', methods=['POST'])
@login_required
@supervisor_required
def probation_submit_recommendation(cycle_id):
    from utils.probation_engine import advance_stage, ProbationStage
    client = get_supabase_client()
    try:
        data = {
            'cycle_id': cycle_id,
            'supervisor_id': current_user.id,
            'recommendation': request.form.get('recommendation'),
            'justification': request.form.get('justification')
        }
        client.table('probation_recommendations').insert(data).execute()
        advance_stage(cycle_id, ProbationStage.HR_DECISION, current_user.id)
        flash('Recommendation submitted to HR for final decision.', 'success')
    except ValueError as e:
        flash(str(e), 'danger')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


@hr1_bp.route('/probation/<int:cycle_id>/decision', methods=['POST'])
@login_required
def probation_submit_decision(cycle_id):
    if not current_user.is_admin() and not current_user.is_super_admin():
        flash('Only HR Administrators can submit final decisions.', 'danger')
        return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))

    client = get_supabase_client()
    try:
        # Get the supervisor's recommendation
        rec = client.table('probation_recommendations').select('recommendation').eq('cycle_id', cycle_id).execute()
        original_rec = rec.data[0]['recommendation'] if rec.data else None
        decision = request.form.get('decision')

        data = {
            'cycle_id': cycle_id,
            'hr_officer_id': current_user.id,
            'decision': decision,
            'modified_from': original_rec if original_rec != decision else None,
            'effective_date': request.form.get('effective_date'),
            'notes': request.form.get('notes')
        }
        client.table('hr_decisions').insert(data).execute()

        # Update cycle status
        status_map = {'Regularize': 'Completed', 'Extend': 'Extended', 'Terminate': 'Terminated', 'Reassign': 'Completed'}
        new_status = status_map.get(decision, 'Completed')
        client.table('probation_cycles').update({'status': new_status, 'updated_at': datetime.utcnow().isoformat()}).eq('id', cycle_id).execute()

        # Notify employee
        cycle = client.table('probation_cycles').select('employee_id').eq('id', cycle_id).single().execute()
        if cycle.data:
            from utils.hms_models import Notification
            Notification.create(
                user_id=cycle.data['employee_id'],
                subsystem='hr1',
                title=f"Probation Decision: {decision}",
                message=f"HR has issued a final decision on your probation: {decision}.",
                n_type="info" if decision == 'Regularize' else "warning",
                sender_subsystem='hr1'
            )

        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "HR Probation Decision", BLUEPRINT_NAME, {"cycle_id": cycle_id, "decision": decision})
        flash(f'HR Decision recorded: {decision}', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.probation_detail', cycle_id=cycle_id))


# =====================================================
# FEATURE 4: SOCIAL RECOGNITION MODULE
# =====================================================

@hr1_bp.route('/recognition')
@login_required
@policy_required(BLUEPRINT_NAME)
def recognition_wall():
    client = get_supabase_client()

    # Auto-reject stale nominations (30+ days pending)
    try:
        cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()
        stale = client.table('recognition_nominations').select('id').eq('status', 'Pending').lt('created_at', cutoff).execute()
        if stale.data:
            for nom in stale.data:
                client.table('recognition_nominations').update({
                    'status': 'Auto-Rejected',
                    'reviewed_at': datetime.utcnow().isoformat(),
                    'review_notes': 'Auto-rejected: No supervisor action within 30 days.'
                }).eq('id', nom['id']).execute()
                from utils.hms_models import AuditLog
                AuditLog.log(None, "Auto-Reject Nomination", BLUEPRINT_NAME, {"nomination_id": nom['id']})
    except Exception:
        pass

    # Approved recognitions (Wall of Fame)
    approved = client.table('recognition_nominations').select(
        '*, recognition_types(name, icon), nominee:users!recognition_nominations_nominee_id_fkey(username, full_name, department), nominator:users!recognition_nominations_nominator_id_fkey(username, full_name)'
    ).eq('status', 'Approved').order('reviewed_at', desc=True).limit(50).execute()

    # My nominations
    my_noms = client.table('recognition_nominations').select(
        '*, recognition_types(name, icon)'
    ).eq('nominator_id', current_user.id).order('created_at', desc=True).limit(10).execute()

    # Recognition types
    types = client.table('recognition_types').select('*').eq('is_active', True).execute()

    return render_template('subsystems/hr/hr1/recognition/wall_of_fame.html',
                           approved_recognitions=approved.data or [],
                           my_nominations=my_noms.data or [],
                           recognition_types=types.data or [],
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr1_bp.route('/recognition/nominate', methods=['GET', 'POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def recognition_nominate():
    client = get_supabase_client()

    if request.method == 'POST':
        nominee_id = int(request.form.get('nominee_id'))

        # Self-nomination prevention
        if nominee_id == current_user.id:
            flash('You cannot nominate yourself.', 'danger')
            return redirect(url_for('hr1.recognition_nominate'))

        # Find supervisor for the nominee — restrict to hr1 subsystem only
        nominee = User.get_by_id(nominee_id)
        supervisor_id = None
        if nominee:
            sup_resp = client.table('users').select('id').eq('department', nominee.department).eq('subsystem', 'hr1').in_('role', ['Manager', 'Admin', 'Administrator']).limit(1).execute()
            supervisor_id = sup_resp.data[0]['id'] if sup_resp.data else None

        # Handle optional supporting document upload
        attachment_url = None
        attachment_file = request.files.get('attachment')
        if attachment_file and attachment_file.filename:
            import os
            ext = os.path.splitext(attachment_file.filename)[1].lower()
            allowed_exts = ['.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png']
            if ext not in allowed_exts:
                flash('Invalid file type. Allowed: PDF, Word, JPG, PNG.', 'danger')
                return redirect(url_for('hr1.recognition_nominate'))
            file_content = attachment_file.read()
            if len(file_content) > 5 * 1024 * 1024:
                flash('File too large. Maximum size is 5 MB.', 'danger')
                return redirect(url_for('hr1.recognition_nominate'))
            try:
                from utils.supabase_client import get_supabase_service_client
                storage_client = get_supabase_service_client()
                bucket_name = 'recognition-docs'
                timestamp = int(datetime.utcnow().timestamp())
                safe_name = (current_user.username or str(current_user.id)).replace(' ', '_').lower()
                file_path = f"{safe_name}_{timestamp}{ext}"
                storage_client.storage.from_(bucket_name).upload(
                    path=file_path,
                    file=file_content,
                    file_options={"content-type": attachment_file.content_type, "x-upsert": "true"}
                )
                attachment_url = storage_client.storage.from_(bucket_name).get_public_url(file_path)
            except Exception as upload_err:
                flash(f'Document upload failed: {str(upload_err)}. Nomination submitted without attachment.', 'warning')

        data = {
            'nominee_id': nominee_id,
            'nominator_id': current_user.id,
            'recognition_type_id': int(request.form.get('recognition_type_id')),
            'justification': request.form.get('justification'),
            'supporting_details': request.form.get('supporting_details'),
            'attachment_url': attachment_url,
            'status': 'Pending',
            'supervisor_id': supervisor_id,
            'auto_reject_date': (datetime.utcnow() + timedelta(days=30)).strftime('%Y-%m-%d')
        }
        try:
            client.table('recognition_nominations').insert(data).execute()

            # Notify supervisor
            if supervisor_id:
                from utils.hms_models import Notification
                Notification.create(
                    user_id=supervisor_id,
                    subsystem='hr1',
                    title="New Recognition Nomination",
                    message=f"{current_user.username} has nominated {nominee.username if nominee else 'an employee'} for recognition. Please review.",
                    n_type="info",
                    sender_subsystem='hr1',
                    target_url=url_for('hr1.recognition_inbox')
                )

            # Notify the nominee
            if nominee:
                from utils.hms_models import Notification
                Notification.create(
                    user_id=nominee.id,
                    subsystem=nominee.subsystem,
                    title="You've Been Nominated for Recognition!",
                    message=f"Congratulations! {current_user.username} has nominated you for recognition. Your nomination is currently under review.",
                    n_type="success",
                    sender_subsystem='hr1',
                    target_url=url_for('hr1.recognition_wall')
                )

            flash('Nomination submitted successfully!', 'success')
            return redirect(url_for('hr1.recognition_wall'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')

    # GET: fetch all staff/manager employees across all subsystems (exclude admins, patients, superadmins)
    employees = client.table('users').select('id, username, full_name, department, role, subsystem').eq('status', 'Active').neq('id', current_user.id).in_('role', ['Staff', 'Manager']).order('full_name').execute()
    types = client.table('recognition_types').select('*').eq('is_active', True).execute()

    return render_template('subsystems/hr/hr1/recognition/nominate.html',
                           employees=employees.data or [],
                           recognition_types=types.data or [],
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr1_bp.route('/recognition/inbox')
@login_required
@policy_required(BLUEPRINT_NAME)
def recognition_inbox():
    """Multi-level approval inbox — each role sees their own queue."""
    client = get_supabase_client()
    SELECT_FIELDS = '*, recognition_types(name, icon), nominee:users!recognition_nominations_nominee_id_fkey(username, full_name, department), nominator:users!recognition_nominations_nominator_id_fkey(username, full_name)'

    is_hr = current_user.is_admin() or current_user.is_super_admin()
    is_management = is_hr or getattr(current_user, 'role', '') == 'Manager'

    # --- Supervisor Queue: Pending nominations where this user is the assigned supervisor ---
    supervisor_pending = []
    if not is_hr:  # Non-admins see only their own
        sp = client.table('recognition_nominations').select(SELECT_FIELDS).eq('supervisor_id', current_user.id).eq('status', 'Pending').order('created_at', desc=True).execute()
        supervisor_pending = sp.data or []
    else:  # Admins see all pending
        sp = client.table('recognition_nominations').select(SELECT_FIELDS).eq('status', 'Pending').order('created_at', desc=True).execute()
        supervisor_pending = sp.data or []

    # --- HR Queue: Supervisor_Approved nominations awaiting HR validation ---
    hr_queue = []
    if is_hr:
        hq = client.table('recognition_nominations').select(SELECT_FIELDS).eq('status', 'Supervisor_Approved').order('reviewed_at', desc=True).execute()
        hr_queue = hq.data or []

    # --- Management Queue: Management_Pending nominations awaiting committee decision ---
    management_queue = []
    if is_management:
        mq = client.table('recognition_nominations').select(SELECT_FIELDS).eq('status', 'Management_Pending').order('reviewed_at', desc=True).execute()
        management_queue = mq.data or []

    # --- History: all reviewed records visible to admins; own nominations to others ---
    if is_hr:
        hist = client.table('recognition_nominations').select(SELECT_FIELDS).not_.in_('status', ['Pending', 'Supervisor_Approved', 'Management_Pending']).order('reviewed_at', desc=True).limit(50).execute()
    else:
        hist = client.table('recognition_nominations').select(SELECT_FIELDS).eq('supervisor_id', current_user.id).not_.in_('status', ['Pending']).order('reviewed_at', desc=True).limit(20).execute()
    reviewed_nominations = hist.data or []

    total_pending = len(supervisor_pending) + len(hr_queue) + len(management_queue)

    return render_template('subsystems/hr/hr1/recognition/inbox.html',
                           supervisor_pending=supervisor_pending,
                           hr_queue=hr_queue,
                           management_queue=management_queue,
                           reviewed_nominations=reviewed_nominations,
                           total_pending=total_pending,
                           is_hr=is_hr,
                           is_management=is_management,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr1_bp.route('/recognition/<int:nom_id>/approve', methods=['POST'])
@login_required
def recognition_approve(nom_id):
    """Supervisor approves nomination and forwards it to HR."""
    client = get_supabase_client()
    try:
        nom_resp = client.table('recognition_nominations').select('nominator_id, nominee_id, supervisor_id').eq('id', nom_id).single().execute()
        nom = nom_resp.data
        if not nom:
            flash('Nomination not found.', 'danger')
            return redirect(url_for('hr1.recognition_inbox'))

        client.table('recognition_nominations').update({
            'status': 'Supervisor_Approved',
            'reviewed_at': datetime.utcnow().isoformat(),
            'review_notes': request.form.get('review_notes', '')
        }).eq('id', nom_id).execute()

        # Notify HR Admins to validate the nomination
        from utils.hms_models import Notification
        Notification.create(
            subsystem='hr1', role='Admin',
            title='Recognition Nomination Awaiting HR Validation',
            message='A supervisor has approved a nomination. Please validate it against HR policy.',
            n_type='info', sender_subsystem='hr1',
            target_url=url_for('hr1.recognition_inbox')
        )
        Notification.create(
            user_id=nom['nominator_id'], subsystem='hr1',
            title='Nomination Forwarded to HR',
            message='Your nomination has been approved by the supervisor and is now under HR review.',
            n_type='info', sender_subsystem='hr1'
        )
        flash('Nomination approved and forwarded to HR for validation.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.recognition_inbox'))


@hr1_bp.route('/recognition/<int:nom_id>/return', methods=['POST'])
@login_required
def recognition_return(nom_id):
    """Supervisor returns nomination to nominator for revision."""
    client = get_supabase_client()
    try:
        nom_resp = client.table('recognition_nominations').select('nominator_id').eq('id', nom_id).single().execute()
        nom = nom_resp.data
        if not nom:
            flash('Nomination not found.', 'danger')
            return redirect(url_for('hr1.recognition_inbox'))

        client.table('recognition_nominations').update({
            'status': 'Returned',
            'reviewed_at': datetime.utcnow().isoformat(),
            'review_notes': request.form.get('review_notes', '')
        }).eq('id', nom_id).execute()

        from utils.hms_models import Notification
        Notification.create(
            user_id=nom['nominator_id'], subsystem='hr1',
            title='Nomination Returned for Revision',
            message=f"Your nomination has been returned by the supervisor for revision. Reason: {request.form.get('review_notes', 'See feedback.')}",
            n_type='warning', sender_subsystem='hr1'
        )
        flash('Nomination returned to nominator for revision.', 'info')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.recognition_inbox'))


@hr1_bp.route('/recognition/<int:nom_id>/reject', methods=['POST'])
@login_required
def recognition_reject(nom_id):
    """Supervisor hard-rejects a nomination (e.g., fails basic criteria)."""
    client = get_supabase_client()
    try:
        nom_resp = client.table('recognition_nominations').select('nominator_id').eq('id', nom_id).single().execute()
        nom = nom_resp.data
        client.table('recognition_nominations').update({
            'status': 'Rejected',
            'reviewed_at': datetime.utcnow().isoformat(),
            'review_notes': request.form.get('review_notes', '')
        }).eq('id', nom_id).execute()

        if nom:
            from utils.hms_models import Notification
            Notification.create(user_id=nom['nominator_id'], subsystem='hr1', title='Nomination Rejected', message='Your recognition nomination did not meet the basic criteria and has been rejected.', n_type='warning', sender_subsystem='hr1')

        flash('Nomination rejected.', 'info')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.recognition_inbox'))


@hr1_bp.route('/recognition/<int:nom_id>/hr-review', methods=['POST'])
@login_required
def recognition_hr_review(nom_id):
    """HR validates the nomination against policy and either forwards to Management or rejects."""
    if not current_user.is_admin() and not current_user.is_super_admin():
        flash('Only HR Administrators can perform this action.', 'danger')
        return redirect(url_for('hr1.recognition_inbox'))

    client = get_supabase_client()
    try:
        action = request.form.get('action')  # 'forward' or 'reject'
        nom_resp = client.table('recognition_nominations').select('nominator_id, nominee_id').eq('id', nom_id).single().execute()
        nom = nom_resp.data

        if action == 'forward':
            client.table('recognition_nominations').update({
                'status': 'Management_Pending',
                'reviewed_at': datetime.utcnow().isoformat(),
                'review_notes': request.form.get('review_notes', '')
            }).eq('id', nom_id).execute()

            from utils.hms_models import Notification
            if nom:
                Notification.create(user_id=nom['nominator_id'], subsystem='hr1', title='Nomination Under Management Review', message='Your nomination has passed HR validation and is now under Management/Committee review.', n_type='info', sender_subsystem='hr1')
            flash('Nomination validated and forwarded to Management/Committee for final approval.', 'success')

        elif action == 'reject':
            client.table('recognition_nominations').update({
                'status': 'HR_Rejected',
                'reviewed_at': datetime.utcnow().isoformat(),
                'review_notes': request.form.get('review_notes', '')
            }).eq('id', nom_id).execute()

            from utils.hms_models import Notification
            if nom:
                Notification.create(user_id=nom['nominator_id'], subsystem='hr1', title='Nomination Rejected by HR', message=f"Your nomination did not pass HR policy validation. Reason: {request.form.get('review_notes', '')}", n_type='warning', sender_subsystem='hr1')
            flash('Nomination rejected at HR level.', 'info')

    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.recognition_inbox'))


@hr1_bp.route('/recognition/<int:nom_id>/management-review', methods=['POST'])
@login_required
def recognition_management_review(nom_id):
    """Management/Committee gives final approval or rejection. Approved → goes to Wall of Fame."""
    if not (current_user.is_admin() or current_user.is_super_admin() or getattr(current_user, 'role', '') == 'Manager'):
        flash('Management access required.', 'danger')
        return redirect(url_for('hr1.recognition_inbox'))

    client = get_supabase_client()
    try:
        action = request.form.get('action')  # 'approve' or 'reject'
        nom_resp = client.table('recognition_nominations').select('nominee_id, nominator_id, recognition_type_id').eq('id', nom_id).single().execute()
        nom = nom_resp.data

        if action == 'approve':
            client.table('recognition_nominations').update({
                'status': 'Approved',
                'reviewed_at': datetime.utcnow().isoformat(),
                'review_notes': request.form.get('review_notes', '')
            }).eq('id', nom_id).execute()

            # Notify nominee and nominator
            from utils.hms_models import Notification
            if nom:
                Notification.create(user_id=nom['nominee_id'], subsystem='hr1', title='Congratulations — Recognition Approved!', message='You have been officially recognized for your outstanding contribution. Your achievement will be featured on the Wall of Fame.', n_type='success', sender_subsystem='hr1')
                Notification.create(user_id=nom['nominator_id'], subsystem='hr1', title='Nomination Approved by Management', message='Your recognition nomination has been approved by Management and is now on the Wall of Fame.', n_type='success', sender_subsystem='hr1')
            # Notify HR to prepare certificate/incentive
            Notification.create(subsystem='hr1', role='Admin', title='Prepare Recognition Certificate/Incentive', message='A recognition has been approved by Management. Please prepare the certificate or incentive and schedule the announcement.', n_type='info', sender_subsystem='hr1')
            flash('Recognition approved! Featured on Wall of Fame. HR has been notified to prepare the certificate.', 'success')

        elif action == 'reject':
            client.table('recognition_nominations').update({
                'status': 'Management_Rejected',
                'reviewed_at': datetime.utcnow().isoformat(),
                'review_notes': request.form.get('review_notes', '')
            }).eq('id', nom_id).execute()

            from utils.hms_models import Notification
            if nom:
                Notification.create(user_id=nom['nominator_id'], subsystem='hr1', title='Nomination Not Approved by Management', message=f"The Management/Committee did not approve the nomination. Reason: {request.form.get('review_notes', '')}", n_type='warning', sender_subsystem='hr1')
            flash('Nomination rejected by Management.', 'info')

    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('hr1.recognition_inbox'))


@hr1_bp.route('/recognition/types', methods=['GET', 'POST'])
@login_required
def recognition_types_admin():
    if not current_user.is_admin() and not current_user.is_super_admin():
        flash('Admin access required.', 'danger')
        return redirect(url_for('hr1.recognition_wall'))

    client = get_supabase_client()

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            data = {
                'name': request.form.get('name'),
                'description': request.form.get('description'),
                'icon': request.form.get('icon', 'award'),
                'is_active': True
            }
            try:
                client.table('recognition_types').insert(data).execute()
                flash('Recognition type created!', 'success')
            except Exception as e:
                flash(f'Error: {str(e)}', 'danger')
        elif action == 'toggle':
            type_id = request.form.get('type_id')
            is_active = request.form.get('is_active') == 'true'
            client.table('recognition_types').update({'is_active': not is_active}).eq('id', type_id).execute()
            flash('Recognition type updated.', 'success')
        return redirect(url_for('hr1.recognition_types_admin'))

    types = client.table('recognition_types').select('*').order('created_at').execute()
    return render_template('subsystems/hr/hr1/recognition/types_admin.html',
                           recognition_types=types.data or [],
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


# EMPLOYEE PORTAL REDIRECTS (FIX FOR HR1 DASHBOARD DIRECTING TO HR3)
@hr1_bp.route('/request-leave', methods=['GET', 'POST'])
@login_required
def request_leave():
    return redirect(url_for('hr3.request_leave'))


@hr1_bp.route('/my_schedule')
@login_required
def my_schedule():
    return redirect(url_for('hr3.my_schedule'))


@hr1_bp.route('/clock-in', methods=['POST'])
@login_required
def clock_in():
    return redirect(url_for('hr3.clock_in'), code=307)

