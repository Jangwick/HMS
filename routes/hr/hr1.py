from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from datetime import datetime

hr1_bp = Blueprint('hr1', __name__)

# Subsystem configuration
SUBSYSTEM_NAME = 'HR1 - Personnel Management'
ACCENT_COLOR = '#3B82F6'
SUBSYSTEM_ICON = 'person-plus-fill'
BLUEPRINT_NAME = 'hr1'

@hr1_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
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
                        flash('Your account is awaiting approval from HR3 Admin.', 'info')
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
                register_successful_login()
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
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
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
                from utils.supabase_client import get_supabase_client
                sb = get_supabase_client()
                other_user = sb.table('users').select('subsystem').ilike('username', username).execute()
                if other_user.data:
                    sub = other_user.data[0]['subsystem'].upper()
                    flash(f'Account found in {sub} department. Please log in through the correct portal.', 'warning')
                else:
                    flash('Invalid credentials.', 'danger')
            except:
                flash('Invalid credentials.', 'danger')
                
            # Register failed attempt even for non-existent users (prevents user enumeration)
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
            
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

@hr1_bp.route('/register', methods=['GET', 'POST'])
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
                return redirect(url_for('hr1.login'))
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
        'interview': len([a for a in all_applicants if a['status'] == 'Interview']),
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
            'status': 'Open',
            'approved_by': current_user.id
        }
        
        try:
            client.table('vacancies').insert(data).execute()
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
def schedule_interview():
    # ... existing implementation ...
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    if request.method == 'POST':
        applicant_id = request.form.get('applicant_id')
        interview_date = request.form.get('interview_date')
        location = request.form.get('location')
        notes = request.form.get('notes')
        interviewer_id = current_user.id
        
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
            # Update applicant status
            client.table('applicants').update({'status': 'Interview'}).eq('id', applicant_id).execute()
            flash('Interview scheduled successfully!', 'success')
            return redirect(url_for('hr1.list_applicants'))
        except Exception as e:
            flash(f'Error scheduling interview: {str(e)}', 'danger')
            
    # GET: fetch applicants and potential interviewers
    applicants = client.table('applicants').select('*').neq('status', 'Handoff').execute().data
    # For now, interviewers are any HR users
    interviewers = client.table('users').select('id, username').eq('department', 'HR').execute().data
    
    selected_applicant_id = request.args.get('applicant_id')
    
    return render_template('subsystems/hr/hr1/schedule_interview.html',
                           applicants=applicants,
                           interviewers=interviewers,
                           selected_applicant_id=selected_applicant_id,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr1_bp.route('/applicants/<int:id>/status/<string:status>', methods=['POST'])
@login_required
def update_applicant_status_quick(id, status):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr1.list_applicants'))
        
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
        
        flash(f'Success! {applicant["first_name"]} {applicant["last_name"]} has been handed off to HR2 for onboarding.', 'success')
    except Exception as e:
        flash(f'Error during handoff: {str(e)}', 'danger')
        
    return redirect(url_for('hr1.list_applicants'))

@hr1_bp.route('/applicants/<int:id>/schedule', methods=['POST'])
@login_required
def schedule_interview_quick(id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('hr1.list_applicants'))
        
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
