from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from datetime import datetime

hr1_bp = Blueprint('hr1', __name__)

# Subsystem configuration
SUBSYSTEM_NAME = 'HR1 - Personnel Management'
ACCENT_COLOR = '[#6366F1]'
BLUEPRINT_NAME = 'hr1'

@hr1_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/hr/hr1/login.html', remaining_seconds=remaining_seconds)
    
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
                    return render_template('subsystems/hr/hr1/login.html')

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
                    return render_template('subsystems/hr/hr1/login.html')
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/hr/hr1/login.html', remaining_seconds=remaining_seconds)
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
                return render_template('subsystems/hr/hr1/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/hr/hr1/login.html')

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
def dashboard():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    # Fetch some stats for the dashboard
    vacancies_count = client.table('vacancies').select('id', count='exact').eq('status', 'Open').execute().count
    applicants_count = client.table('applicants').select('id', count='exact').execute().count
    
    # Fetch interviews today
    today = datetime.utcnow().strftime('%Y-%m-%d')
    interviews_today = client.table('interviews').select('id', count='exact').gte('interview_date', today).execute().count or 0
    
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    return render_template('subsystems/hr/hr1/dashboard.html', 
                           now=datetime.utcnow,
                           vacancies_count=vacancies_count,
                           applicants_count=applicants_count,
                           interviews_today=interviews_today,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr1_bp.route('/vacancies')
@login_required
def list_vacancies():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    response = client.table('vacancies').select('*').execute()
    vacancies = response.data if response.data else []
    return render_template('subsystems/hr/hr1/vacancies.html', 
                           vacancies=vacancies,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr1_bp.route('/applicants')
@login_required
def list_applicants():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    status_filter = request.args.get('status')
    if status_filter:
        response = client.table('applicants').select('*').eq('status', status_filter).execute()
    else:
        response = client.table('applicants').select('*').execute()
        
    applicants = response.data if response.data else []
    return render_template('subsystems/hr/hr1/applicants.html', 
                           applicants=applicants,
                           status_filter=status_filter,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr1_bp.route('/applicants/add', methods=['GET', 'POST'])
@login_required
def add_applicant():
    if request.method == 'POST':
        from utils.supabase_client import get_supabase_client
        client = get_supabase_client()
        data = {
            'first_name': request.form.get('first_name'),
            'last_name': request.form.get('last_name'),
            'email': request.form.get('email'),
            'phone': request.form.get('phone'),
            'source': request.form.get('source'),
            'status': 'Screening'
        }
        client.table('applicants').insert(data).execute()
        flash('Applicant added successfully!', 'success')
        return redirect(url_for('hr1.list_applicants'))
    return render_template('subsystems/hr/hr1/add_applicant.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr1_bp.route('/vacancies/add', methods=['GET', 'POST'])
@login_required
def add_vacancy():
    if request.method == 'POST':
        from utils.supabase_client import get_supabase_client
        client = get_supabase_client()
        data = {
            'position_name': request.form.get('position_name'),
            'department': request.form.get('department'),
            'reason': request.form.get('reason'),
            'status': 'Open'
        }
        client.table('vacancies').insert(data).execute()
        flash('Vacancy posted successfully!', 'success')
        return redirect(url_for('hr1.list_vacancies'))
    return redirect(url_for('hr1.list_vacancies'))

@hr1_bp.route('/interviews/schedule', methods=['GET', 'POST'])
@login_required
def schedule_interview():
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

@hr1_bp.route('/handoff/hr2', methods=['POST'])
@login_required
def handoff_hr2():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    applicant_id = request.form.get('applicant_id')
    
    try:
        # Update applicant status
        client.table('applicants').update({'status': 'Handoff'}).eq('id', applicant_id).execute()
        
        # Create onboarding record
        onboarding_data = {
            'applicant_id': applicant_id,
            'status': 'Pending'
        }
        client.table('onboarding').insert(onboarding_data).execute()
        
        flash('Applicant successfully handed off to HR2 (Talent Development/Onboarding)!', 'success')
    except Exception as e:
        flash(f'Error during handoff: {str(e)}', 'danger')
        
    return redirect(url_for('hr1.list_applicants'))

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
