from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user, login_user, logout_user
import os

portal_bp = Blueprint('portal', __name__)

@portal_bp.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'Patient':
            return redirect(url_for('patient.landing'))
        
        from utils.supabase_client import SUBSYSTEM_CONFIG
        subsystem_info = SUBSYSTEM_CONFIG.get(current_user.subsystem, {})
        subsystem_color = subsystem_info.get('color', 'blue')
        return render_template('portal/index.html', subsystem_color=subsystem_color)
    
    return render_template('portal/index.html', subsystem_color='blue')

@portal_bp.route('/erp')
def erp():
    return render_template('portal/index.html', subsystem_color='blue')


@portal_bp.route('/dashboard')
@login_required
def dashboard():
    role_name = (current_user.role or '').strip().lower()
    employee_roles = {
        'doctor',
        'nurse',
        'pharmacist',
        'staff',
        'administrative assistant',
        'warehouse staff',
        'logistics manager',
        'human resources manager'
    }
    if role_name in employee_roles:
        return redirect(url_for('portal.careers_employee_dashboard'))
    return redirect(url_for('portal.index'))


@portal_bp.route('/settings', methods=['GET', 'POST'])
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
        return redirect(url_for('portal.settings'))

    return render_template('shared/settings.html',
                           subsystem_name='Employee Portal',
                           accent_color='#3B82F6',
                           blueprint_name='portal')


@portal_bp.route('/logout')
@login_required
def logout():
    role_name = (current_user.role or '').strip().lower()
    logout_user()
    if role_name in {
        'doctor',
        'nurse',
        'pharmacist',
        'staff',
        'administrative assistant',
        'warehouse staff',
        'logistics manager',
        'human resources manager'
    }:
        return redirect(url_for('portal.careers_employee_login'))
    return redirect(url_for('portal.index'))

@portal_bp.route('/profile')
@login_required
def profile():
    from utils.supabase_client import SUBSYSTEM_CONFIG, get_supabase_client
    client = get_supabase_client()
    
    subsystem_info = SUBSYSTEM_CONFIG.get(current_user.subsystem, {})
    subsystem_name = subsystem_info.get('name', current_user.subsystem.upper())
    subsystem_color = subsystem_info.get('color', 'indigo')
    
    # Fetch career paths for professional development section
    career_resp = client.table('staff_career_paths')\
        .select('*, path:career_paths(*)')\
        .eq('user_id', current_user.id)\
        .order('updated_at', desc=True)\
        .execute()
    
    career_data = career_resp.data if career_resp.data else []
    
    return render_template('portal/profile.html', 
                         user=current_user, 
                         subsystem_full_name=subsystem_name,
                         subsystem_color=subsystem_color,
                         career_paths=career_data)

@portal_bp.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    from utils.supabase_client import get_supabase_client
    from utils.password_validator import PasswordValidationError
    from flask_login import logout_user

    current_password = request.form.get('current_password', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()

    if not current_user.check_password(current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('portal.profile') + '#security')

    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('portal.profile') + '#security')

    try:
        current_user.set_password(new_password)
        flash('Password updated successfully! Please log in again with your new password.', 'success')
        logout_user()
        # Redirect to the subsystem login
        from utils.supabase_client import SUBSYSTEM_CONFIG
        subsystem = current_user.subsystem if current_user.subsystem else 'portal'
        try:
            return redirect(url_for(f'{subsystem}.login'))
        except Exception:
            return redirect(url_for('portal.index'))
    except PasswordValidationError as e:
        for error in e.errors:
            flash(error, 'danger')
    except Exception as e:
        flash('An error occurred while updating password.', 'danger')

    return redirect(url_for('portal.profile') + '#security')


@portal_bp.route('/profile/upload-avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('portal.profile'))
    
    file = request.files['avatar']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('portal.profile'))
    
    if file:
        try:
            from utils.supabase_client import get_supabase_client
            client = get_supabase_client()
            
            # File extension
            ext = os.path.splitext(file.filename)[1].lower()
            if ext not in ['.jpg', '.jpeg', '.png', '.gif']:
                flash('Invalid file type. Please upload an image.', 'danger')
                return redirect(url_for('portal.profile'))

            # Read file content
            file_content = file.read()
            file_path = f"avatars/{current_user.id}_{int(os.path.getmtime(os.path.dirname(__file__)) or 0)}{ext}"
            
            # Upload to Supabase Storage (bucket named 'profiles')
            try:
                bucket_name = 'profiles'
                from utils.supabase_client import get_supabase_service_client
                storage_client = get_supabase_service_client()
                res = storage_client.storage.from_(bucket_name).upload(
                    path=file_path,
                    file=file_content,
                    file_options={"content-type": file.content_type, "x-upsert": "true"}
                )
                
                # Get public URL
                avatar_url = storage_client.storage.from_(bucket_name).get_public_url(file_path)
                
                # Update user in database
                current_user.update(avatar_url=avatar_url)
                
                flash('Profile picture updated successfully!', 'success')
            except Exception as e:
                # If upload fails, it might be because the bucket doesn't exist
                error_msg = str(e)
                if 'Bucket not found' in error_msg:
                    flash('Storage Error: The "profiles" bucket was not found. Please run the Storage Setup section in supabase_setup.sql in your Supabase SQL Editor.', 'danger')
                else:
                    flash(f'Error uploading to storage: {error_msg}', 'danger')
                
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')
            
    return redirect(url_for('portal.profile'))

@portal_bp.route('/hr')
def hr_hub():
    return render_template('departments/hr_hub.html')

@portal_bp.route('/core-transaction')
def ct_hub():
    return render_template('departments/ct_hub.html')

@portal_bp.route('/logistics')
def logistics_hub():
    return render_template('departments/logistics_hub.html')

@portal_bp.route('/notifications/read/<int:n_id>', methods=['POST'])
@login_required
def mark_notification_read(n_id):
    from utils.hms_models import Notification
    Notification.mark_as_read(n_id)
    return {'status': 'success'}

@portal_bp.route('/notifications/read-all', methods=['POST'])
@login_required
def mark_all_notifications_read():
    from utils.hms_models import Notification
    Notification.mark_all_read_for_user(current_user)
    flash('All notifications marked as read', 'success')
    return redirect(request.referrer or url_for('portal.index'))

@portal_bp.route('/notifications/delete/<int:n_id>', methods=['POST'])
@login_required
def delete_notification(n_id):
    from utils.hms_models import Notification
    Notification.delete(n_id)
    return {'status': 'success'}

@portal_bp.route('/notifications/clear-all', methods=['POST'])
@login_required
def clear_all_notifications():
    from utils.hms_models import Notification
    only_read = request.form.get('only_read') == 'true'
    Notification.delete_all_for_user(current_user, only_read=only_read)
    msg = 'Read notifications cleared' if only_read else 'All notifications cleared'
    flash(msg, 'success')
    return redirect(url_for('portal.list_notifications'))

@portal_bp.route('/settings/notifications', methods=['POST'])
@login_required
def update_notification_settings():
    settings = {
        "email_notifications": request.form.get('email_notifications') == 'on',
        "system_updates": request.form.get('system_updates') == 'on',
        "security_alerts": request.form.get('security_alerts') == 'on',
        "activity_logs": request.form.get('activity_logs') == 'on'
    }
    
    if current_user.update(notification_settings=settings):
        flash('Notification preferences updated successfully', 'success')
    else:
        flash('Failed to update settings', 'danger')
        
    return redirect(url_for('portal.profile') + '#notifications')

@portal_bp.route('/notifications')
@login_required
def list_notifications():
    from utils.hms_models import Notification
    from utils.supabase_client import SUBSYSTEM_CONFIG
    
    # Fetch all for the list page (limit=None)
    all_notifs = Notification.get_for_user(current_user, limit=None)
    
    subsystem_info = SUBSYSTEM_CONFIG.get(current_user.subsystem, {})
    subsystem_color = subsystem_info.get('color', 'indigo')
    subsystem_name = subsystem_info.get('name', 'System')
    
    # Map colors to HEX for subsystem_base compatibility
    color_map = {
        'blue': '#3B82F6',
        'emerald': '#10B981',
        'amber': '#F59E0B',
        'purple': '#8B5CF6',
        'indigo': '#4F46E5',
        'rose': '#F43F5E'
    }
    accent_color = color_map.get(subsystem_color, '#4F46E5')

    return render_template('portal/notifications.html', 
                         notifications=all_notifs,
                         subsystem_color=subsystem_color,
                         accent_color=accent_color,
                         subsystem_name=subsystem_name,
                         blueprint_name=current_user.subsystem)

@portal_bp.route('/about')
def about():
    return render_template('portal/about.html')

@portal_bp.route('/financials')
def financials_hub():
    return render_template('departments/financials_hub.html')

@portal_bp.route('/terms')
def terms():
    return render_template('portal/terms.html')

@portal_bp.route('/privacy')
def privacy():
    return render_template('portal/privacy.html')

@portal_bp.route('/support')
def support():
    return render_template('portal/support.html')

@portal_bp.route('/logout-switch')
def logout_switch():
    from flask_login import logout_user
    from flask import request, redirect, url_for
    from utils.hms_models import AuditLog
    if current_user.is_authenticated:
        AuditLog.log(current_user.id, "Logout (Switch)", "PORTAL")
    logout_user()
    target = request.args.get('target', url_for('portal.index'))
    return redirect(target)


@portal_bp.route('/careers')
def careers():
    """Public page listing open vacancies for online application."""
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    vacancies = []
    try:
        resp = client.table('vacancies').select('*').eq('status', 'Open').order('created_at', desc=True).execute()
        vacancies = resp.data or []
    except:
        pass

    return render_template('portal/careers.html', vacancies=vacancies)


@portal_bp.route('/careers/employee-login', methods=['GET', 'POST'])
def careers_employee_login():
    """Employee login entry inside Careers portal."""
    from utils.supabase_client import User

    if current_user.is_authenticated:
        return redirect(url_for('portal.careers_employee_dashboard'))

    allowed_roles = {
        'doctor',
        'nurse',
        'pharmacist',
        'staff',
        'administrative assistant',
        'warehouse staff',
        'logistics manager',
        'human resources manager'
    }

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not username or not password:
            flash('Please enter your username and password.', 'danger')
            return redirect(url_for('portal.careers_employee_login'))

        user = User.get_by_username(username)
        if not user or not user.check_password(password):
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('portal.careers_employee_login'))

        if user.status != 'Active' or not user.is_active:
            flash('Your account is not active yet. Please contact HR.', 'warning')
            return redirect(url_for('portal.careers_employee_login'))

        role_name = (user.role or '').strip().lower()
        if role_name not in allowed_roles:
            flash('Access denied. This portal is for employee roles only.', 'danger')
            return redirect(url_for('portal.careers_employee_login'))

        login_user(user)
        return redirect(url_for('portal.careers_employee_dashboard'))

    return render_template('portal/careers_employee_login.html')


@portal_bp.route('/careers/employee-dashboard')
@login_required
def careers_employee_dashboard():
    """Employee portal dashboard with the same layout as HR1 My Dashboard."""
    from datetime import datetime
    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification

    role_name = (current_user.role or '').strip().lower()
    allowed_roles = {
        'doctor',
        'nurse',
        'pharmacist',
        'staff',
        'administrative assistant',
        'warehouse staff',
        'logistics manager',
        'human resources manager'
    }
    if role_name not in allowed_roles:
        flash('Access denied. This portal is for employee roles only.', 'danger')
        return redirect(url_for('portal.careers_employee_login'))

    client = get_supabase_client()
    user = current_user

    try:
        ann_resp = client.table('announcements').select('*').eq('is_active', True).order('created_at', desc=True).limit(5).execute()
        announcements = ann_resp.data or []
    except Exception:
        announcements = []

    try:
        tasks_resp = client.table('employee_tasks').select('*').eq('user_id', user.id).eq('status', 'Pending').order('due_date').limit(10).execute()
        pending_tasks = tasks_resp.data or []
    except Exception:
        pending_tasks = []

    team_data = None
    if user.role in ['Manager', 'Admin', 'Administrator', 'SuperAdmin', 'HR_Staff']:
        try:
            team_resp = client.table('users').select('id, full_name, username, role, status, last_login').eq('department', user.department).neq('id', user.id).eq('status', 'Active').execute()
            team_data = team_resp.data or []
        except Exception:
            team_data = []

    try:
        prob_resp = client.table('probation_cycles').select('*').eq('employee_id', user.id).eq('status', 'Active').execute()
        my_probation = prob_resp.data[0] if prob_resp.data else None
    except Exception:
        my_probation = None

    try:
        rec_resp = client.table('recognition_nominations').select('*, recognition_types(name, icon)').eq('nominee_id', user.id).eq('status', 'Approved').order('created_at', desc=True).limit(5).execute()
        my_recognitions = rec_resp.data or []
    except Exception:
        my_recognitions = []

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

    try:
        today_str = datetime.now().strftime('%Y-%m-%d')
        today_att_resp = client.table('attendance_logs').select('*').eq('user_id', user.id).gte('clock_in', today_str).order('clock_in', desc=True).limit(1).execute()
        today_attendance = today_att_resp.data[0] if today_att_resp.data else None
        is_clocked_in = today_attendance is not None and today_attendance.get('clock_out') is None
    except Exception:
        today_attendance = None
        is_clocked_in = False

    try:
        day_name = datetime.now().strftime('%A')
        sched_resp = client.table('staff_schedules').select('*').eq('user_id', user.id).eq('is_active', True).or_(f"day_of_week.eq.{day_name},day_of_week.eq.Daily").execute()
        my_schedule = sched_resp.data[0] if sched_resp.data else None
    except Exception:
        my_schedule = None

    try:
        all_sched_resp = client.table('staff_schedules').select('*').eq('user_id', user.id).execute()
        schedules = all_sched_resp.data or []
    except Exception:
        schedules = []

    try:
        my_notifications = Notification.get_for_user(user, limit=10)
    except Exception:
        my_notifications = []

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
                           my_notifications=my_notifications,
                           subsystem_name='Employee Portal',
                           accent_color='#3B82F6',
                           blueprint_name='portal')


@portal_bp.route('/careers/employee-logout', methods=['POST'])
@login_required
def careers_employee_logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('portal.careers_employee_login'))


@portal_bp.route('/apply', methods=['POST'])
def apply():
    """Public job application form submission — data goes to HR1 applicants table."""
    from utils.supabase_client import get_supabase_client
    import os
    from datetime import datetime
    client = get_supabase_client()

    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()
    email = request.form.get('email', '').strip()
    phone = request.form.get('phone', '').strip()
    vacancy_id = request.form.get('vacancy_id')
    cover_letter = request.form.get('cover_letter', '').strip()

    if not first_name or not last_name or not email:
        flash('Please fill in all required fields (First Name, Last Name, Email).', 'danger')
        return redirect(url_for('portal.careers'))

    data = {
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'phone': phone,
        'source': 'Online Portal',
        'status': 'Screening'
    }

    if vacancy_id:
        data['vacancy_id'] = int(vacancy_id)

    # Build documents list
    documents = []

    # Handle resume/CV file upload
    resume_url = None
    if 'resume' in request.files:
        file = request.files['resume']
        if file and file.filename:
            ext = os.path.splitext(file.filename)[1].lower()
            if ext in ['.pdf', '.doc', '.docx']:
                try:
                    file_content = file.read()
                    # Max 5MB
                    if len(file_content) <= 5 * 1024 * 1024:
                        timestamp = int(datetime.now().timestamp())
                        safe_name = f"{first_name}_{last_name}".replace(' ', '_').lower()
                        file_path = f"{safe_name}_{timestamp}{ext}"
                        bucket_name = 'resumes'

                        # Use service client for storage operations (requires elevated privileges)
                        from utils.supabase_client import get_supabase_service_client
                        storage_client = get_supabase_service_client()
                        storage_client.storage.from_(bucket_name).upload(
                            path=file_path,
                            file=file_content,
                            file_options={"content-type": file.content_type, "x-upsert": "true"}
                        )

                        resume_url = storage_client.storage.from_(bucket_name).get_public_url(file_path)
                        documents.append({
                            'type': 'resume',
                            'filename': file.filename,
                            'url': resume_url
                        })
                    else:
                        flash('Resume file is too large. Maximum size is 5MB.', 'warning')
                except Exception as e:
                    # Don't block the application — just warn the applicant and log the real error
                    import traceback
                    print(f"Resume upload error (bucket='resumes'): {e}")
                    traceback.print_exc()
                    flash('Your CV file could not be uploaded (storage error). Your application was still submitted — HR can request your CV directly.', 'warning')

    # Add cover letter to documents
    if cover_letter:
        documents.append({'type': 'cover_letter', 'content': cover_letter})

    if documents:
        data['documents'] = documents

    try:
        client.table('applicants').insert(data).execute()

        # Notify HR1 admins of new online application
        try:
            from utils.hms_models import Notification
            resume_note = " (with resume attached)" if resume_url else ""
            Notification.create(
                subsystem='hr1',
                title="New Online Job Application",
                message=f"{first_name} {last_name} has submitted an online application via the HMS Careers portal{resume_note}.",
                n_type="info",
                sender_subsystem='portal',
                target_url=url_for('hr1.list_applicants', _external=True)
            )
        except:
            pass

        flash('Your application has been submitted successfully! Our HR team will review your application and get back to you.', 'success')
    except Exception as e:
        flash(f'There was an error submitting your application. Please try again later.', 'danger')

    return redirect(url_for('portal.careers'))
