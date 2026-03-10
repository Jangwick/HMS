from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_wtf.csrf import generate_csrf
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, SUBSYSTEM_CONFIG, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from datetime import datetime, timedelta

hr3_bp = Blueprint('hr3', __name__)

# Subsystem configuration
SUBSYSTEM_NAME = 'HR3 - Workforce Operations'
ACCENT_COLOR = '#0EA5E9'
SUBSYSTEM_ICON = 'clock-history'
BLUEPRINT_NAME = 'hr3'

@hr3_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked(subsystem=BLUEPRINT_NAME)
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/hr/hr3/login.html', 
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
                    return render_template('subsystems/hr/hr3/login.html',
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           subsystem_icon=SUBSYSTEM_ICON,
                                           blueprint_name=BLUEPRINT_NAME,
                                           hub_route='portal.hr_hub')

                # Check for password expiration - redirect to change password
                if user.password_expires_at and user.password_expires_at < now_utc:
                    session['expired_user_id'] = user.id
                    session['expired_subsystem'] = BLUEPRINT_NAME
                    flash('Your password has expired. Please set a new password to continue.', 'warning')
                    return redirect(url_for('hr3.change_password'))

                # Clear IP lockout attempts on successful login
                register_successful_login(subsystem=BLUEPRINT_NAME)
                user.register_successful_login()
                
                if login_user(user):
                    days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                    if days_left <= 7:
                        flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    return redirect(url_for('hr3.dashboard'))
                else:
                    flash('Login failed. Your account may be deactivated.', 'danger')
                    return render_template('subsystems/hr/hr3/login.html',
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
                    return render_template('subsystems/hr/hr3/login.html', 
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
            
            # Register failed attempt even for non-existent users
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt(subsystem=BLUEPRINT_NAME)
            
            if is_now_locked:
                return render_template('subsystems/hr/hr3/login.html', 
                                       remaining_seconds=remaining_seconds,
                                       subsystem_name=SUBSYSTEM_NAME,
                                       accent_color=ACCENT_COLOR,
                                       subsystem_icon=SUBSYSTEM_ICON,
                                       blueprint_name=BLUEPRINT_NAME,
                                       hub_route='portal.hr_hub')
            
    return render_template('subsystems/hr/hr3/login.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           subsystem_icon=SUBSYSTEM_ICON,
                           blueprint_name=BLUEPRINT_NAME,
                           hub_route='portal.hr_hub')


@hr3_bp.route('/change-password', methods=['GET', 'POST'])
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
            return redirect(url_for('hr3.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('hr3.login'))
    
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
            return redirect(url_for('hr3.login'))
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html',
        subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@hr3_bp.route('/dashboard')
@login_required
@policy_required(BLUEPRINT_NAME)
def dashboard():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Check if user is currently clocked in
    is_clocked_in = False
    current_log = None
    try:
        active_log_resp = client.table('attendance_logs').select('*').eq('user_id', current_user.id).is_('clock_out', 'null').execute()
        if active_log_resp.data:
            is_clocked_in = True
            current_log = active_log_resp.data[0]
    except Exception as e:
        print(f"Error checking clock-in status: {e}")

    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    
    # Get Workforce stats
    try:
        # Get active users count
        all_users = User.get_all()
        active_count = len([u for u in all_users if u.status == 'Active'])
        
        # Today's Attendance (simplified count)
        today = datetime.now().strftime('%Y-%m-%d')
        # Filter for entries starting with today's date in clock_in
        attendance_resp = client.table('attendance_logs').select('id', count='exact').gte('clock_in', today).execute()
        today_attendance = attendance_resp.count if attendance_resp.count is not None else 0
        
        # Pending Leave Requests
        leave_resp = client.table('leave_requests').select('id', count='exact').eq('status', 'Pending').execute()
        pending_leaves = leave_resp.count if leave_resp.count is not None else 0
        
        # Recent activity - Mix of new users and leave requests with avatars
        recent_leaves = client.table('leave_requests').select('*, users:users!leave_requests_user_id_fkey(username, avatar_url)').order('created_at', desc=True).limit(3).execute().data or []
        
        # Get Current user's schedule for today
        day_name = datetime.now().strftime('%A')
        user_schedule = client.table('staff_schedules')\
            .select('*')\
            .eq('user_id', current_user.id)\
            .eq('is_active', True)\
            .or_(f"day_of_week.eq.{day_name},day_of_week.eq.Daily")\
            .execute().data
        
    except Exception as e:
        print(f"Error fetching HR3 stats: {e}")
        active_count = 0
        today_attendance = 0
        pending_leaves = 0
        recent_leaves = []
        user_schedule = []
    
    return render_template('subsystems/hr/hr3/dashboard.html', 
                          now=datetime.utcnow, 
                          active_count=active_count,
                          today_attendance=today_attendance,
                          pending_leaves=pending_leaves,
                          recent_leaves=recent_leaves,
                          user_schedule=user_schedule[0] if user_schedule else None,
                          is_clocked_in=is_clocked_in,
                          current_log=current_log,
                          subsystem_name=SUBSYSTEM_NAME,
                          accent_color=ACCENT_COLOR,
                          blueprint_name=BLUEPRINT_NAME)

def hr3_redirect_fallback(next_page=None):
    """Smart fallback redirect for HR3 routes."""
    target = next_page or request.form.get('next') or request.args.get('next') or request.referrer
    
    # Avoid redirect loops or invalid referrers
    if not target or any(p in target for p in ['/clock-in', '/clock-out', '/login']):
        if current_user.is_authenticated and current_user.subsystem and current_user.subsystem != 'hr3':
            try: return redirect(url_for(f'{current_user.subsystem}.dashboard'))
            except: pass
        return redirect(url_for('hr3.dashboard'))
    
    return redirect(target)

# Attendance & Leave for Current User
@hr3_bp.route('/attendance/clock-in', methods=['POST'])
@login_required
def clock_in():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Check if already clocked in
    active_log = client.table('attendance_logs').select('*').eq('user_id', current_user.id).is_('clock_out', 'null').execute()
    if active_log.data:
        flash('You are already clocked in.', 'warning')
        return hr3_redirect_fallback()
    
    now = datetime.now()
    day_name = now.strftime('%A')
    
    # Default status
    status = 'On-time'
    remarks = request.form.get('remarks') or ""
    
    # Check for assigned schedule
    try:
        schedule_resp = client.table('staff_schedules')\
            .select('*')\
            .eq('user_id', current_user.id)\
            .eq('is_active', True)\
            .execute()
        
        if schedule_resp.data:
            # Find schedule for today or 'Daily'
            schedule = next((s for s in schedule_resp.data if s['day_of_week'] == day_name or s['day_of_week'] == 'Daily'), None)
            
            if schedule:
                start_time_str = schedule['start_time']
                schedule_start = datetime.strptime(f"{now.strftime('%Y-%m-%d')} {start_time_str}", "%Y-%m-%d %H:%M:%S")
                
                if now > (schedule_start + timedelta(minutes=5)):
                    status = 'Late'
                    # Calculate minutes late
                    diff = now - schedule_start
                    minutes_late = int(diff.total_seconds() / 60)
                    remarks = f"Late by {minutes_late} minutes. " + (request.form.get('remarks') or "")
            else:
                if now.hour >= 9 and now.minute > 5:
                    status = 'Late'
                    schedule_start = datetime.strptime(f"{now.strftime('%Y-%m-%d')} 09:00:00", "%Y-%m-%d %H:%M:%S")
                    diff = now - schedule_start
                    minutes_late = int(diff.total_seconds() / 60)
                    remarks = f"Late by {minutes_late} minutes (Default). " + (request.form.get('remarks') or "")
        else:
            if now.hour >= 9 and now.minute > 5:
                status = 'Late'
                schedule_start = datetime.strptime(f"{now.strftime('%Y-%m-%d')} 09:00:00", "%Y-%m-%d %H:%M:%S")
                diff = now - schedule_start
                minutes_late = int(diff.total_seconds() / 60)
                remarks = f"Late by {minutes_late} minutes (Default). " + (request.form.get('remarks') or "")
    except Exception as e:
        print(f"Schedule check error: {e}")
        if now.hour >= 9 and now.minute > 5:
            status = 'Late'
            remarks = "Late (Default check error). " + (request.form.get('remarks') or "")
        
    try:
        data = {
            'user_id': current_user.id,
            'clock_in': now.isoformat(),
            'status': status,
            'remarks': remarks
        }
        client.table('attendance_logs').insert(data).execute()
        flash(f'Clocked in successfully at {now.strftime("%H:%M")}. Status: {status}', 'success')
    except Exception as e:
        flash(f'Error during clock-in: {str(e)}', 'danger')
    
    return hr3_redirect_fallback()

@hr3_bp.route('/attendance/clock-out', methods=['POST'])
@login_required
def clock_out():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    active_log = client.table('attendance_logs').select('*').eq('user_id', current_user.id).is_('clock_out', 'null').execute()
    if not active_log.data:
        flash('No active clock-in found.', 'warning')
        return hr3_redirect_fallback()
    
    try:
        now = datetime.now()
        log_id = active_log.data[0]['id']
        overtime_hours = 0.0

        # Compute overtime vs scheduled end time
        try:
            day_name = now.strftime('%A')
            sched_resp = client.table('staff_schedules')\
                .select('end_time')\
                .eq('user_id', current_user.id)\
                .eq('is_active', True)\
                .execute()
            if sched_resp.data:
                sched = next((s for s in sched_resp.data if s.get('day_of_week') in (day_name, 'Daily')), None)
                if sched and sched.get('end_time'):
                    end_str = sched['end_time']  # e.g. "17:00:00"
                    sched_end = datetime.strptime(f"{now.strftime('%Y-%m-%d')} {end_str}", "%Y-%m-%d %H:%M:%S")
                    if now > sched_end + timedelta(minutes=30):
                        diff = now - sched_end
                        overtime_hours = round(diff.total_seconds() / 3600, 2)
        except Exception as oe:
            print(f"OT calculation error: {oe}")

        update_data = {'clock_out': now.isoformat(), 'overtime_hours': overtime_hours}
        client.table('attendance_logs').update(update_data).eq('id', log_id).execute()
        
        ot_msg = f" Overtime: {overtime_hours}h recorded." if overtime_hours > 0 else ""
        flash(f'Clocked out at {now.strftime("%H:%M")}.{ot_msg}', 'success')
    except Exception as e:
        flash(f'Error during clock-out: {str(e)}', 'danger')
        
    return hr3_redirect_fallback()

@hr3_bp.route('/attendance/force-clock-out/<int:log_id>', methods=['POST'])
@login_required
def force_clock_out(log_id):
    if not current_user.is_super_admin() and (not current_user.is_admin() or current_user.subsystem != 'hr3'):
        flash('Unauthorized: Administrative access required.', 'danger')
        return hr3_redirect_fallback()

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Verify log exists and is active
        log_resp = client.table('attendance_logs').select('*').eq('id', log_id).execute()
        if not log_resp.data:
            flash('Log entry not found.', 'danger')
            return hr3_redirect_fallback()
        
        if log_resp.data[0]['clock_out'] is not None:
            flash('This personnel is already clocked out.', 'info')
            return hr3_redirect_fallback()

        client.table('attendance_logs').update({
            'clock_out': datetime.now().isoformat(),
            'remarks': (log_resp.data[0].get('remarks', '') or '') + " [Admin Force Clock-out]"
        }).eq('id', log_id).execute()
        
        flash(f"Forcefully clocked out personnel for log #{log_id}.", 'success')
    except Exception as e:
        flash(f'Error during force clock-out: {str(e)}', 'danger')
        
    return hr3_redirect_fallback()


@hr3_bp.route('/attendance/mark-absent', methods=['POST'])
@login_required
def mark_absent():
    """Admin: auto-mark employees with a schedule today who never clocked in as Absent."""
    if not current_user.is_super_admin() and (not current_user.is_admin() or current_user.subsystem != 'hr3'):
        flash('Unauthorized.', 'danger')
        return redirect(url_for('hr3.list_attendance'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    marked = 0
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        day_name = datetime.now().strftime('%A')

        sched_resp = client.table('staff_schedules')\
            .select('user_id, end_time')\
            .eq('is_active', True)\
            .execute()
        scheduled_ids = {
            s['user_id']: s['end_time']
            for s in (sched_resp.data or [])
            if s.get('day_of_week') in (day_name, 'Daily')
        }

        clocked_resp = client.table('attendance_logs').select('user_id').gte('clock_in', today).execute()
        clocked_ids = {r['user_id'] for r in (clocked_resp.data or [])}

        now = datetime.now()
        for uid, end_time_str in scheduled_ids.items():
            if uid in clocked_ids:
                continue
            # Only mark absent after scheduled end time
            try:
                sched_end = datetime.strptime(f"{today} {end_time_str}", "%Y-%m-%d %H:%M:%S")
            except Exception:
                sched_end = datetime.strptime(f"{today} 18:00:00", "%Y-%m-%d %H:%M:%S")
            if now >= sched_end:
                client.table('attendance_logs').insert({
                    'user_id': uid,
                    'clock_in': f"{today}T00:00:00",
                    'status': 'Absent',
                    'remarks': 'Auto-marked absent — no clock-in recorded for scheduled shift.'
                }).execute()
                marked += 1

        flash(f'{marked} employee(s) marked as Absent.', 'success' if marked else 'info')
    except Exception as e:
        flash(f'Error marking absent: {str(e)}', 'danger')

    return redirect(url_for('hr3.list_attendance'))

def _notify_hr3_admins(client, title, message, n_type, sender_subsystem, target_url=None):
    """Notify all active HR3 admins."""
    from utils.hms_models import Notification
    try:
        admins = client.table('users').select('id').eq('subsystem', 'hr3').in_('role', ['Admin', 'Administrator']).eq('status', 'Active').execute()
        for a in (admins.data or []):
            Notification.create(
                user_id=a['id'],
                title=title,
                message=message,
                n_type=n_type,
                sender_subsystem=sender_subsystem,
                target_url=target_url
            )
    except Exception as e:
        print(f"HR3 notification error: {e}")


@hr3_bp.route('/leaves/request', methods=['GET', 'POST'])
@login_required
def request_leave():
    if request.method == 'POST':
        leave_type = request.form.get('leave_type')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        remarks = (request.form.get('remarks') or '').strip()
        doc_file = request.files.get('document')

        # ── 1. Completeness validation ────────────────────────────────────
        errors = []
        if not leave_type:
            errors.append('Leave type is required.')
        if not start_date:
            errors.append('Start date is required.')
        if not end_date:
            errors.append('End date is required.')
        if start_date and end_date and end_date < start_date:
            errors.append('End date cannot be before start date.')
        if not remarks or len(remarks) < 10:
            errors.append('Please provide a reason of at least 10 characters.')
        if errors:
            for err in errors:
                flash(err, 'danger')
            return render_template('subsystems/hr/hr3/leave_request_form.html',
                                   subsystem_name=SUBSYSTEM_NAME,
                                   accent_color=ACCENT_COLOR,
                                   blueprint_name=BLUEPRINT_NAME,
                                   form_data=request.form)

        from utils.supabase_client import get_supabase_client, get_supabase_service_client
        client = get_supabase_client()

        # ── 2. Document upload (optional) ─────────────────────────────────
        document_url = None
        if doc_file and doc_file.filename:
            ALLOWED_EXT = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'}
            ext = doc_file.filename.rsplit('.', 1)[-1].lower() if '.' in doc_file.filename else ''
            if ext not in ALLOWED_EXT:
                flash(f'Unsupported file type ({ext}). Allowed: {", ".join(sorted(ALLOWED_EXT))}', 'warning')
            else:
                try:
                    import traceback
                    svc = get_supabase_service_client()
                    file_bytes = doc_file.read()
                    safe_name = f"leave_{current_user.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{ext}"
                    svc.storage.from_('ess-documents').upload(safe_name, file_bytes,
                        {'content-type': doc_file.content_type or 'application/octet-stream'})
                    document_url = svc.storage.from_('ess-documents').get_public_url(safe_name)
                except Exception as e:
                    import traceback; traceback.print_exc()
                    flash(f'Document upload failed (request still submitted): {e}', 'warning')

        # ── 3. Automated routing: find HR3 supervisor ─────────────────────
        supervisor_id = None
        supervisor_data = []
        try:
            sup_resp = client.table('users').select('id, full_name, username') \
                .eq('subsystem', 'hr3').in_('role', ['Admin', 'Administrator']).eq('status', 'Active').execute()
            supervisor_data = sup_resp.data or []
            if supervisor_data:
                supervisor_id = supervisor_data[0]['id']
        except Exception as e:
            print(f"Auto-routing error: {e}")

        # ── 4. Save leave request ──────────────────────────────────────────
        try:
            data = {
                'user_id': current_user.id,
                'leave_type': leave_type,
                'start_date': start_date,
                'end_date': end_date,
                'status': 'Pending',
                'remarks': remarks,
                'document_url': document_url,
                'workflow_step': 'Supervisor Review',
                'supervisor_id': supervisor_id,
            }
            result = client.table('leave_requests').insert(data).execute()
            leave_id = result.data[0]['id'] if result.data else None

            # ── 5. Notify supervisor(s) ────────────────────────────────────
            from utils.hms_models import Notification
            target_url = url_for('hr3.leave_detail', leave_id=leave_id) if leave_id else url_for('hr3.list_leaves')
            for sup in supervisor_data:
                Notification.create(
                    user_id=sup['id'],
                    title="Leave Request — Supervisor Review Required",
                    message=f"{current_user.full_name or current_user.username} submitted a {leave_type} leave "
                            f"request ({start_date} → {end_date}). Please review and decide.",
                    n_type="info",
                    sender_subsystem=current_user.subsystem or 'hr3',
                    target_url=target_url
                )

            flash('Leave request submitted! It has been routed to your supervisor for review.', 'success')
            return redirect(target_url)
        except Exception as e:
            flash(f'Error submitting leave request: {str(e)}', 'danger')

    return render_template('subsystems/hr/hr3/leave_request_form.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME,
                           form_data={})

@hr3_bp.route('/directory')
@login_required
def directory():
    """All-staff directory for HR3 users."""
    users = User.get_all()
    # Filter out sensitive or rejected users if needed
    active_users = [u for u in users if u.status == 'Active']
    
    return render_template('subsystems/hr/hr3/directory.html',
                           users=active_users,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@hr3_bp.route('/my-schedule')
@login_required
def my_schedule():
    """View personal schedule for the current user."""
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        schedules_resp = client.table('staff_schedules').select('*').eq('user_id', current_user.id).execute()
        schedules = schedules_resp.data or []
    except Exception as e:
        flash(f'Error fetching schedule: {str(e)}', 'danger')
        schedules = []
        
    return render_template('subsystems/hr/hr3/my_schedule.html',
                           schedules=schedules,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

# Admin: Analytics & Settings
@hr3_bp.route('/analytics')
@login_required
def analytics():
    if not current_user.is_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # 1. Attendance Analytics
    try:
        attendance_data = client.table('attendance_logs').select('*').execute().data or []
    except:
        attendance_data = []
        
    # 2. Leave Analytics
    try:
        leave_data = client.table('leave_requests').select('*').execute().data or []
    except:
        leave_data = []

    # 3. User distribution
    all_users = User.get_all()
    
    # Process attendance stats
    attendance_stats = {
        'On-time': 0,
        'Late': 0,
        'Absent': 0
    }
    for entry in attendance_data:
        status = entry.get('status')
        if status in attendance_stats:
            attendance_stats[status] += 1
            
    # Process leave stats
    leave_stats = {
        'Pending': 0,
        'Approved': 0,
        'Rejected': 0
    }
    leave_types = {}
    for entry in leave_data:
        status = entry.get('status')
        if status in leave_stats:
            leave_stats[status] += 1
        
        ltype = entry.get('leave_type')
        if ltype:
            leave_types[ltype] = leave_types.get(ltype, 0) + 1

    # Subsystem distribution
    subsystem_dist = {}
    for u in all_users:
        sub = u.subsystem.upper()
        subsystem_dist[sub] = subsystem_dist.get(sub, 0) + 1

    # Today's late logs
    today_str = datetime.now().strftime('%Y-%m-%d')
    late_today = []
    try:
        late_resp = client.table('attendance_logs').select('*, users(username)').gte('clock_in', today_str).eq('status', 'Late').execute()
        late_today = late_resp.data or []
    except Exception as e:
        print(f"Error fetching late logs: {e}")

    return render_template('subsystems/hr/hr3/analytics.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME,
                           attendance_stats=attendance_stats,
                           leave_stats=leave_stats,
                           leave_types=leave_types,
                           subsystem_dist=subsystem_dist,
                           late_today=late_today,
                           total_users=len(all_users),
                           datetime=datetime)

@hr3_bp.route('/settings', methods=['GET', 'POST'])
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

@hr3_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hr3.login'))

@hr3_bp.route('/attendance')
@login_required
def list_attendance():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Use context from query param if provided, otherwise default to blueprint name
    context = request.args.get('context', BLUEPRINT_NAME)
    
    # Context-aware UI configuration
    CONTEXT_CONFIGS = {
        'hr1': {'name': 'HR1 - Personnel', 'color': '#3B82F6', 'icon': 'person-plus-fill'},
        'hr2': {'name': 'HR2 - Development', 'color': '#0891B2', 'icon': 'award-fill'},
        'hr3': {'name': 'HR3 - Operations', 'color': '#0EA5E9', 'icon': 'clock-history'},
        'hr4': {'name': 'HR4 - Compensation', 'color': '#6366F1', 'icon': 'wallet2'},
        'ct1': {'name': 'CT1 - Patient Access', 'color': '#10B981', 'icon': 'person-badge'},
        'ct2': {'name': 'CT2 - Clinical Ops', 'color': '#10B981', 'icon': 'clipboard-pulse'},
        'ct3': {'name': 'CT3 - Admin & Finance', 'color': '#059669', 'icon': 'hospital'},
        'log1': {'name': 'LOG1 - Inventory', 'color': '#F59E0B', 'icon': 'box-seam'},
        'log2': {'name': 'LOG2 - Fleet Ops', 'color': '#F97316', 'icon': 'truck'},
        'financials': {'name': 'Financial Management', 'color': '#8B5CF6', 'icon': 'bank'}
    }
    
    current_config = CONTEXT_CONFIGS.get(context, {'name': SUBSYSTEM_NAME, 'color': ACCENT_COLOR, 'icon': SUBSYSTEM_ICON})
    display_name = current_config['name']
    display_color = current_config['color']
    display_icon = current_config['icon']
    
    query = client.table('attendance_logs').select('*, users(username, avatar_url, full_name)')
    
    # Non-admins only see their own logs
    if not current_user.is_super_admin() and (current_user.role not in ['Admin', 'Administrator'] or current_user.subsystem != 'hr3'):
        query = query.eq('user_id', current_user.id)
        
    response = query.order('clock_in', desc=True).execute()
    logs = response.data if response.data else []
    
    # If admin, also find who hasn't clocked in today
    missing_staff = []
    users_list = []
    sched_map = {}
    if current_user.is_super_admin() or (current_user.is_admin() and current_user.subsystem == 'hr3'):
        try:
            today = datetime.now().strftime('%Y-%m-%d')
            day_name = datetime.now().strftime('%A')
            
            # Get everyone's schedules for today (for missing staff alert)
            sched_today_query = client.table('staff_schedules')\
                .select('*, users(username, avatar_url, full_name)')\
                .eq('is_active', True)\
                .or_(f"day_of_week.eq.{day_name},day_of_week.eq.Daily")\
                .execute()
            
            # Get everyone who DID clock in today
            clocked_in_today = client.table('attendance_logs').select('user_id').gte('clock_in', today).execute()
            clocked_in_ids = [log['user_id'] for log in clocked_in_today.data]
            
            for s in (sched_today_query.data or []):
                if s['user_id'] not in clocked_in_ids:
                    missing_staff.append({
                        'full_name': s['users'].get('full_name') or s['users'].get('username'),
                        'username': s['users'].get('username'),
                        'avatar_url': s['users'].get('avatar_url'),
                        'start_time': s['start_time']
                    })

            # ALSO FETCH DATA FOR SCHEDULING TAB
            users_list = User.get_all()
            all_schedules = client.table('staff_schedules').select('*').execute()
            for s in (all_schedules.data or []):
                u_id = s['user_id']
                if u_id not in sched_map:
                    sched_map[u_id] = []
                sched_map[u_id].append(s)

        except Exception as e:
            print(f"Error fetching monitoring data: {e}")
            
    return render_template('subsystems/hr/hr3/attendance.html',
                           logs=logs,
                           missing_staff=missing_staff,
                           users=users_list,
                           schedules=sched_map,
                           subsystem_name=display_name,
                           accent_color=display_color,
                           subsystem_icon=display_icon,
                           blueprint_name=context)

@hr3_bp.route('/schedules', methods=['GET', 'POST'])
@login_required
@policy_required('hr3')
def manage_schedules():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        day_of_week = request.form.get('day_of_week', 'Daily')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')
        is_active = request.form.get('is_active') == 'on'
        
        try:
            # Check if exists
            exists = client.table('staff_schedules')\
                .select('*')\
                .eq('user_id', user_id)\
                .eq('day_of_week', day_of_week)\
                .execute()
            
            data = {
                'user_id': user_id,
                'day_of_week': day_of_week,
                'start_time': start_time,
                'end_time': end_time,
                'is_active': is_active
            }
            
            if exists.data:
                client.table('staff_schedules').update(data).eq('id', exists.data[0]['id']).execute()
            else:
                client.table('staff_schedules').insert(data).execute()
                
            flash('Schedule updated successfully.', 'success')
        except Exception as e:
            flash(f'Error updating schedule: {str(e)}', 'danger')
        return redirect(url_for('hr3.manage_schedules'))

    # Fetch all users and their schedules
    try:
        users_list = User.get_all()
        schedules_resp = client.table('staff_schedules').select('*').execute()
        
        # Organize schedules into a dict for easy lookup
        sched_map = {}
        for s in (schedules_resp.data or []):
            u_id = s['user_id']
            if u_id not in sched_map:
                sched_map[u_id] = []
            sched_map[u_id].append(s)
            
        return render_template('subsystems/hr/hr3/schedules.html', 
                             users=users_list, 
                             schedules=sched_map,
                             subsystem_name=SUBSYSTEM_NAME,
                             accent_color=ACCENT_COLOR,
                             blueprint_name=BLUEPRINT_NAME)
    except Exception as e:
        flash(f'Error fetching data: {str(e)}', 'danger')
        return redirect(url_for('hr3.dashboard'))

@hr3_bp.route('/schedules/delete/<int:schedule_id>', methods=['POST'])
@login_required
@policy_required('hr3')
def delete_schedule(schedule_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        client.table('staff_schedules').delete().eq('id', schedule_id).execute()
        flash('Schedule removed successfully.', 'success')
    except Exception as e:
        flash(f'Error removing schedule: {str(e)}', 'danger')
    return redirect(url_for('hr3.manage_schedules'))

@hr3_bp.route('/leaves')
@login_required
def list_leaves():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    filter_step = request.args.get('step', 'all')
    show_archived = request.args.get('archived', '0') == '1'

    query = client.table('leave_requests').select(
        '*, users:users!leave_requests_user_id_fkey(username, full_name, avatar_url)'
    )

    # Non-admins only see their own requests
    is_admin = current_user.is_super_admin() or (
        current_user.role in ['Admin', 'Administrator'] and current_user.subsystem == 'hr3'
    )
    if not is_admin:
        query = query.eq('user_id', current_user.id)

    if not show_archived:
        query = query.eq('is_archived', False)

    if filter_step != 'all' and filter_step in ('Supervisor Review', 'HR Validation', 'Final Approval', 'Approved', 'Rejected'):
        query = query.eq('workflow_step', filter_step)

    response = query.order('created_at', desc=True).execute()
    leaves = response.data if response.data else []

    # Count per step for tab badges
    counts = {'all': 0, 'Supervisor Review': 0, 'HR Validation': 0, 'Final Approval': 0, 'Approved': 0, 'Rejected': 0}
    all_resp_q = client.table('leave_requests').select('workflow_step')
    if not is_admin:
        all_resp_q = all_resp_q.eq('user_id', current_user.id)
    all_resp_q = all_resp_q.eq('is_archived', False)
    try:
        all_steps = all_resp_q.execute().data or []
        for row in all_steps:
            s = row.get('workflow_step', '')
            counts['all'] += 1
            if s in counts:
                counts[s] += 1
    except Exception:
        pass

    return render_template('subsystems/hr/hr3/leaves.html',
                           leaves=leaves,
                           is_admin=is_admin,
                           filter_step=filter_step,
                           show_archived=show_archived,
                           counts=counts,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr3_bp.route('/leaves/<int:leave_id>')
@login_required
def leave_detail(leave_id):
    """Full ESS workflow detail view for a single leave request."""
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        resp = client.table('leave_requests').select('*').eq('id', leave_id).limit(1).execute()
        if not resp.data:
            flash('Leave request not found.', 'danger')
            return redirect(url_for('hr3.list_leaves'))
        leave = resp.data[0]
    except Exception as e:
        flash(f'Error loading leave request: {e}', 'danger')
        return redirect(url_for('hr3.list_leaves'))

    is_admin = current_user.is_super_admin() or (
        current_user.role in ['Admin', 'Administrator'] and current_user.subsystem == 'hr3'
    )
    if not is_admin and leave.get('user_id') != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.list_leaves'))

    # Resolve related user names separately (avoids FK-name guessing)
    def _get_user(uid):
        if not uid:
            return None
        try:
            r = client.table('users').select('id, username, full_name, avatar_url').eq('id', uid).limit(1).execute()
            return r.data[0] if r.data else None
        except Exception:
            return None

    leave['employee'] = _get_user(leave.get('user_id'))
    leave['supervisor_user'] = _get_user(leave.get('supervisor_id'))
    leave['hr_validator_user'] = _get_user(leave.get('hr_validated_by'))
    leave['final_approver_user'] = _get_user(leave.get('final_decided_by'))
    leave['approved_by_user'] = _get_user(leave.get('approved_by'))

    WORKFLOW_STEPS_LIST = ['Supervisor Review', 'HR Validation', 'Final Approval', 'Approved']

    return render_template('subsystems/hr/hr3/leave_detail.html',
                           leave=leave,
                           is_admin=is_admin,
                           workflow_steps=WORKFLOW_STEPS_LIST,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr3_bp.route('/leaves/<int:leave_id>/supervisor-action', methods=['POST'])
@login_required
def supervisor_action(leave_id):
    """Step 1 — Supervisor approves or rejects the leave request."""
    is_admin = current_user.is_super_admin() or (
        current_user.role in ['Admin', 'Administrator'] and current_user.subsystem == 'hr3'
    )
    if not is_admin:
        flash('Unauthorized: Supervisor access required.', 'danger')
        return redirect(url_for('hr3.leave_detail', leave_id=leave_id))

    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()

    decision = request.form.get('decision')
    notes = (request.form.get('notes') or '').strip()

    try:
        leave_resp = client.table('leave_requests').select('*').eq('id', leave_id).limit(1).execute()
        if not leave_resp.data:
            flash('Leave request not found.', 'danger')
            return redirect(url_for('hr3.list_leaves'))
        leave = leave_resp.data[0]
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('hr3.list_leaves'))

    if leave.get('workflow_step') != 'Supervisor Review':
        flash('This request is not awaiting supervisor review.', 'warning')
        return redirect(url_for('hr3.leave_detail', leave_id=leave_id))

    now_iso = datetime.now().isoformat()
    detail_url = url_for('hr3.leave_detail', leave_id=leave_id)

    def _get_user(uid):
        if not uid: return None
        try:
            r = client.table('users').select('id, username, full_name').eq('id', uid).limit(1).execute()
            return r.data[0] if r.data else None
        except Exception: return None

    employee = _get_user(leave.get('user_id'))
    emp_name = (employee.get('full_name') or employee.get('username') or 'Employee') if employee else 'Employee'
    emp_id = leave.get('user_id')

    if decision == 'Approve':
        client.table('leave_requests').update({
            'supervisor_decision': 'Approved',
            'supervisor_notes': notes,
            'supervisor_decided_at': now_iso,
            'workflow_step': 'HR Validation',
        }).eq('id', leave_id).execute()

        _notify_hr3_admins(client,
            title="Leave Request — HR/Payroll Validation Required",
            message=f"Supervisor approved {emp_name}'s {leave['leave_type']} leave "
                    f"({leave['start_date']} → {leave['end_date']}). HR validation is required.",
            n_type="info", sender_subsystem='hr3', target_url=detail_url
        )
        flash('Approved at supervisor stage. Routed to HR for validation.', 'success')

    elif decision == 'Reject':
        client.table('leave_requests').update({
            'supervisor_decision': 'Rejected',
            'supervisor_notes': notes,
            'supervisor_decided_at': now_iso,
            'workflow_step': 'Rejected',
            'status': 'Rejected',
        }).eq('id', leave_id).execute()

        if emp_id:
            Notification.create(
                user_id=emp_id,
                title="Leave Request Rejected — Supervisor",
                message=f"Your {leave['leave_type']} leave ({leave['start_date']} → {leave['end_date']}) "
                        f"was rejected by your supervisor.{(' Reason: ' + notes) if notes else ''}",
                n_type="danger", sender_subsystem='hr3', target_url=detail_url
            )
        flash('Leave request rejected. Employee has been notified.', 'info')

    return redirect(detail_url)


@hr3_bp.route('/leaves/<int:leave_id>/hr-validate', methods=['POST'])
@login_required
def hr_validate(leave_id):
    """Step 2 — HR/Payroll validates policy compliance and leave balance."""
    is_admin = current_user.is_super_admin() or (
        current_user.role in ['Admin', 'Administrator'] and current_user.subsystem == 'hr3'
    )
    if not is_admin:
        flash('Unauthorized: HR access required.', 'danger')
        return redirect(url_for('hr3.leave_detail', leave_id=leave_id))

    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()

    decision = request.form.get('decision')
    notes = (request.form.get('notes') or '').strip()

    try:
        leave_resp = client.table('leave_requests').select('*').eq('id', leave_id).limit(1).execute()
        if not leave_resp.data:
            flash('Leave request not found.', 'danger')
            return redirect(url_for('hr3.list_leaves'))
        leave = leave_resp.data[0]
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('hr3.list_leaves'))

    if leave.get('workflow_step') != 'HR Validation':
        flash('This request is not awaiting HR validation.', 'warning')
        return redirect(url_for('hr3.leave_detail', leave_id=leave_id))

    now_iso = datetime.now().isoformat()
    detail_url = url_for('hr3.leave_detail', leave_id=leave_id)
    emp_id = leave.get('user_id')

    def _get_user(uid):
        if not uid: return None
        try:
            r = client.table('users').select('id, username, full_name').eq('id', uid).limit(1).execute()
            return r.data[0] if r.data else None
        except Exception: return None

    employee = _get_user(emp_id)
    emp_name = (employee.get('full_name') or employee.get('username') or 'Employee') if employee else 'Employee'

    if decision == 'Validate':
        client.table('leave_requests').update({
            'hr_validated': True,
            'hr_validated_by': current_user.id,
            'hr_validated_at': now_iso,
            'hr_notes': notes,
            'workflow_step': 'Final Approval',
        }).eq('id', leave_id).execute()

        _notify_hr3_admins(client,
            title="Leave Request — Final Approval Required",
            message=f"HR validated {emp_name}'s {leave['leave_type']} leave "
                    f"({leave['start_date']} → {leave['end_date']}). Final approval decision required.",
            n_type="warning", sender_subsystem='hr3', target_url=detail_url
        )
        flash('HR validation complete. Forwarded for final approval.', 'success')

    elif decision == 'Reject':
        client.table('leave_requests').update({
            'hr_validated': False,
            'hr_validated_by': current_user.id,
            'hr_validated_at': now_iso,
            'hr_notes': notes,
            'workflow_step': 'Rejected',
            'status': 'Rejected',
        }).eq('id', leave_id).execute()

        if emp_id:
            Notification.create(
                user_id=emp_id,
                title="Leave Request Rejected — HR/Payroll",
                message=f"Your {leave['leave_type']} leave ({leave['start_date']} → {leave['end_date']}) "
                        f"did not pass HR/Payroll validation.{(' Reason: ' + notes) if notes else ''}",
                n_type="danger", sender_subsystem='hr3', target_url=detail_url
            )
        flash('Rejected at HR validation. Employee notified.', 'info')

    return redirect(detail_url)


@hr3_bp.route('/leaves/<int:leave_id>/final-decision', methods=['POST'])
@login_required
def final_decision_leave(leave_id):
    """Step 3 — Final approval decision; updates HR records and notifies employee."""
    is_admin = current_user.is_super_admin() or (
        current_user.role in ['Admin', 'Administrator'] and current_user.subsystem == 'hr3'
    )
    if not is_admin:
        flash('Unauthorized.', 'danger')
        return redirect(url_for('hr3.leave_detail', leave_id=leave_id))

    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()

    decision = request.form.get('decision')
    notes = (request.form.get('notes') or '').strip()

    try:
        leave_resp = client.table('leave_requests').select('*').eq('id', leave_id).limit(1).execute()
        if not leave_resp.data:
            flash('Leave request not found.', 'danger')
            return redirect(url_for('hr3.list_leaves'))
        leave = leave_resp.data[0]
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('hr3.list_leaves'))

    if leave.get('workflow_step') != 'Final Approval':
        flash('This request is not awaiting final approval.', 'warning')
        return redirect(url_for('hr3.leave_detail', leave_id=leave_id))

    now_iso = datetime.now().isoformat()
    detail_url = url_for('hr3.leave_detail', leave_id=leave_id)
    emp_id = leave.get('user_id')

    def _get_user(uid):
        if not uid: return None
        try:
            r = client.table('users').select('id, username, full_name').eq('id', uid).limit(1).execute()
            return r.data[0] if r.data else None
        except Exception: return None

    employee = _get_user(emp_id)
    emp_name = (employee.get('full_name') or employee.get('username') or 'Employee') if employee else 'Employee'

    if decision == 'Approve':
        # ── Update HR records (status = Approved, archive) ────────────────
        client.table('leave_requests').update({
            'final_decision': 'Approved',
            'final_decided_by': current_user.id,
            'final_decided_at': now_iso,
            'workflow_step': 'Approved',
            'status': 'Approved',
            'approved_by': current_user.id,
            'is_archived': True,
            'archived_at': now_iso,
        }).eq('id', leave_id).execute()

        if emp_id:
            Notification.create(
                user_id=emp_id,
                title="Leave Request Approved",
                message=f"Your {leave['leave_type']} leave ({leave['start_date']} → {leave['end_date']}) "
                        f"has been fully approved. Enjoy your time off!",
                n_type="success", sender_subsystem='hr3', target_url=detail_url
            )
        flash(f"Leave approved and HR records updated. {emp_name} has been notified.", 'success')

    elif decision == 'Reject':
        client.table('leave_requests').update({
            'final_decision': 'Rejected',
            'final_decided_by': current_user.id,
            'final_decided_at': now_iso,
            'workflow_step': 'Rejected',
            'status': 'Rejected',
            'is_archived': True,
            'archived_at': now_iso,
        }).eq('id', leave_id).execute()

        if emp_id:
            Notification.create(
                user_id=emp_id,
                title="Leave Request Not Approved",
                message=f"Your {leave['leave_type']} leave ({leave['start_date']} → {leave['end_date']}) "
                        f"was not approved at final review.{(' Note: ' + notes) if notes else ' Please contact HR.'}",
                n_type="danger", sender_subsystem='hr3', target_url=detail_url
            )
        flash('Leave request rejected. Employee has been notified.', 'info')

    return redirect(detail_url)


@hr3_bp.route('/leaves/<int:leave_id>/archive', methods=['POST'])
@login_required
def archive_leave(leave_id):
    """Manually archive a completed or rejected leave request."""
    is_admin = current_user.is_super_admin() or (
        current_user.role in ['Admin', 'Administrator'] and current_user.subsystem == 'hr3'
    )
    if not is_admin:
        flash('Unauthorized.', 'danger')
        return redirect(url_for('hr3.leave_detail', leave_id=leave_id))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        client.table('leave_requests').update({
            'is_archived': True,
            'archived_at': datetime.now().isoformat(),
        }).eq('id', leave_id).execute()
        flash('Leave request archived.', 'success')
    except Exception as e:
        flash(f'Error archiving: {str(e)}', 'danger')
    return redirect(url_for('hr3.list_leaves'))


@hr3_bp.route('/leaves/approve', methods=['POST'])
@login_required
def approve_leave():
    """Legacy quick-approve route — redirected into the new ESS workflow."""
    leave_id = request.form.get('leave_id')
    status = request.form.get('status')  # 'Approved' or 'Rejected'

    is_admin = current_user.is_super_admin() or (
        current_user.role in ['Admin', 'Administrator'] and current_user.subsystem == 'hr3'
    )
    if not is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('hr3.dashboard'))

    if not leave_id:
        return redirect(url_for('hr3.list_leaves'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        leave_resp = client.table('leave_requests').select('user_id, leave_type, workflow_step').eq('id', leave_id).limit(1).execute()
        if not leave_resp.data:
            flash('Leave request not found.', 'danger')
            return redirect(url_for('hr3.list_leaves'))
        leave = leave_resp.data[0]

        # If still in old simple flow (no workflow_step set), do direct update
        if not leave.get('workflow_step'):
            from utils.hms_models import Notification
            client.table('leave_requests').update({
                'status': status,
                'approved_by': current_user.id,
                'workflow_step': status,
                'is_archived': True,
                'archived_at': datetime.now().isoformat()
            }).eq('id', leave_id).execute()
            target_id = leave.get('user_id')
            if target_id:
                Notification.create(user_id=target_id,
                    title=f"Leave Request {status}",
                    message=f"Your {leave['leave_type']} leave has been {status.lower()}.",
                    n_type="success" if status == 'Approved' else "danger",
                    sender_subsystem=BLUEPRINT_NAME)
            flash(f'Leave request {status.lower()}.', 'success')
            return redirect(url_for('hr3.list_leaves'))

    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')

    # For new-flow requests, redirect to detail page
    return redirect(url_for('hr3.leave_detail', leave_id=leave_id))


# =====================================================
# SCHEDULE CHANGE REQUESTS
# =====================================================

def _notify_finance_admins(client, title, message, n_type, sender_subsystem, target_url=None):
    """Notify all active Finance/Financials admins."""
    from utils.hms_models import Notification
    try:
        admins = client.table('users').select('id').eq('subsystem', 'financials').in_('role', ['Admin', 'Administrator']).eq('status', 'Active').execute()
        for a in (admins.data or []):
            Notification.create(user_id=a['id'], title=title, message=message,
                                n_type=n_type, sender_subsystem=sender_subsystem, target_url=target_url)
    except Exception as e:
        print(f"Finance notification error: {e}")


@hr3_bp.route('/schedule-changes', methods=['GET'])
@login_required
def list_schedule_changes():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    is_admin = current_user.is_super_admin() or (
        current_user.role in ['Admin', 'Administrator'] and current_user.subsystem == 'hr3'
    )
    query = client.table('schedule_change_requests').select(
        '*, users:users!schedule_change_requests_user_id_fkey(username, full_name, avatar_url)'
    )
    if not is_admin:
        query = query.eq('user_id', current_user.id)
    response = query.order('created_at', desc=True).execute()
    changes = response.data or []

    # Counts for admin tabs
    counts = {}
    if is_admin:
        all_resp = client.table('schedule_change_requests').select('status').execute()
        for r in (all_resp.data or []):
            s = r.get('status', 'Pending')
            counts[s] = counts.get(s, 0) + 1

    return render_template('subsystems/hr/hr3/schedule_changes.html',
                           changes=changes,
                           counts=counts,
                           is_admin=is_admin,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr3_bp.route('/schedule-changes/request', methods=['GET', 'POST'])
@login_required
def request_schedule_change():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    # Fetch employee's current schedules for pre-fill
    my_schedules = []
    try:
        resp = client.table('staff_schedules').select('*').eq('user_id', current_user.id).eq('is_active', True).execute()
        my_schedules = resp.data or []
    except Exception:
        pass

    if request.method == 'POST':
        current_day = request.form.get('current_day', '').strip()
        current_start = request.form.get('current_start', '').strip()
        current_end = request.form.get('current_end', '').strip()
        requested_day = request.form.get('requested_day', '').strip()
        requested_start = request.form.get('requested_start', '').strip()
        requested_end = request.form.get('requested_end', '').strip()
        reason = request.form.get('reason', '').strip()

        if not all([requested_day, requested_start, requested_end, reason]):
            flash('Please fill in all required fields.', 'warning')
            return render_template('subsystems/hr/hr3/schedule_change_form.html',
                                   my_schedules=my_schedules,
                                   form_data=request.form,
                                   subsystem_name=SUBSYSTEM_NAME,
                                   accent_color=ACCENT_COLOR,
                                   blueprint_name=BLUEPRINT_NAME)
        try:
            record = {
                'user_id': current_user.id,
                'current_day': current_day or None,
                'current_start': current_start or None,
                'current_end': current_end or None,
                'requested_day': requested_day,
                'requested_start': requested_start,
                'requested_end': requested_end,
                'reason': reason,
                'status': 'Pending'
            }
            result = client.table('schedule_change_requests').insert(record).execute()
            req_id = result.data[0]['id'] if result.data else None
            target_url = url_for('hr3.list_schedule_changes')
            _notify_hr3_admins(client,
                               title='New Schedule Change Request',
                               message=f"{current_user.username} has submitted a schedule change request.",
                               n_type='info',
                               sender_subsystem=BLUEPRINT_NAME,
                               target_url=target_url)
            flash('Schedule change request submitted successfully.', 'success')
            return redirect(url_for('hr3.list_schedule_changes'))
        except Exception as e:
            flash(f'Error submitting request: {str(e)}', 'danger')

    return render_template('subsystems/hr/hr3/schedule_change_form.html',
                           my_schedules=my_schedules,
                           form_data={},
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr3_bp.route('/schedule-changes/<int:req_id>/decide', methods=['POST'])
@login_required
def decide_schedule_change(req_id):
    if not current_user.is_super_admin() and (not current_user.is_admin() or current_user.subsystem != 'hr3'):
        flash('Unauthorized.', 'danger')
        return redirect(url_for('hr3.list_schedule_changes'))

    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()

    decision = request.form.get('decision')
    reviewer_notes = request.form.get('reviewer_notes', '').strip()

    if decision not in ('Approved', 'Rejected'):
        flash('Invalid decision.', 'danger')
        return redirect(url_for('hr3.list_schedule_changes'))

    try:
        resp = client.table('schedule_change_requests').select('*').eq('id', req_id).limit(1).execute()
        if not resp.data:
            flash('Request not found.', 'danger')
            return redirect(url_for('hr3.list_schedule_changes'))
        req_data = resp.data[0]

        client.table('schedule_change_requests').update({
            'status': decision,
            'reviewed_by': current_user.id,
            'reviewed_at': datetime.now().isoformat(),
            'reviewer_notes': reviewer_notes
        }).eq('id', req_id).execute()

        # If approved, apply the schedule change
        if decision == 'Approved':
            uid = req_data['user_id']
            new_day = req_data['requested_day']
            new_start = req_data['requested_start']
            new_end = req_data['requested_end']
            existing = client.table('staff_schedules').select('id').eq('user_id', uid).eq('day_of_week', new_day).execute()
            if existing.data:
                client.table('staff_schedules').update({'start_time': new_start, 'end_time': new_end, 'is_active': True}) \
                    .eq('id', existing.data[0]['id']).execute()
            else:
                client.table('staff_schedules').insert({
                    'user_id': uid, 'day_of_week': new_day,
                    'start_time': new_start, 'end_time': new_end, 'is_active': True
                }).execute()

        # Notify employee
        Notification.create(
            user_id=req_data['user_id'],
            title=f"Schedule Change Request {decision}",
            message=f"Your schedule change request has been {decision.lower()}." +
                    (f" Notes: {reviewer_notes}" if reviewer_notes else ""),
            n_type='success' if decision == 'Approved' else 'danger',
            sender_subsystem=BLUEPRINT_NAME
        )
        flash(f'Schedule change request {decision.lower()}.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')

    return redirect(url_for('hr3.list_schedule_changes'))


# =====================================================
# REIMBURSEMENT CLAIMS
# =====================================================

@hr3_bp.route('/reimbursements', methods=['GET'])
@login_required
def list_reimbursements():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    is_admin = current_user.is_super_admin() or (
        current_user.role in ['Admin', 'Administrator'] and current_user.subsystem in ('hr3', 'financials')
    )
    filter_step = request.args.get('step', 'all')
    show_archived = request.args.get('archived', '0') == '1'

    query = client.table('reimbursement_claims').select(
        '*, users:users!reimbursement_claims_user_id_fkey(username, full_name, avatar_url)'
    )
    if not is_admin:
        query = query.eq('user_id', current_user.id)
    if not show_archived:
        query = query.eq('is_archived', False)
    if filter_step != 'all' and filter_step in ('HR Review', 'Finance Review', 'Completed', 'Rejected'):
        query = query.eq('workflow_step', filter_step)

    claims = query.order('created_at', desc=True).execute().data or []

    counts = {}
    if is_admin:
        all_resp = client.table('reimbursement_claims').select('workflow_step').execute()
        for r in (all_resp.data or []):
            s = r.get('workflow_step', 'HR Review')
            counts[s] = counts.get(s, 0) + 1

    return render_template('subsystems/hr/hr3/reimbursements.html',
                           claims=claims,
                           counts=counts,
                           is_admin=is_admin,
                           filter_step=filter_step,
                           show_archived=show_archived,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr3_bp.route('/reimbursements/submit', methods=['GET', 'POST'])
@login_required
def submit_reimbursement():
    from utils.supabase_client import get_supabase_client, get_supabase_service_client
    client = get_supabase_client()

    if request.method == 'POST':
        claim_type = request.form.get('claim_type', '').strip()
        amount_str = request.form.get('amount', '0').strip()
        description = request.form.get('description', '').strip()
        expense_date = request.form.get('expense_date', '').strip()
        receipt_file = request.files.get('receipt')

        errors = []
        if not claim_type:
            errors.append('Claim type is required.')
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError
        except ValueError:
            errors.append('Enter a valid positive amount.')
        if not description:
            errors.append('Description is required.')
        if not expense_date:
            errors.append('Expense date is required.')

        if errors:
            for e in errors:
                flash(e, 'warning')
            return render_template('subsystems/hr/hr3/reimbursement_form.html',
                                   form_data=request.form,
                                   subsystem_name=SUBSYSTEM_NAME,
                                   accent_color=ACCENT_COLOR,
                                   blueprint_name=BLUEPRINT_NAME)
        # Upload receipt if provided
        receipt_url = None
        if receipt_file and receipt_file.filename:
            try:
                import uuid, os
                ext = os.path.splitext(receipt_file.filename)[1].lower()
                allowed = {'.pdf', '.jpg', '.jpeg', '.png'}
                if ext not in allowed:
                    flash('Receipt must be PDF, JPG, or PNG.', 'warning')
                    return render_template('subsystems/hr/hr3/reimbursement_form.html',
                                           form_data=request.form,
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           blueprint_name=BLUEPRINT_NAME)
                service_client = get_supabase_service_client()
                file_bytes = receipt_file.read()
                filename = f"receipts/{current_user.id}/{uuid.uuid4().hex}{ext}"
                service_client.storage.from_('receipts').upload(filename, file_bytes,
                    file_options={"content-type": receipt_file.content_type or "application/octet-stream"})
                receipt_url = service_client.storage.from_('receipts').get_public_url(filename)
            except Exception as ue:
                flash(f'Receipt upload failed: {str(ue)}', 'warning')

        try:
            record = {
                'user_id': current_user.id,
                'claim_type': claim_type,
                'amount': amount,
                'description': description,
                'expense_date': expense_date,
                'receipt_url': receipt_url,
                'status': 'Pending',
                'workflow_step': 'HR Review'
            }
            client.table('reimbursement_claims').insert(record).execute()

            target_url = url_for('hr3.list_reimbursements')
            _notify_hr3_admins(client,
                               title='New Reimbursement Claim',
                               message=f"{current_user.username} submitted a ₱{amount:,.2f} {claim_type} reimbursement claim.",
                               n_type='info',
                               sender_subsystem=BLUEPRINT_NAME,
                               target_url=target_url)
            flash('Reimbursement claim submitted successfully.', 'success')
            return redirect(url_for('hr3.list_reimbursements'))
        except Exception as e:
            flash(f'Error submitting claim: {str(e)}', 'danger')

    return render_template('subsystems/hr/hr3/reimbursement_form.html',
                           form_data={},
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@hr3_bp.route('/reimbursements/<int:claim_id>/decide', methods=['POST'])
@login_required
def decide_reimbursement(claim_id):
    if not current_user.is_super_admin() and \
       not (current_user.is_admin() and current_user.subsystem in ('hr3', 'financials')):
        flash('Unauthorized.', 'danger')
        return redirect(url_for('hr3.list_reimbursements'))

    from utils.supabase_client import get_supabase_client
    from utils.hms_models import Notification
    client = get_supabase_client()

    decision = request.form.get('decision')
    notes = request.form.get('notes', '').strip()

    if decision not in ('Approve', 'Reject'):
        flash('Invalid decision.', 'danger')
        return redirect(url_for('hr3.list_reimbursements'))

    try:
        resp = client.table('reimbursement_claims').select('*').eq('id', claim_id).limit(1).execute()
        if not resp.data:
            flash('Claim not found.', 'danger')
            return redirect(url_for('hr3.list_reimbursements'))
        claim = resp.data[0]
        step = claim.get('workflow_step', 'HR Review')
        now_iso = datetime.now().isoformat()

        if step == 'HR Review':
            if decision == 'Approve':
                client.table('reimbursement_claims').update({
                    'workflow_step': 'Finance Review',
                    'status': 'HR Approved',
                    'hr_approved_by': current_user.id,
                    'hr_approved_at': now_iso,
                    'hr_notes': notes
                }).eq('id', claim_id).execute()
                _notify_finance_admins(client,
                    title='Reimbursement Claim — Finance Review Needed',
                    message=f"A ₱{claim['amount']:,.2f} {claim['claim_type']} claim is awaiting Finance approval.",
                    n_type='info', sender_subsystem=BLUEPRINT_NAME,
                    target_url=url_for('hr3.list_reimbursements'))
                flash('Claim forwarded to Finance for approval.', 'success')
            else:
                client.table('reimbursement_claims').update({
                    'workflow_step': 'Rejected',
                    'status': 'Rejected',
                    'hr_approved_by': current_user.id,
                    'hr_approved_at': now_iso,
                    'hr_notes': notes,
                    'is_archived': True,
                    'archived_at': now_iso
                }).eq('id', claim_id).execute()
                Notification.create(user_id=claim['user_id'],
                    title='Reimbursement Claim Rejected',
                    message=f"Your {claim['claim_type']} claim of ₱{claim['amount']:,.2f} was rejected by HR." +
                            (f" Reason: {notes}" if notes else ""),
                    n_type='danger', sender_subsystem=BLUEPRINT_NAME)
                flash('Claim rejected.', 'info')

        elif step == 'Finance Review':
            if decision == 'Approve':
                client.table('reimbursement_claims').update({
                    'workflow_step': 'Completed',
                    'status': 'Finance Approved',
                    'finance_approved_by': current_user.id,
                    'finance_approved_at': now_iso,
                    'finance_notes': notes,
                    'is_archived': True,
                    'archived_at': now_iso
                }).eq('id', claim_id).execute()
                Notification.create(user_id=claim['user_id'],
                    title='Reimbursement Claim Approved',
                    message=f"Your {claim['claim_type']} claim of ₱{claim['amount']:,.2f} has been approved for payment.",
                    n_type='success', sender_subsystem=BLUEPRINT_NAME)
                flash('Claim fully approved. Employee notified.', 'success')
            else:
                client.table('reimbursement_claims').update({
                    'workflow_step': 'Rejected',
                    'status': 'Rejected',
                    'finance_approved_by': current_user.id,
                    'finance_approved_at': now_iso,
                    'finance_notes': notes,
                    'is_archived': True,
                    'archived_at': now_iso
                }).eq('id', claim_id).execute()
                Notification.create(user_id=claim['user_id'],
                    title='Reimbursement Claim Rejected by Finance',
                    message=f"Your {claim['claim_type']} claim was rejected by Finance." +
                            (f" Reason: {notes}" if notes else ""),
                    n_type='danger', sender_subsystem=BLUEPRINT_NAME)
                flash('Claim rejected.', 'info')
        else:
            flash('This claim has already been completed.', 'info')

    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')

    return redirect(url_for('hr3.list_reimbursements'))
