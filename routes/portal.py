from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
import os

portal_bp = Blueprint('portal', __name__)

@portal_bp.route('/')
def index():
    from utils.supabase_client import SUBSYSTEM_CONFIG
    subsystem_color = 'blue'
    if current_user.is_authenticated:
        subsystem_info = SUBSYSTEM_CONFIG.get(current_user.subsystem, {})
        subsystem_color = subsystem_info.get('color', 'blue')
    return render_template('portal/index.html', subsystem_color=subsystem_color)

@portal_bp.route('/profile')
@login_required
def profile():
    from utils.supabase_client import SUBSYSTEM_CONFIG
    subsystem_info = SUBSYSTEM_CONFIG.get(current_user.subsystem, {})
    subsystem_name = subsystem_info.get('name', current_user.subsystem.upper())
    subsystem_color = subsystem_info.get('color', 'indigo')
    return render_template('portal/profile.html', 
                         user=current_user, 
                         subsystem_full_name=subsystem_name,
                         subsystem_color=subsystem_color)

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
            # Assuming 'profiles' bucket exists and is public or has appropriate policies
            try:
                # Try to upload file
                bucket_name = 'profiles'
                
                # Check if bucket exists, if not this might fail but we'll try to upload anyway
                # Supabase Python client storage API: storage.from_('bucket').upload('path', file)
                res = client.storage.from_(bucket_name).upload(
                    path=file_path,
                    file=file_content,
                    file_options={"content-type": file.content_type, "x-upsert": "true"}
                )
                
                # Get public URL
                avatar_url = client.storage.from_(bucket_name).get_public_url(file_path)
                
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
