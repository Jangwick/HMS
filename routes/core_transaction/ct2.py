from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error, get_supabase_client
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from datetime import datetime, timedelta

ct2_bp = Blueprint('ct2', __name__, template_folder='templates')

# Subsystem configuration
SUBSYSTEM_NAME = 'CT2 - Clinical Operations'
ACCENT_COLOR = '#10B981'
SUBSYSTEM_ICON = 'clipboard-pulse'
BLUEPRINT_NAME = 'ct2'

@ct2_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked(subsystem=BLUEPRINT_NAME)
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/core_transaction/ct2/login.html', 
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
                    return redirect(url_for('ct2.change_password'))

                # Check if account is approved
                if user.status != 'Active':
                    if user.status == 'Pending':
                        flash('Your account is awaiting approval from HR2 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('subsystems/core_transaction/ct2/login.html',
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           subsystem_icon=SUBSYSTEM_ICON,
                                           blueprint_name=BLUEPRINT_NAME,
                                           hub_route='portal.ct_hub')

                # Clear IP lockout attempts on successful login
                register_successful_login(subsystem=BLUEPRINT_NAME)
                user.register_successful_login()
                
                if login_user(user):
                    days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                    if days_left <= 7:
                        flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    return redirect(url_for('ct2.dashboard'))
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
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt(subsystem=BLUEPRINT_NAME)
                
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


@ct2_bp.route('/change-password', methods=['GET', 'POST'])
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
            return redirect(url_for('ct2.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('ct2.login'))
    
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
            return redirect(url_for('ct2.login'))
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html',
        subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@ct2_bp.route('/dashboard')
@login_required
@policy_required(BLUEPRINT_NAME)
def dashboard():
    from utils.hms_models import LabOrder
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    
    supabase = get_supabase_client()
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    
    # Get stats
    metrics = {
        'total_lab_orders': 0,
        'pending_labs': 0,
        'low_stock_items': 0,
        'today_patients': 0,
        'pending_prescriptions': 0,
        'today_dispenses': 0,
        'critical_count': 0,
        'radiology_pending': 0,
        'surgeries_today': 0
    }
    recent_orders = []
    critical_labs = []
    recent_dispenses = []

    try:
        # Lab stats
        res = supabase.table('lab_orders').select('*, patients(*)').execute()
        lab_data = res.data if res.data else []
        metrics['total_lab_orders'] = len(lab_data)
        metrics['pending_labs'] = len([o for o in lab_data if o.get('status') == 'Ordered'])
        critical_labs = [o for o in lab_data if o.get('critical_alert')]
        metrics['critical_count'] = len(critical_labs)

        # Radiology stats
        res = supabase.table('radiology_orders').select('*').eq('status', 'Ordered').execute()
        metrics['radiology_pending'] = len(res.data) if res.data else 0

        # Surgery stats
        today_str = datetime.utcnow().strftime('%Y-%m-%d')
        res = supabase.table('surgeries').select('*').gte('surgery_date', f"{today_str}T00:00:00").lte('surgery_date', f"{today_str}T23:59:59").execute()
        metrics['surgeries_today'] = len(res.data) if res.data else 0

        # Pharmacy stats
        res = supabase.table('inventory').select('*').execute()
        inv_data = res.data if res.data else []
        metrics['low_stock_items'] = len([i for i in inv_data if (i.get('quantity') or 0) < 10])

        res = supabase.table('prescriptions').select('*').execute()
        rx_data = res.data if res.data else []
        metrics['pending_prescriptions'] = len([r for r in rx_data if r.get('status') == 'Pending'])

        res = supabase.table('appointments').select('*').execute()
        app_data = res.data if res.data else []
        # Filter for today
        today_date = datetime.utcnow().date()
        today_apps = []
        for a in app_data:
            a_date_str = a.get('appointment_date')
            if a_date_str:
                try:
                    a_date = datetime.fromisoformat(a_date_str.replace('Z', '+00:00')).date()
                    if a_date == today_date:
                        today_apps.append(a)
                except:
                    pass
        metrics['today_patients'] = len(today_apps)

        # Dispensing
        res = supabase.table('dispensing_history').select('*, patients(*), inventory(*)').execute()
        dispense_data = res.data if res.data else []
        metrics['today_dispenses'] = len([d for d in dispense_data if d.get('dispensed_at', '').startswith(datetime.utcnow().strftime('%Y-%m-%d'))])
        recent_dispenses = sorted(dispense_data, key=lambda x: x.get('dispensed_at', ''), reverse=True)[:5]

        # DNMS Stats
        res = supabase.table('diet_plans').select('*').eq('status', 'Active').execute()
        metrics['active_diet_plans'] = len(res.data) if res.data else 0
        
        res = supabase.table('meal_tracking').select('*').gte('created_at', f"{today_str}T00:00:00").execute()
        metrics['today_meals'] = len(res.data) if res.data else 0

        recent_orders = LabOrder.get_recent(5)

        # Encounter stats
        try:
            enc_data = supabase.table('encounters').select('status').execute().data or []
            metrics['active_encounters'] = sum(1 for e in enc_data if e.get('status') == 'Active')
            metrics['enc_awaiting'] = sum(1 for e in enc_data if e.get('status') == 'Awaiting Results')
        except Exception:
            metrics['active_encounters'] = 0
            metrics['enc_awaiting'] = 0

        # Inbox unread
        try:
            inbox_data = supabase.table('result_inbox').select('acknowledged').eq('physician_id', current_user.id).eq('acknowledged', False).execute().data or []
            metrics['inbox_unread'] = len(inbox_data)
        except Exception:
            metrics['inbox_unread'] = 0

    except Exception as e:
        print(f"Dashboard Data Error: {e}")
    
    return render_template('subsystems/core_transaction/ct2/dashboard.html',
                           now=datetime.utcnow,
                           metrics=metrics,
                           recent_orders=recent_orders,
                           critical_labs=critical_labs,
                           recent_dispenses=recent_dispenses,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/lab/orders')
@login_required
def lab_orders():
    from utils.hms_models import LabOrder, Patient
    orders = LabOrder.get_all()
    patients = Patient.get_all()
    
    client = get_supabase_client()
    doctors = client.table('users').select('*').in_('subsystem', ['ct1', 'ct2', 'ct3']).execute().data or []
        
    return render_template('subsystems/core_transaction/ct2/lab_orders.html', 
                           now=datetime.utcnow,
                           orders=orders,
                           patients=patients,
                           doctors=doctors,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/lab/order/new', methods=['POST'])
@login_required
def new_lab_order():
    from utils.hms_models import LabOrder
    try:
        data = {
            'patient_id': request.form.get('patient_id'),
            'doctor_id': request.form.get('doctor_id') or current_user.id,
            'test_name': request.form.get('test_name'),
            'status': 'Ordered',
            'critical_alert': 'critical_alert' in request.form
        }
        LabOrder.create(data)
        
        # Auto-Charge for Lab Order (INTEGRATION)
        from utils.hms_models import Billing
        lab_fee = 2500.0
        Billing.post_charge(data['patient_id'], lab_fee, f"Lab Order: {data['test_name']}", "Laboratory (CT2)")
        
        flash('Lab order created successfully!', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('ct2.lab_orders'))

@ct2_bp.route('/lab/order/<int:order_id>/update', methods=['POST'])
@login_required
def update_lab_order(order_id):
    from utils.hms_models import LabOrder
    try:
        results = request.form.get('results')
        status = request.form.get('status')
        critical = 'critical_alert' in request.form
        
        update_data = {
            'status': status,
            'critical_alert': critical
        }
        
        if results:
            update_data['results'] = {'finding': results, 'updated_by': current_user.username}
            
        LabOrder.update(order_id, update_data)
        
        # AUDIT LOG
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Update Lab Order", BLUEPRINT_NAME, 
                     {"order_id": order_id, "status": status, "is_critical": critical})
                     
        if status == 'Completed':
            # Notify the Patient
            client = get_supabase_client()
            lab_order_res = client.table('lab_orders').select('patient_id, test_name').eq('id', order_id).execute()
            if lab_order_res.data:
                patient_id = lab_order_res.data[0]['patient_id']
                test_name = lab_order_res.data[0]['test_name']
                portal_user_res = client.table('users').select('id').eq('patient_id', patient_id).execute()
                if portal_user_res.data:
                    from utils.hms_models import Notification
                    Notification.create(
                        user_id=portal_user_res.data[0]['id'],
                        subsystem='patient',
                        title="Lab Results Available",
                        message=f"Your {test_name} results are now available for review.",
                        n_type="info",
                        sender_subsystem=BLUEPRINT_NAME,
                        target_url=url_for('patient.journey')
                    )
        flash('Lab order updated.', 'success')
    except Exception as e:
        flash(f'Update failed: {str(e)}', 'danger')
    return redirect(url_for('ct2.lab_orders'))


@ct2_bp.route('/radiology/orders')
@login_required
def radiology_orders():
    from utils.hms_models import RadiologyOrder, Patient
    orders = RadiologyOrder.get_all()
    patients = Patient.get_all()
    
    client = get_supabase_client()
    doctors = client.table('users').select('*').in_('subsystem', ['ct1', 'ct2', 'ct3']).execute().data or []
        
    return render_template('subsystems/core_transaction/ct2/radiology_orders.html', 
                           now=datetime.utcnow,
                           orders=orders,
                           patients=patients,
                           doctors=doctors,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/radiology/order/new', methods=['POST'])
@login_required
def new_radiology_order():
    from utils.hms_models import RadiologyOrder
    try:
        data = {
            'patient_id': request.form.get('patient_id'),
            'doctor_id': request.form.get('doctor_id') or current_user.id,
            'imaging_type': request.form.get('imaging_type'),
            'status': 'Ordered'
        }
        RadiologyOrder.create(data)
        
        # Auto-Charge for Radiology (INTEGRATION)
        from utils.hms_models import Billing
        imaging_fee = 5000.0 # Standard imaging fee estimate
        Billing.post_charge(data['patient_id'], imaging_fee, f"Radiology Order: {data['imaging_type']}", "Radiology (CT2)")
        
        flash('Radiology order created successfully!', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('ct2.radiology_orders'))

@ct2_bp.route('/radiology/order/<int:order_id>/update', methods=['POST'])
@login_required
def update_radiology_order(order_id):
    from utils.hms_models import RadiologyOrder
    try:
        findings = request.form.get('findings')
        status = request.form.get('status')
        image_url = request.form.get('image_url')
        
        update_data = {
            'status': status,
            'findings': findings,
            'image_url': image_url
        }
            
        RadiologyOrder.update(order_id, update_data)
        
        # AUDIT LOG
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Update Radiology Order", BLUEPRINT_NAME, 
                     {"order_id": order_id, "status": status})
                     
        if status == 'Completed':
            # Notify the Patient
            client = get_supabase_client()
            radio_order_res = client.table('radiology_orders').select('patient_id, imaging_type').eq('id', order_id).execute()
            if radio_order_res.data:
                patient_id = radio_order_res.data[0]['patient_id']
                imaging_type = radio_order_res.data[0]['imaging_type']
                portal_user_res = client.table('users').select('id').eq('patient_id', patient_id).execute()
                if portal_user_res.data:
                    from utils.hms_models import Notification
                    Notification.create(
                        user_id=portal_user_res.data[0]['id'],
                        subsystem='patient',
                        title="Radiology Results Available",
                        message=f"Your {imaging_type} results are now available for review.",
                        n_type="info",
                        sender_subsystem=BLUEPRINT_NAME,
                        target_url=url_for('patient.journey')
                    )
                     
        flash('Radiology order updated.', 'success')
    except Exception as e:
        flash(f'Update failed: {str(e)}', 'danger')
    return redirect(url_for('ct2.radiology_orders'))

@ct2_bp.route('/radiology/order/<int:order_id>/delete', methods=['POST'])
@login_required
def delete_radiology_order(order_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can delete radiology records.', 'danger')
        return redirect(url_for('ct2.radiology_orders'))
        
    from utils.hms_models import RadiologyOrder, AuditLog
    try:
        RadiologyOrder.delete(order_id)
        AuditLog.log(current_user.id, "Delete Radiology Order", BLUEPRINT_NAME, {"order_id": order_id})
        flash('Radiology order deleted.', 'info')
    except Exception as e:
        flash(f'Deletion failed: {str(e)}', 'danger')
    return redirect(url_for('ct2.radiology_orders'))


@ct2_bp.route('/surgery/schedule')
@login_required
def surgery_schedule():
    from utils.hms_models import Surgery, Patient
    surgeries = Surgery.get_all()
    patients = Patient.get_all()
    
    client = get_supabase_client()
    surgeons = client.table('users').select('*').in_('subsystem', ['ct2', 'ct3']).execute().data or []
        
    return render_template('subsystems/core_transaction/ct2/surgery_schedule.html', 
                           now=datetime.utcnow,
                           surgeries=surgeries,
                           patients=patients,
                           surgeons=surgeons,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/surgery/new', methods=['POST'])
@login_required
def new_surgery():
    from utils.hms_models import Surgery
    try:
        data = {
            'patient_id': request.form.get('patient_id'),
            'surgeon_id': request.form.get('surgeon_id'),
            'surgery_name': request.form.get('surgery_name'),
            'surgery_date': request.form.get('surgery_date'),
            'operating_theater': request.form.get('operating_theater'),
            'status': 'Scheduled',
            'notes': request.form.get('notes')
        }
        Surgery.create(data)
        
        # Auto-Charge for Surgery (INTEGRATION - Deposit/Base Fee)
        from utils.hms_models import Billing
        surgery_base_fee = 15000.0
        Billing.post_charge(data['patient_id'], surgery_base_fee, f"Surgery Scheduled: {data['surgery_name']}", "Surgery (CT2)")
        
        # Notify the Patient
        client = get_supabase_client()
        portal_user_res = client.table('users').select('id').eq('patient_id', data['patient_id']).execute()
        if portal_user_res.data:
            from utils.hms_models import Notification
            portal_user_id = portal_user_res.data[0]['id']
            # safely parse surgery date
            try:
                date_val = data['surgery_date']
                if 'T' in date_val:
                    date_obj = datetime.fromisoformat(date_val.replace('Z', '+00:00'))
                else:
                    date_obj = datetime.strptime(date_val, '%Y-%m-%d')
                date_str = date_obj.strftime('%b %d, %Y')
            except:
                date_str = data['surgery_date']
                
            Notification.create(
                user_id=portal_user_id,
                subsystem='patient',
                title="Surgery Scheduled",
                message=f"Your surgery ({data['surgery_name']}) has been scheduled for {date_str}.",
                n_type="warning",
                sender_subsystem=BLUEPRINT_NAME,
                target_url=url_for('ct1.dashboard')
            )
            
        flash('Surgery scheduled successfully!', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('ct2.surgery_schedule'))

@ct2_bp.route('/surgery/<int:surgery_id>/update', methods=['POST'])
@login_required
def update_surgery(surgery_id):
    from utils.hms_models import Surgery
    try:
        # Basic fields for everyone
        status = request.form.get('status')
        notes = request.form.get('notes')
        
        update_data = {
            'status': status,
            'notes': notes
        }

        # Admin extra fields
        if current_user.is_admin():
            if request.form.get('surgery_name'):
                update_data['surgery_name'] = request.form.get('surgery_name')
            if request.form.get('operating_theater'):
                update_data['operating_theater'] = request.form.get('operating_theater')
            if request.form.get('surgery_date'):
                update_data['surgery_date'] = request.form.get('surgery_date')
            if request.form.get('surgeon_id'):
                update_data['surgeon_id'] = request.form.get('surgeon_id')
            
        Surgery.update(surgery_id, update_data)
        
        # AUDIT LOG
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Update Surgery", BLUEPRINT_NAME, 
                     {"surgery_id": surgery_id, "status": status, "is_admin_edit": current_user.is_admin()})
                     
        flash('Surgery record updated successfully.', 'success')
    except Exception as e:
        flash(f'Update failed: {str(e)}', 'danger')
    return redirect(url_for('ct2.surgery_schedule'))

@ct2_bp.route('/surgery/<int:surgery_id>/delete', methods=['POST'])
@login_required
def delete_surgery(surgery_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can delete surgery records.', 'danger')
        return redirect(url_for('ct2.surgery_schedule'))
        
    from utils.hms_models import Surgery, AuditLog
    try:
        Surgery.delete(surgery_id)
        AuditLog.log(current_user.id, "Delete Surgery Record", BLUEPRINT_NAME, {"surgery_id": surgery_id})
        flash('Surgery record removed.', 'info')
    except Exception as e:
        flash(f'Deletion failed: {str(e)}', 'danger')
    return redirect(url_for('ct2.surgery_schedule'))


@ct2_bp.route('/pharmacy/inventory')
@login_required
def pharmacy_inventory():
    from utils.hms_models import InventoryItem
    try:
        items = InventoryItem.get_all(category='Medical')
    except Exception as e:
        flash(f"Error fetching inventory: {str(e)}", "danger")
        items = []
        
    return render_template('subsystems/core_transaction/ct2/pharmacy_inventory.html', 
                           now=datetime.utcnow,
                           items=items,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/pharmacy/item/add', methods=['POST'])
@login_required
def add_pharmacy_item():
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can add inventory items.', 'error')
        return redirect(url_for('ct2.pharmacy_inventory'))

    from utils.hms_models import InventoryItem
    try:
        data = {
            'item_name': request.form.get('item_name'),
            'category': 'Medical',
            'quantity': int(request.form.get('quantity', 0)),
            'reorder_level': int(request.form.get('reorder_level', 10)),
            'expiry_date': request.form.get('expiry_date'),
            'batch_number': request.form.get('batch_number')
        }
        InventoryItem.create(data)
        flash('Medication added to inventory.', 'success')
    except Exception as e:
        flash(f'Error adding item: {str(e)}', 'danger')
    return redirect(url_for('ct2.pharmacy_inventory'))

@ct2_bp.route('/pharmacy/item/<int:item_id>/update', methods=['POST'])
@login_required
def update_pharmacy_item(item_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can update stock levels.', 'error')
        return redirect(url_for('ct2.pharmacy_inventory'))
        
    from utils.hms_models import InventoryItem
    try:
        data = {
            'quantity': int(request.form.get('quantity')),
            'reorder_level': int(request.form.get('reorder_level')),
            'expiry_date': request.form.get('expiry_date')
        }
        InventoryItem.update(item_id, data)
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Update Pharmacy Stock", BLUEPRINT_NAME, {"item_id": item_id, "new_quantity": data.get('quantity')})
        flash('Inventory updated.', 'success')
    except Exception as e:
        flash(f'Update failed: {str(e)}', 'danger')
    return redirect(url_for('ct2.pharmacy_inventory'))

@ct2_bp.route('/pharmacy/item/<int:item_id>/delete', methods=['POST'])
@login_required
def delete_pharmacy_item(item_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can delete records.', 'error')
        return redirect(url_for('ct2.pharmacy_inventory'))
        
    from utils.hms_models import InventoryItem
    try:
        InventoryItem.delete(item_id)
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Delete Pharmacy Item", BLUEPRINT_NAME, {"item_id": item_id})
        flash('Medication record removed.', 'info')
    except Exception as e:
        flash(f'Deletion failed: {str(e)}', 'danger')
    return redirect(url_for('ct2.pharmacy_inventory'))

@ct2_bp.route('/pharmacy/history')
@login_required
def dispensing_history():
    client = get_supabase_client()
    try:
        # Get prescriptions with status 'Dispensed' and join patients/doctors
        response = client.table('prescriptions').select('*, patients(*), users!prescriptions_doctor_id_fkey(*)').eq('status', 'Dispensed').order('created_at', desc=True).execute()
        history = response.data if response.data else []
    except Exception as e:
        flash(f'Error fetching history: {str(e)}', 'danger')
        history = []
        
    return render_template('subsystems/core_transaction/ct2/dispensing_history.html',
                           history=history,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/pharmacy/dispense', methods=['GET', 'POST'])
@login_required
def dispense_meds():
    from utils.hms_models import Patient
    client = get_supabase_client()
    
    if request.method == 'POST':
        try:
            # Check if dispensing an existing prescription
            prescription_id = request.form.get('prescription_id')
            patient_id = request.form.get('patient_id')
            med_name = request.form.get('medication')
            qty_str = request.form.get('quantity', '1')
            qty = int(qty_str) if qty_str else 1
            
            # 1. Update Inventory
            item_res = client.table('inventory').select('*').eq('item_name', med_name).eq('category', 'Medical').execute()
            if not item_res.data:
                flash(f'Medication "{med_name}" not found in medical inventory.', 'danger')
                return redirect(url_for('ct2.dispense_meds'))
            
            item = item_res.data[0]
            if item['quantity'] < qty:
                flash(f'Insufficient stock for {med_name}. Available: {item["quantity"]}, Requested: {qty}', 'warning')
                return redirect(url_for('ct2.dispense_meds'))
            
            new_qty = item['quantity'] - qty
            client.table('inventory').update({'quantity': new_qty}).eq('id', item['id']).execute()
            
            if prescription_id:
                # Update existing prescription
                client.table('prescriptions').update({'status': 'Dispensed'}).eq('id', prescription_id).execute()
                flash(f'Prescription #{prescription_id} dispensed successfully.', 'success')
            else:
                # 2. Record New Prescription (as dispensed)
                prescription_data = {
                    'patient_id': patient_id,
                    'doctor_id': current_user.id,
                    'medication_name': med_name,
                    'dosage': f"{qty} units",
                    'instructions': request.form.get('instructions'),
                    'status': 'Dispensed'
                }
                client.table('prescriptions').insert(prescription_data).execute()
                flash(f'Successfully dispensed {qty} of {med_name}.', 'success')
            
            # 3. Auto-Charge to Billing (INTEGRATION)
            from utils.hms_models import Billing
            # Assume a unit price for meds since it's not in DB yet
            unit_price = 150.0 
            total_charge = qty * unit_price
            charge_desc = f"Medication Dispensed: {med_name} (x{qty})"
            Billing.post_charge(patient_id, total_charge, charge_desc, "Pharmacy (CT2)")
            
            # AUDIT LOG
            from utils.hms_models import AuditLog
            AuditLog.log(current_user.id, "Dispense Medication", BLUEPRINT_NAME, 
                         {"medication": med_name, "quantity": qty, "patient_id": patient_id})
                         
            # Notify the Patient
            portal_user_res = client.table('users').select('id').eq('patient_id', patient_id).execute()
            if portal_user_res.data:
                from utils.hms_models import Notification
                portal_user_id = portal_user_res.data[0]['id']
                Notification.create(
                    user_id=portal_user_id,
                    subsystem='patient',
                    title="Medication Dispensed",
                    message=f"Your medication ({med_name}, qty: {qty}) has been dispensed.",
                    n_type="success",
                    sender_subsystem=BLUEPRINT_NAME,
                    target_url=url_for('ct1.dashboard')
                )
            
            return redirect(url_for('ct2.pharmacy_inventory'))
            
        except Exception as e:
            flash(f'Dispensing error: {str(e)}', 'danger')
    
    # GET request
    patients = Patient.get_all()
    meds = client.table('inventory').select('*').eq('category', 'Medical').gt('quantity', 0).execute().data or []
    
    # Fetch pending prescriptions with patient details
    pending_prescriptions = client.table('prescriptions')\
        .select('*, patients(first_name, last_name, patient_id_alt), users!prescriptions_doctor_id_fkey(username)')\
        .eq('status', 'Pending')\
        .order('created_at', desc=True)\
        .execute().data or []
    
    return render_template('subsystems/core_transaction/ct2/dispense_meds.html', 
                           now=datetime.utcnow,
                           patients=patients,
                           medications=meds,
                           pending_prescriptions=pending_prescriptions,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct2_bp.route('/settings', methods=['GET', 'POST'])
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
                           now=datetime.utcnow,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('ct2.login'))

@ct2_bp.route('/patients')
@login_required
def list_patients():
    supabase = get_supabase_client()
    try:
        response = supabase.table('patients').select('*').order('created_at', desc=True).execute()
        patients = response.data if response.data else []
    except Exception as e:
        flash(f"Error fetching patients: {str(e)}", "danger")
        patients = []
        
    return render_template('subsystems/core_transaction/ct1/patient_list.html', 
                           patients=patients,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/patients/search')
@login_required
def search_patients():
    query = request.args.get('q', '')
    supabase = get_supabase_client()
    try:
        # Simple search across name or ID
        response = supabase.table('patients').select('*').or_(f"first_name.ilike.%{query}%,last_name.ilike.%{query}%,patient_id_alt.ilike.%{query}%").execute()
        patients = response.data if response.data else []
    except Exception as e:
        flash(f"Search failed: {str(e)}", "danger")
        patients = []
        
    return render_template('subsystems/core_transaction/ct1/patient_list.html', 
                           patients=patients,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/patients/view/<patient_id>')
@login_required
def view_patient(patient_id):
    supabase = get_supabase_client()
    try:
        response = supabase.table('patients').select('*').eq('id', patient_id).single().execute()
        patient = response.data
        if not patient:
            flash("Patient not found", "warning")
            return redirect(url_for('ct2.list_patients'))
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for('ct2.list_patients'))
        
    return render_template('subsystems/core_transaction/ct1/view_patient.html',
                           patient=patient,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

# =====================================================
# DNMS: Diet and Nutrition Management System
# =====================================================

@ct2_bp.route('/dnms')
@login_required
@policy_required(BLUEPRINT_NAME)
def dnms_dashboard():
    supabase = get_supabase_client()
    try:
        # Get active diet plans
        diet_plans = supabase.table('diet_plans').select('*, patients(first_name, last_name)').order('created_at', desc=True).limit(5).execute().data
        
        # Get pending meal deliveries for today
        today = datetime.now().date().isoformat()
        pending_meals = supabase.table('meal_tracking').select('*, patients(first_name, last_name)').eq('delivery_status', 'Pending').execute().data
        
        # Get recent assessments
        recent_assessments = supabase.table('nutritional_assessments').select('*, patients(first_name, last_name)').order('created_at', desc=True).limit(5).execute().data
        
        stats = {
            'active_plans': len(supabase.table('diet_plans').select('id').eq('status', 'Active').execute().data),
            'pending_meals': len(pending_meals),
            'assessments_today': len(supabase.table('nutritional_assessments').select('id').gte('created_at', today).execute().data)
        }
    except Exception as e:
        flash(f"Error fetching DNMS data: {str(e)}", "danger")
        diet_plans, pending_meals, recent_assessments, stats = [], [], [], {}

    return render_template('subsystems/core_transaction/ct2/dnms_dashboard.html',
                           diet_plans=diet_plans,
                           pending_meals=pending_meals,
                           recent_assessments=recent_assessments,
                           stats=stats,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/dnms/diet-plans')
@login_required
def list_diet_plans():
    supabase = get_supabase_client()
    try:
        plans = supabase.table('diet_plans').select('*, patients(first_name, last_name, patient_id_alt), users(username)').order('created_at', desc=True).execute().data
        patients = supabase.table('patients').select('id, first_name, last_name, patient_id_alt').execute().data
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        plans, patients = [], []
    
    return render_template('subsystems/core_transaction/ct2/diet_plans.html',
                           plans=plans,
                           patients=patients,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/dnms/diet-plans/add', methods=['POST'])
@login_required
def add_diet_plan():
    supabase = get_supabase_client()
    data = {
        'patient_id': request.form.get('patient_id'),
        'diet_type': request.form.get('diet_type'),
        'instruction': request.form.get('instruction'),
        'prescribed_by': current_user.id,
        'start_date': request.form.get('start_date') or datetime.now().date().isoformat(),
        'end_date': request.form.get('end_date') or None,
        'status': 'Active'
    }
    try:
        supabase.table('diet_plans').insert(data).execute()
        flash('Diet plan prescribed successfully!', 'success')
    except Exception as e:
        flash(f"Failed to add diet plan: {str(e)}", "danger")
    return redirect(url_for('ct2.list_diet_plans'))

@ct2_bp.route('/dnms/assessments')
@login_required
def list_assessments():
    supabase = get_supabase_client()
    try:
        assessments = supabase.table('nutritional_assessments').select('*, patients(first_name, last_name, patient_id_alt), users(username)').order('created_at', desc=True).execute().data
        patients = supabase.table('patients').select('id, first_name, last_name, patient_id_alt').execute().data
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        assessments, patients = [], []
    
    return render_template('subsystems/core_transaction/ct2/nutrition_assessments.html',
                           assessments=assessments,
                           patients=patients,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/dnms/assessments/add', methods=['POST'])
@login_required
def add_assessment():
    supabase = get_supabase_client()
    weight = float(request.form.get('weight', 0))
    height = float(request.form.get('height', 1)) / 100 # cm to m
    bmi = round(weight / (height * height), 2) if height > 0 else 0
    
    data = {
        'patient_id': request.form.get('patient_id'),
        'clinician_id': current_user.id,
        'weight': weight,
        'height': float(request.form.get('height', 0)),
        'bmi': bmi,
        'assessment_notes': request.form.get('assessment_notes'),
        'recommendations': request.form.get('recommendations')
    }
    try:
        supabase.table('nutritional_assessments').insert(data).execute()
        flash('Nutritional assessment recorded!', 'success')
    except Exception as e:
        flash(f"Failed to save assessment: {str(e)}", "danger")
    return redirect(url_for('ct2.list_assessments'))

@ct2_bp.route('/dnms/meal-tracking')
@login_required
def meal_tracking():
    supabase = get_supabase_client()
    status_filter = request.args.get('status')
    try:
        query = supabase.table('meal_tracking').select('*, patients(first_name, last_name, patient_id_alt), users(username)').order('created_at', desc=True)
        if status_filter:
            query = query.eq('delivery_status', status_filter)
        
        meals = query.execute().data
        patients = supabase.table('patients').select('id, first_name, last_name, patient_id_alt').execute().data
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        meals, patients = [], []
    
    return render_template('subsystems/core_transaction/ct2/meal_tracking.html',
                           meals=meals,
                           patients=patients,
                           current_status=status_filter,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

# -----------------------------------------------------
# New Feature: Patient Nutrition Profile
# -----------------------------------------------------

@ct2_bp.route('/dnms/patient/<int:patient_id>')
@login_required
def patient_nutrition_profile(patient_id):
    supabase = get_supabase_client()
    try:
        patient = supabase.table('patients').select('*').eq('id', patient_id).single().execute().data
        diet_plans = supabase.table('diet_plans').select('*, users(username)').eq('patient_id', patient_id).order('created_at', desc=True).execute().data
        assessments = supabase.table('nutritional_assessments').select('*, users(username)').eq('patient_id', patient_id).order('created_at', desc=True).execute().data
        meal_history = supabase.table('meal_tracking').select('*, users(username)').eq('patient_id', patient_id).order('created_at', desc=True).limit(20).execute().data
    except Exception as e:
        flash(f"Error loading profile: {str(e)}", "danger")
        return redirect(url_for('ct2.dnms_dashboard'))
    
    return render_template('subsystems/core_transaction/ct2/patient_profile.html',
                           patient=patient,
                           diet_plans=diet_plans,
                           assessments=assessments,
                           meal_history=meal_history,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/dnms/meal-tracking/update/<int:meal_id>', methods=['POST'])
@login_required
def update_meal_status(meal_id):
    supabase = get_supabase_client()
    status = request.form.get('status')
    data = {
        'delivery_status': status,
        'delivered_at': datetime.now().isoformat() if status in ['Delivered', 'Consumed'] else None,
        'delivery_staff_id': current_user.id
    }
    try:
        supabase.table('meal_tracking').update(data).eq('id', meal_id).execute()
        flash('Meal status updated!', 'success')
    except Exception as e:
        flash(f"Failed to update meal: {str(e)}", "danger")
    return redirect(url_for('ct2.meal_tracking'))

@ct2_bp.route('/dnms/meal-tracking/add', methods=['POST'])
@login_required
def add_meal_log():
    supabase = get_supabase_client()
    data = {
        'patient_id': request.form.get('patient_id'),
        'meal_type': request.form.get('meal_type'),
        'delivery_status': 'Pending',
        'notes': request.form.get('notes')
    }
    try:
        supabase.table('meal_tracking').insert(data).execute()
        flash('Meal scheduled for delivery!', 'info')
    except Exception as e:
        flash(f"Failed to schedule meal: {str(e)}", "danger")
    return redirect(url_for('ct2.meal_tracking'))

# =====================================================
# DNMS Admin CRUD Operations
# =====================================================

@ct2_bp.route('/dnms/diet-plans/delete/<int:plan_id>', methods=['POST'])
@login_required
def delete_diet_plan(plan_id):
    if not current_user.is_admin():
        flash("Permission denied. Admin access required.", "danger")
        return redirect(url_for('ct2.list_diet_plans'))
    
    supabase = get_supabase_client()
    try:
        supabase.table('diet_plans').delete().eq('id', plan_id).execute()
        flash('Diet plan deleted successfully!', 'success')
    except Exception as e:
        flash(f"Failed to delete plan: {str(e)}", "danger")
    return redirect(url_for('ct2.list_diet_plans'))

@ct2_bp.route('/dnms/diet-plans/update/<int:plan_id>', methods=['POST'])
@login_required
def update_diet_plan(plan_id):
    if not current_user.is_admin():
        flash("Permission denied. Admin access required.", "danger")
        return redirect(url_for('ct2.list_diet_plans'))
    
    supabase = get_supabase_client()
    data = {
        'diet_type': request.form.get('diet_type'),
        'instruction': request.form.get('instruction'),
        'status': request.form.get('status'),
        'end_date': request.form.get('end_date') or None
    }
    try:
        supabase.table('diet_plans').update(data).eq('id', plan_id).execute()
        flash('Diet plan updated successfully!', 'success')
    except Exception as e:
        flash(f"Failed to update plan: {str(e)}", "danger")
    return redirect(url_for('ct2.list_diet_plans'))

@ct2_bp.route('/dnms/assessments/delete/<int:assessment_id>', methods=['POST'])
@login_required
def delete_assessment(assessment_id):
    if not current_user.is_admin():
        flash("Permission denied. Admin access required.", "danger")
        return redirect(url_for('ct2.list_assessments'))
    
    supabase = get_supabase_client()
    try:
        supabase.table('nutritional_assessments').delete().eq('id', assessment_id).execute()
        flash('Assessment record deleted!', 'success')
    except Exception as e:
        flash(f"Failed to delete assessment: {str(e)}", "danger")
    return redirect(url_for('ct2.list_assessments'))

@ct2_bp.route('/dnms/meal-tracking/delete/<int:meal_id>', methods=['POST'])
@login_required
def delete_meal_log(meal_id):
    if not current_user.is_admin():
        flash("Permission denied. Admin access required.", "danger")
        return redirect(url_for('ct2.meal_tracking'))
    
    supabase = get_supabase_client()
    try:
        supabase.table('meal_tracking').delete().eq('id', meal_id).execute()
        flash('Meal log entry removed.', 'success')
    except Exception as e:
        flash(f"Failed to delete meal log: {str(e)}", "danger")
    return redirect(url_for('ct2.meal_tracking'))


# =====================================================
# PHASE 1 — EMR & ENCOUNTER MANAGEMENT
# =====================================================

@ct2_bp.route('/encounters')
@login_required
@policy_required(BLUEPRINT_NAME)
def encounters():
    supabase = get_supabase_client()
    status_filter = request.args.get('status', '')
    try:
        q = supabase.table('encounters').select('*, patients(first_name, last_name, patient_id_alt), users!encounters_physician_id_fkey(full_name, username)')
        if status_filter:
            q = q.eq('status', status_filter)
        enc_data = q.order('encounter_date', desc=True).execute().data or []
    except Exception as e:
        flash(f'Error loading encounters: {str(e)}', 'danger')
        enc_data = []

    patients = []
    try:
        patients = supabase.table('patients').select('id, first_name, last_name, patient_id_alt').order('first_name').execute().data or []
    except Exception:
        pass

    # Always fetch global counts (unaffected by filter)
    counts = {'Active': 0, 'Awaiting Results': 0, 'Ready for Discharge': 0, 'Discharged': 0}
    try:
        all_enc = supabase.table('encounters').select('status').execute().data or []
        for e in all_enc:
            s = e.get('status', '')
            if s in counts:
                counts[s] += 1
    except Exception:
        pass

    return render_template('subsystems/core_transaction/ct2/encounters.html',
                           encounters=enc_data,
                           patients=patients,
                           counts=counts,
                           status_filter=status_filter,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct2_bp.route('/encounter/new', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def new_encounter():
    supabase = get_supabase_client()
    try:
        data = {
            'patient_id': int(request.form['patient_id']),
            'physician_id': current_user.id,
            'chief_complaint': request.form.get('chief_complaint', '').strip(),
            'examination_notes': request.form.get('examination_notes', '').strip(),
            'diagnosis': request.form.get('diagnosis', '').strip(),
            'icd_code': request.form.get('icd_code', '').strip(),
            'status': 'Active',
            'encounter_date': datetime.utcnow().isoformat(),
        }
        res = supabase.table('encounters').insert(data).execute()
        enc_id = res.data[0]['id'] if res.data else None
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, 'New Encounter', BLUEPRINT_NAME, {'patient_id': data['patient_id']})
        flash('Encounter created successfully.', 'success')
        if enc_id:
            return redirect(url_for('ct2.encounter_detail', encounter_id=enc_id))
    except Exception as e:
        flash(f'Error creating encounter: {str(e)}', 'danger')
    return redirect(url_for('ct2.encounters'))


@ct2_bp.route('/encounter/<int:encounter_id>')
@login_required
@policy_required(BLUEPRINT_NAME)
def encounter_detail(encounter_id):
    supabase = get_supabase_client()
    try:
        enc = supabase.table('encounters').select('*, patients(*), users(full_name, username)').eq('id', encounter_id).single().execute().data
        if not enc:
            flash('Encounter not found.', 'warning')
            return redirect(url_for('ct2.encounters'))
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('ct2.encounters'))

    # Parallel data for order tabs
    lab_orders, radiology_orders_list, prescriptions, diet_plans_list, surgeries_list, result_inbox_items = [], [], [], [], [], []
    try:
        lab_orders = supabase.table('lab_orders').select('*').eq('patient_id', enc['patient_id']).order('created_at', desc=True).execute().data or []
    except Exception: pass
    try:
        radiology_orders_list = supabase.table('radiology_orders').select('*').eq('patient_id', enc['patient_id']).order('created_at', desc=True).execute().data or []
    except Exception: pass
    try:
        prescriptions = supabase.table('prescriptions').select('*').eq('patient_id', enc['patient_id']).order('created_at', desc=True).execute().data or []
    except Exception: pass
    try:
        diet_plans_list = supabase.table('diet_plans').select('*').eq('patient_id', enc['patient_id']).order('created_at', desc=True).execute().data or []
    except Exception: pass
    try:
        surgeries_list = supabase.table('surgeries').select('*').eq('patient_id', enc['patient_id']).order('created_at', desc=True).execute().data or []
    except Exception: pass
    try:
        result_inbox_items = supabase.table('result_inbox').select('*').eq('encounter_id', encounter_id).order('created_at', desc=True).execute().data or []
    except Exception: pass

    # Meds and doctors for order forms
    meds, doctors = [], []
    try:
        meds = supabase.table('inventory').select('id, item_name, quantity').eq('category', 'Medical').gt('quantity', 0).execute().data or []
    except Exception: pass
    try:
        doctors = supabase.table('users').select('id, username, full_name').in_('subsystem', ['ct1', 'ct2', 'ct3']).execute().data or []
    except Exception: pass

    return render_template('subsystems/core_transaction/ct2/encounter_detail.html',
                           enc=enc,
                           lab_orders=lab_orders,
                           radiology_orders=radiology_orders_list,
                           prescriptions=prescriptions,
                           diet_plans=diet_plans_list,
                           surgeries=surgeries_list,
                           result_inbox=result_inbox_items,
                           meds=meds,
                           doctors=doctors,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct2_bp.route('/encounter/<int:encounter_id>/update', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def update_encounter(encounter_id):
    supabase = get_supabase_client()
    try:
        data = {
            'chief_complaint': request.form.get('chief_complaint', '').strip(),
            'examination_notes': request.form.get('examination_notes', '').strip(),
            'diagnosis': request.form.get('diagnosis', '').strip(),
            'icd_code': request.form.get('icd_code', '').strip(),
            'status': request.form.get('status'),
            'updated_at': datetime.utcnow().isoformat(),
        }
        supabase.table('encounters').update(data).eq('id', encounter_id).execute()
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, 'Update Encounter', BLUEPRINT_NAME, {'encounter_id': encounter_id, 'status': data['status']})
        flash('Encounter updated.', 'success')
    except Exception as e:
        flash(f'Update failed: {str(e)}', 'danger')
    return redirect(url_for('ct2.encounter_detail', encounter_id=encounter_id))


@ct2_bp.route('/encounter/<int:encounter_id>/discharge', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def discharge_encounter(encounter_id):
    supabase = get_supabase_client()
    try:
        supabase.table('encounters').update({
            'status': 'Discharged',
            'discharged_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
        }).eq('id', encounter_id).execute()
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, 'Discharge Encounter', BLUEPRINT_NAME, {'encounter_id': encounter_id})
        flash('Patient encounter closed — discharged successfully.', 'success')
    except Exception as e:
        flash(f'Discharge failed: {str(e)}', 'danger')
    return redirect(url_for('ct2.encounters'))


# =====================================================
# PHASE 2 — ORDER HUB  (quick-create within encounter)
# =====================================================

@ct2_bp.route('/encounter/<int:encounter_id>/order/lab', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def encounter_order_lab(encounter_id):
    supabase = get_supabase_client()
    try:
        enc = supabase.table('encounters').select('patient_id').eq('id', encounter_id).single().execute().data
        data = {
            'patient_id': enc['patient_id'],
            'doctor_id': current_user.id,
            'test_name': request.form.get('test_name'),
            'priority': request.form.get('priority', 'Routine'),
            'status': 'Ordered',
            'critical_alert': False,
        }
        supabase.table('lab_orders').insert(data).execute()
        supabase.table('encounters').update({'status': 'Awaiting Results', 'updated_at': datetime.utcnow().isoformat()}).eq('id', encounter_id).execute()
        flash('Lab order created.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('ct2.encounter_detail', encounter_id=encounter_id))


@ct2_bp.route('/encounter/<int:encounter_id>/order/radiology', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def encounter_order_radiology(encounter_id):
    supabase = get_supabase_client()
    try:
        enc = supabase.table('encounters').select('patient_id').eq('id', encounter_id).single().execute().data
        data = {
            'patient_id': enc['patient_id'],
            'doctor_id': current_user.id,
            'imaging_type': request.form.get('imaging_type'),
            'priority': request.form.get('priority', 'Routine'),
            'status': 'Ordered',
        }
        supabase.table('radiology_orders').insert(data).execute()
        supabase.table('encounters').update({'status': 'Awaiting Results', 'updated_at': datetime.utcnow().isoformat()}).eq('id', encounter_id).execute()
        flash('Radiology order created.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('ct2.encounter_detail', encounter_id=encounter_id))


@ct2_bp.route('/encounter/<int:encounter_id>/order/pharmacy', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def encounter_order_pharmacy(encounter_id):
    supabase = get_supabase_client()
    try:
        enc = supabase.table('encounters').select('patient_id').eq('id', encounter_id).single().execute().data
        data = {
            'patient_id': enc['patient_id'],
            'doctor_id': current_user.id,
            'medication_name': request.form.get('medication_name'),
            'dosage': request.form.get('dosage'),
            'instructions': request.form.get('instructions'),
            'priority': request.form.get('priority', 'Routine'),
            'status': 'Pending',
        }
        supabase.table('prescriptions').insert(data).execute()
        flash('Medication order sent to pharmacy.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('ct2.encounter_detail', encounter_id=encounter_id))


@ct2_bp.route('/encounter/<int:encounter_id>/order/diet', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def encounter_order_diet(encounter_id):
    supabase = get_supabase_client()
    try:
        enc = supabase.table('encounters').select('patient_id').eq('id', encounter_id).single().execute().data
        data = {
            'patient_id': enc['patient_id'],
            'prescribed_by': current_user.id,
            'diet_type': request.form.get('diet_type'),
            'instruction': request.form.get('instruction'),
            'status': 'Active',
            'start_date': datetime.utcnow().date().isoformat(),
        }
        supabase.table('diet_plans').insert(data).execute()
        flash('Diet order sent to nutrition.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('ct2.encounter_detail', encounter_id=encounter_id))


@ct2_bp.route('/encounter/<int:encounter_id>/order/surgery', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def encounter_order_surgery(encounter_id):
    supabase = get_supabase_client()
    try:
        enc = supabase.table('encounters').select('patient_id').eq('id', encounter_id).single().execute().data
        data = {
            'patient_id': enc['patient_id'],
            'surgeon_id': request.form.get('surgeon_id') or current_user.id,
            'surgery_name': request.form.get('surgery_name'),
            'surgery_date': request.form.get('surgery_date'),
            'operating_theater': request.form.get('operating_theater'),
            'notes': request.form.get('notes'),
            'status': 'Requested',
        }
        supabase.table('surgeries').insert(data).execute()
        flash('Surgery request submitted.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('ct2.encounter_detail', encounter_id=encounter_id))


# =====================================================
# PHASE 3 — LAB (LIS) FULL WORKFLOW
# =====================================================

@ct2_bp.route('/lab/order/<int:order_id>/collect-specimen', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def collect_specimen(order_id):
    import uuid as _uuid
    supabase = get_supabase_client()
    try:
        barcode = 'SPX-' + _uuid.uuid4().hex[:10].upper()
        supabase.table('lab_orders').update({
            'status': 'Specimen Collected',
            'barcode': barcode,
            'specimen_collected_at': datetime.utcnow().isoformat(),
        }).eq('id', order_id).execute()
        flash(f'Specimen collected. Barcode: {barcode}', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.lab_orders'))


@ct2_bp.route('/lab/order/<int:order_id>/register-specimen', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def register_specimen(order_id):
    supabase = get_supabase_client()
    try:
        supabase.table('lab_orders').update({
            'status': 'In Analysis',
            'specimen_registered_at': datetime.utcnow().isoformat(),
        }).eq('id', order_id).execute()
        flash('Specimen registered and sent for analysis.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.lab_orders'))


@ct2_bp.route('/lab/order/<int:order_id>/reject', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def reject_specimen(order_id):
    supabase = get_supabase_client()
    try:
        supabase.table('lab_orders').update({
            'status': 'Rejected',
            'rejection_reason': request.form.get('rejection_reason', '').strip(),
        }).eq('id', order_id).execute()
        flash('Specimen rejected.', 'warning')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.lab_orders'))


@ct2_bp.route('/lab/order/<int:order_id>/enter-results', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def enter_lab_results(order_id):
    supabase = get_supabase_client()
    try:
        result_value = request.form.get('result_value', '').strip()
        ref_range = request.form.get('result_reference_range', '').strip()
        is_critical = request.form.get('is_critical') == '1'
        upd = {
            'result_value': result_value,
            'result_unit': request.form.get('result_unit', '').strip(),
            'result_reference_range': ref_range,
            'is_critical': is_critical,
            'status': 'Awaiting Verification',
        }
        supabase.table('lab_orders').update(upd).eq('id', order_id).execute()
        if is_critical:
            # Alert the ordering physician
            row = supabase.table('lab_orders').select('patient_id, doctor_id, test_name').eq('id', order_id).single().execute().data or {}
            if row.get('doctor_id'):
                from utils.hms_models import Notification
                Notification.create(user_id=row['doctor_id'], subsystem='ct2', title='⚠ Critical Lab Result',
                                    message=f"CRITICAL result on {row.get('test_name','lab test')}: {result_value}. Immediate review required.",
                                    n_type='danger', sender_subsystem=BLUEPRINT_NAME)
        flash('Results entered. Awaiting verification.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.lab_orders'))


@ct2_bp.route('/lab/order/<int:order_id>/verify', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def verify_lab_results(order_id):
    supabase = get_supabase_client()
    try:
        supabase.table('lab_orders').update({
            'status': 'Verified',
            'verified_by': current_user.id,
            'verified_at': datetime.utcnow().isoformat(),
        }).eq('id', order_id).execute()
        # Push to result_inbox
        row = supabase.table('lab_orders').select('patient_id, doctor_id, test_name, result_value, is_critical').eq('id', order_id).single().execute().data or {}
        try:
            supabase.table('result_inbox').insert({
                'patient_id': row.get('patient_id'),
                'physician_id': row.get('doctor_id'),
                'source_module': 'Lab',
                'source_record_id': order_id,
                'summary': f"{row.get('test_name','')} — {row.get('result_value','')}",
                'is_critical': row.get('is_critical', False),
            }).execute()
        except Exception: pass
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, 'Verify Lab Result', BLUEPRINT_NAME, {'order_id': order_id})
        flash('Lab result verified and sent to results inbox.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.lab_orders'))


@ct2_bp.route('/lab/worklist')
@login_required
@policy_required(BLUEPRINT_NAME)
def lab_worklist():
    supabase = get_supabase_client()
    try:
        orders = supabase.table('lab_orders').select('*, patients(first_name, last_name, patient_id_alt)')\
            .not_.in_('status', ['Verified', 'Rejected'])\
            .order('created_at').execute().data or []
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        orders = []
    return render_template('subsystems/core_transaction/ct2/lab_orders.html',
                           orders=orders, patients=[], doctors=[],
                           worklist_mode=True,
                           subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)


# =====================================================
# PHASE 4 — RADIOLOGY (RIS) FULL WORKFLOW
# =====================================================

@ct2_bp.route('/radiology/order/<int:order_id>/schedule', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def schedule_radiology(order_id):
    supabase = get_supabase_client()
    try:
        supabase.table('radiology_orders').update({
            'status': 'Scheduled',
            'scheduled_at': request.form.get('scheduled_at'),
            'patient_prep_status': 'Pending',
        }).eq('id', order_id).execute()
        flash('Imaging appointment scheduled.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.radiology_orders'))


@ct2_bp.route('/radiology/order/<int:order_id>/imaging-done', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def radiology_imaging_done(order_id):
    supabase = get_supabase_client()
    try:
        supabase.table('radiology_orders').update({
            'status': 'Interpretation',
            'imaging_completed_at': datetime.utcnow().isoformat(),
            'patient_prep_status': 'Done',
        }).eq('id', order_id).execute()
        flash('Imaging completed. Sent to interpretation queue.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.radiology_orders'))


@ct2_bp.route('/radiology/order/<int:order_id>/interpret', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def radiology_interpret(order_id):
    supabase = get_supabase_client()
    try:
        is_critical = request.form.get('is_critical') == '1'
        upd = {
            'findings': request.form.get('findings', '').strip(),
            'report_text': request.form.get('report_text', '').strip(),
            'is_critical': is_critical,
            'critical_findings': request.form.get('critical_findings', '').strip() if is_critical else None,
            'interpreter_id': current_user.id,
            'status': 'Report Validated',
        }
        supabase.table('radiology_orders').update(upd).eq('id', order_id).execute()
        # Push to result_inbox
        row = supabase.table('radiology_orders').select('patient_id, doctor_id, imaging_type').eq('id', order_id).single().execute().data or {}
        try:
            supabase.table('result_inbox').insert({
                'patient_id': row.get('patient_id'),
                'physician_id': row.get('doctor_id'),
                'source_module': 'Radiology',
                'source_record_id': order_id,
                'summary': f"{row.get('imaging_type','')} — {upd['findings'][:100]}",
                'is_critical': is_critical,
            }).execute()
        except Exception: pass
        if is_critical and row.get('doctor_id'):
            from utils.hms_models import Notification
            Notification.create(user_id=row['doctor_id'], subsystem='ct2', title='⚠ Critical Radiology Finding',
                                message=f"Critical finding on {row.get('imaging_type','imaging')}: {upd['critical_findings']}",
                                n_type='danger', sender_subsystem=BLUEPRINT_NAME)
        flash('Radiology report completed and sent to physician inbox.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.radiology_orders'))


@ct2_bp.route('/radiology/worklist')
@login_required
@policy_required(BLUEPRINT_NAME)
def radiology_worklist():
    supabase = get_supabase_client()
    try:
        orders = supabase.table('radiology_orders').select('*, patients(first_name, last_name, patient_id_alt)')\
            .not_.in_('status', ['Report Validated', 'Completed', 'Cancelled'])\
            .order('created_at').execute().data or []
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        orders = []
    return render_template('subsystems/core_transaction/ct2/radiology_orders.html',
                           orders=orders, patients=[], doctors=[],
                           worklist_mode=True,
                           subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)


# =====================================================
# PHASE 5 — PHARMACY (PMS) FULL WORKFLOW
# =====================================================

@ct2_bp.route('/pharmacy/order/<int:rx_id>/safety-check', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def pharmacy_safety_check(rx_id):
    supabase = get_supabase_client()
    try:
        flag_reason = request.form.get('flag_reason', '').strip()
        is_safe = not flag_reason
        upd = {
            'safety_check_status': 'Safe' if is_safe else 'Flagged',
            'safety_flag_reason': flag_reason if not is_safe else None,
            'status': 'Pending' if not is_safe else 'Verified',
        }
        supabase.table('prescriptions').update(upd).eq('id', rx_id).execute()
        if not is_safe:
            row = supabase.table('prescriptions').select('doctor_id, medication_name').eq('id', rx_id).single().execute().data or {}
            if row.get('doctor_id'):
                from utils.hms_models import Notification
                Notification.create(user_id=row['doctor_id'], subsystem='ct2',
                                    title='Medication Safety Alert',
                                    message=f"Rx for {row.get('medication_name','')} flagged: {flag_reason}",
                                    n_type='warning', sender_subsystem=BLUEPRINT_NAME)
            flash(f'Medication flagged as unsafe: {flag_reason}', 'warning')
        else:
            flash('Safety check passed. Prescription verified.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.dispense_meds'))


@ct2_bp.route('/pharmacy/order/<int:rx_id>/dispense-rx', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def dispense_prescription(rx_id):
    supabase = get_supabase_client()
    try:
        rx = supabase.table('prescriptions').select('*').eq('id', rx_id).single().execute().data
        if not rx:
            flash('Prescription not found.', 'danger')
            return redirect(url_for('ct2.dispense_meds'))
        med_name = rx.get('medication_name', '')
        qty = int(rx.get('quantity') or 1)
        # Deduct inventory
        inv = supabase.table('inventory').select('id, quantity').eq('item_name', med_name).eq('category', 'Medical').execute().data
        if inv:
            new_qty = max(0, inv[0]['quantity'] - qty)
            supabase.table('inventory').update({'quantity': new_qty}).eq('id', inv[0]['id']).execute()
        supabase.table('prescriptions').update({
            'status': 'Dispensed',
            'dispensed_at': datetime.utcnow().isoformat(),
            'dispensed_by': current_user.id,
        }).eq('id', rx_id).execute()
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, 'Dispense Prescription', BLUEPRINT_NAME, {'rx_id': rx_id, 'medication': med_name})
        flash(f'Prescription #{rx_id} ({med_name}) dispensed.', 'success')
    except Exception as e:
        flash(f'Dispense error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.dispense_meds'))


@ct2_bp.route('/pharmacy/worklist')
@login_required
@policy_required(BLUEPRINT_NAME)
def pharmacy_worklist():
    supabase = get_supabase_client()
    try:
        pending = supabase.table('prescriptions')\
            .select('*, patients(first_name, last_name, patient_id_alt), users!prescriptions_doctor_id_fkey(username)')\
            .in_('status', ['Pending', 'Verified'])\
            .order('created_at').execute().data or []
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        pending = []
    return render_template('subsystems/core_transaction/ct2/dispense_meds.html',
                           patients=[], medications=[], pending_prescriptions=pending,
                           worklist_mode=True,
                           subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)


# =====================================================
# PHASE 6 — DIET / NUTRITION (DNMS) FULL WORKFLOW
# =====================================================

@ct2_bp.route('/dnms/diet-plans/<int:plan_id>/approve', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def approve_diet_plan(plan_id):
    supabase = get_supabase_client()
    try:
        supabase.table('diet_plans').update({
            'approved_by': current_user.id,
            'approved_at': datetime.utcnow().isoformat(),
            'status': 'Active',
        }).eq('id', plan_id).execute()
        flash('Diet plan approved.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.list_diet_plans'))


@ct2_bp.route('/dnms/meal-tracking/<int:meal_id>/deliver', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def deliver_meal(meal_id):
    supabase = get_supabase_client()
    try:
        supabase.table('meal_tracking').update({
            'delivery_status': 'Delivered',
            'delivered_at': datetime.utcnow().isoformat(),
            'delivery_staff_id': current_user.id,
        }).eq('id', meal_id).execute()
        flash('Meal marked as delivered.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.meal_tracking'))


@ct2_bp.route('/dnms/meal-tracking/<int:meal_id>/intake', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def record_meal_intake(meal_id):
    supabase = get_supabase_client()
    try:
        pct = int(request.form.get('intake_percentage', 0))
        upd = {'intake_percentage': pct, 'delivery_status': 'Consumed'}
        if pct < 50:
            upd['intake_exception_reason'] = request.form.get('intake_exception_reason', 'Low intake')
        supabase.table('meal_tracking').update(upd).eq('id', meal_id).execute()
        flash('Intake recorded.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.meal_tracking'))


@ct2_bp.route('/dnms/worklist')
@login_required
@policy_required(BLUEPRINT_NAME)
def dnms_worklist():
    supabase = get_supabase_client()
    try:
        pending_assessments = supabase.table('nutritional_assessments').select('*, patients(first_name, last_name, patient_id_alt)').order('created_at', desc=True).limit(20).execute().data or []
        pending_meals = supabase.table('meal_tracking').select('*, patients(first_name, last_name, patient_id_alt)').eq('delivery_status', 'Pending').order('created_at').execute().data or []
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        pending_assessments, pending_meals = [], []
    return render_template('subsystems/core_transaction/ct2/dnms_dashboard.html',
                           diet_plans=[], pending_meals=pending_meals,
                           recent_assessments=pending_assessments,
                           stats={}, worklist_mode=True,
                           subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)


# =====================================================
# PHASE 7 — SURGERY / OR (SORS) FULL WORKFLOW
# =====================================================

@ct2_bp.route('/surgery/<int:surgery_id>/preop-assessment', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def surgery_preop(surgery_id):
    supabase = get_supabase_client()
    try:
        supabase.table('surgeries').update({
            'preop_cleared': request.form.get('cleared') == '1',
            'preop_notes': request.form.get('preop_notes', '').strip(),
            'status': 'Pre-Op Cleared' if request.form.get('cleared') == '1' else 'Pre-Op Pending',
        }).eq('id', surgery_id).execute()
        flash('Pre-op assessment recorded.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.surgery_schedule'))


@ct2_bp.route('/surgery/<int:surgery_id>/start', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def surgery_start(surgery_id):
    supabase = get_supabase_client()
    try:
        supabase.table('surgeries').update({
            'status': 'In Progress',
            'started_at': datetime.utcnow().isoformat(),
        }).eq('id', surgery_id).execute()
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, 'Surgery Started', BLUEPRINT_NAME, {'surgery_id': surgery_id})
        flash('Surgery marked as In Progress.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.surgery_schedule'))


@ct2_bp.route('/surgery/<int:surgery_id>/complete', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def surgery_complete(surgery_id):
    supabase = get_supabase_client()
    try:
        supabase.table('surgeries').update({
            'status': 'Completed',
            'ended_at': datetime.utcnow().isoformat(),
            'intraop_notes': request.form.get('intraop_notes', '').strip(),
            'postop_status': 'Recovery',
            'recovery_location': request.form.get('recovery_location', '').strip(),
        }).eq('id', surgery_id).execute()
        # Push to result_inbox
        row = supabase.table('surgeries').select('patient_id, surgeon_id, surgery_name').eq('id', surgery_id).single().execute().data or {}
        try:
            supabase.table('result_inbox').insert({
                'patient_id': row.get('patient_id'),
                'physician_id': row.get('surgeon_id'),
                'source_module': 'Surgery',
                'source_record_id': surgery_id,
                'summary': f"Surgery completed: {row.get('surgery_name','')}",
                'is_critical': False,
            }).execute()
        except Exception: pass
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, 'Surgery Completed', BLUEPRINT_NAME, {'surgery_id': surgery_id})
        flash('Surgery completed. Patient transferred to recovery.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.surgery_schedule'))


@ct2_bp.route('/surgery/<int:surgery_id>/postop-update', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def surgery_postop(surgery_id):
    supabase = get_supabase_client()
    try:
        supabase.table('surgeries').update({
            'postop_status': request.form.get('postop_status'),
            'recovery_location': request.form.get('recovery_location', ''),
            'notes': request.form.get('notes', ''),
        }).eq('id', surgery_id).execute()
        flash('Post-op status updated.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.surgery_schedule'))


@ct2_bp.route('/surgery/or-board')
@login_required
@policy_required(BLUEPRINT_NAME)
def or_board():
    supabase = get_supabase_client()
    try:
        active = supabase.table('surgeries').select('*, patients(first_name, last_name), users(username, full_name)')\
            .in_('status', ['Pre-Op Cleared', 'Scheduled', 'In Progress', 'Post-Op Pending', 'Recovery'])\
            .order('surgery_date').execute().data or []
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        active = []
    doctors = []
    try:
        doctors = supabase.table('users').select('id, username, full_name').in_('subsystem', ['ct2', 'ct3']).execute().data or []
    except Exception: pass
    return render_template('subsystems/core_transaction/ct2/surgery_schedule.html',
                           surgeries=active, patients=[], surgeons=doctors,
                           or_board_mode=True,
                           subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR, blueprint_name=BLUEPRINT_NAME)


# =====================================================
# PHASE 8 — RESULTS & REPORTS INBOX
# =====================================================

@ct2_bp.route('/inbox')
@login_required
@policy_required(BLUEPRINT_NAME)
def results_inbox():
    supabase = get_supabase_client()
    critical_only = request.args.get('critical') == '1'
    module_filter = request.args.get('module', '')
    try:
        q = supabase.table('result_inbox')\
            .select('*, patients(first_name, last_name, patient_id_alt), encounters(status, chief_complaint)')
        if critical_only:
            q = q.eq('is_critical', True)
        if module_filter:
            q = q.eq('source_module', module_filter)
        items = q.order('created_at', desc=True).execute().data or []
    except Exception as e:
        flash(f'Error loading inbox: {str(e)}', 'danger')
        items = []
    unread = sum(1 for i in items if not i.get('acknowledged'))
    modules = ['Lab', 'Radiology', 'Surgery', 'Pharmacy']
    return render_template('subsystems/core_transaction/ct2/results_inbox.html',
                           inbox=items,
                           unread=unread,
                           critical_only=critical_only,
                           module_filter=module_filter,
                           modules=modules,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@ct2_bp.route('/inbox/<int:item_id>/acknowledge', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def acknowledge_result(item_id):
    supabase = get_supabase_client()
    try:
        supabase.table('result_inbox').update({
            'acknowledged': True,
            'acknowledged_at': datetime.utcnow().isoformat(),
        }).eq('id', item_id).execute()
        flash('Result acknowledged.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('ct2.results_inbox'))


@ct2_bp.route('/inbox/acknowledge-all', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def acknowledge_all_results():
    supabase = get_supabase_client()
    try:
        supabase.table('result_inbox').update({
            'acknowledged': True,
            'acknowledged_at': datetime.utcnow().isoformat(),
        }).eq('acknowledged', False).execute()
        flash('All results marked as acknowledged.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('ct2.results_inbox'))


# =====================================================
# PHASE 9 — BILLING / CHARGE AGGREGATION
# =====================================================

@ct2_bp.route('/billing/charges')
@login_required
@policy_required(BLUEPRINT_NAME)
def billing_charges():
    supabase = get_supabase_client()
    try:
        charges = supabase.table('invoices').select('*, patients(first_name, last_name, patient_id_alt)')\
            .order('issued_at', desc=True).limit(100).execute().data or []
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        charges = []
    by_dept = {}
    for c in charges:
        dept = c.get('invoice_type', 'Other')
        by_dept.setdefault(dept, []).append(c)
    return render_template('subsystems/core_transaction/ct2/billing_charges.html',
                           charges=charges,
                           by_dept=by_dept,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


# =====================================================
# PHASE 10 — ALERT CENTER
# =====================================================

@ct2_bp.route('/alerts')
@login_required
@policy_required(BLUEPRINT_NAME)
def alert_center():
    supabase = get_supabase_client()
    alerts = []
    # Critical unacknowledged lab results
    try:
        lab_crits = supabase.table('lab_orders').select('id, test_name, result_value, status, is_critical, patients(first_name, last_name)')\
            .eq('is_critical', True).neq('status', 'Verified').execute().data or []
        for r in lab_crits:
            alerts.append({'type': 'Lab', 'level': 'danger', 'patient': r.get('patients'),
                           'msg': f"Critical lab result: {r.get('test_name','')} — {r.get('result_value','pending')}",
                           'id': r['id'], 'action_url': url_for('ct2.lab_orders')})
    except Exception: pass
    # Critical radiology
    try:
        rad_crits = supabase.table('radiology_orders').select('id, imaging_type, critical_findings, patients(first_name, last_name)')\
            .eq('is_critical', True).execute().data or []
        for r in rad_crits:
            alerts.append({'type': 'Radiology', 'level': 'danger', 'patient': r.get('patients'),
                           'msg': f"Critical imaging: {r.get('imaging_type','')} — {r.get('critical_findings','see report')}",
                           'id': r['id'], 'action_url': url_for('ct2.radiology_orders')})
    except Exception: pass
    # Safety-flagged prescriptions
    try:
        rx_flags = supabase.table('prescriptions').select('id, medication_name, safety_flag_reason, patients(first_name, last_name)')\
            .eq('safety_check_status', 'Flagged').execute().data or []
        for r in rx_flags:
            alerts.append({'type': 'Pharmacy', 'level': 'warning', 'patient': r.get('patients'),
                           'msg': f"Safety flag on {r.get('medication_name','')} — {r.get('safety_flag_reason','review required')}",
                           'id': r['id'], 'action_url': url_for('ct2.dispense_meds')})
    except Exception: pass
    # Unacknowledged critical inbox items
    try:
        inbox_crits = supabase.table('result_inbox').select('id, source_module, summary, patients(first_name, last_name)')\
            .eq('is_critical', True).eq('acknowledged', False).execute().data or []
        for r in inbox_crits:
            alerts.append({'type': r.get('source_module', 'Result'), 'level': 'danger', 'patient': r.get('patients'),
                           'msg': r.get('summary', ''), 'id': r['id'],
                           'action_url': url_for('ct2.results_inbox', critical='1')})
    except Exception: pass
    # Overdue / stuck surgeries (Scheduled but past surgery_date)
    try:
        today_iso = datetime.utcnow().date().isoformat()
        overdue_surg = supabase.table('surgeries').select('id, surgery_name, surgery_date, patients(first_name, last_name)')\
            .in_('status', ['Scheduled', 'Requested']).lt('surgery_date', today_iso).execute().data or []
        for r in overdue_surg:
            alerts.append({'type': 'Surgery', 'level': 'warning', 'patient': r.get('patients'),
                           'msg': f"Overdue surgery: {r.get('surgery_name','')} (scheduled {(r.get('surgery_date') or '')[:10]})",
                           'id': r['id'], 'action_url': url_for('ct2.surgery_schedule')})
    except Exception: pass
    # Low stock medications (qty < 10)
    try:
        low_stock = supabase.table('inventory').select('id, item_name, quantity')\
            .eq('category', 'Medical').lt('quantity', 10).gt('quantity', 0).execute().data or []
        for r in low_stock:
            alerts.append({'type': 'Inventory', 'level': 'warning', 'patient': None,
                           'msg': f"Low stock: {r.get('item_name','')} — only {r.get('quantity',0)} units remaining",
                           'id': r['id'], 'action_url': url_for('ct2.pharmacy_inventory')})
    except Exception: pass
    # Out-of-stock medications (qty == 0)
    try:
        no_stock = supabase.table('inventory').select('id, item_name, quantity')\
            .eq('category', 'Medical').eq('quantity', 0).execute().data or []
        for r in no_stock:
            alerts.append({'type': 'Inventory', 'level': 'danger', 'patient': None,
                           'msg': f"Out of stock: {r.get('item_name','')} — 0 units",
                           'id': r['id'], 'action_url': url_for('ct2.pharmacy_inventory')})
    except Exception: pass

    # Sort: danger first, then warning
    alerts.sort(key=lambda a: 0 if a['level'] == 'danger' else 1)

    counts = {
        'danger': sum(1 for a in alerts if a['level'] == 'danger'),
        'warning': sum(1 for a in alerts if a['level'] == 'warning'),
    }

    return render_template('subsystems/core_transaction/ct2/alert_center.html',
                           alerts=alerts,
                           counts=counts,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


