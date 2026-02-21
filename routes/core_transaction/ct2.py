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
                other_user = User.get_by_username(username)
                if other_user:
                    sub = other_user.subsystem.upper()
                    flash(f'Account found in {sub} department. Please log in through the correct portal.', 'warning')
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
                target_url=url_for('patient.dashboard')
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
        response = client.table('prescriptions').select('*, patients(*), users(*)').eq('status', 'Dispensed').order('created_at', desc=True).execute()
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
                    target_url=url_for('patient.dashboard')
                )
            
            return redirect(url_for('ct2.pharmacy_inventory'))
            
        except Exception as e:
            flash(f'Dispensing error: {str(e)}', 'danger')
    
    # GET request
    patients = Patient.get_all()
    meds = client.table('inventory').select('*').eq('category', 'Medical').gt('quantity', 0).execute().data or []
    
    # Fetch pending prescriptions with patient details
    pending_prescriptions = client.table('prescriptions')\
        .select('*, patients(first_name, last_name, patient_id_alt), users(username)')\
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


