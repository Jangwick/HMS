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
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('shared/login.html', 
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
                        flash('Your account is awaiting approval from HR3 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('shared/login.html',
                                           subsystem_name=SUBSYSTEM_NAME,
                                           accent_color=ACCENT_COLOR,
                                           subsystem_icon=SUBSYSTEM_ICON,
                                           blueprint_name=BLUEPRINT_NAME,
                                           hub_route='portal.ct_hub')

                # Clear IP lockout attempts on successful login
                register_successful_login()
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
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
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
            is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
            
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

@ct2_bp.route('/register', methods=['GET', 'POST'])
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
                department='CORE_TRANSACTION',
                status='Pending'
            )
            
            if new_user:
                flash('Registration successful! Your account is awaiting approval from HR3 Admin.', 'success')
                return redirect(url_for('ct2.login'))
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
                           hub_route='portal.ct_hub',
                           accent_color=ACCENT_COLOR)

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
        'critical_count': 0
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
                     
        flash('Lab order updated.', 'success')
    except Exception as e:
        flash(f'Update failed: {str(e)}', 'danger')
    return redirect(url_for('ct2.lab_orders'))


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
    from utils.hms_models import InventoryItem
    try:
        data = {
            'quantity': int(request.form.get('quantity')),
            'reorder_level': int(request.form.get('reorder_level')),
            'expiry_date': request.form.get('expiry_date')
        }
        InventoryItem.update(item_id, data)
        flash('Inventory updated.', 'success')
    except Exception as e:
        flash(f'Update failed: {str(e)}', 'danger')
    return redirect(url_for('ct2.pharmacy_inventory'))

@ct2_bp.route('/pharmacy/item/<int:item_id>/delete', methods=['POST'])
@login_required
def delete_pharmacy_item(item_id):
    from utils.hms_models import InventoryItem
    try:
        InventoryItem.delete(item_id)
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
