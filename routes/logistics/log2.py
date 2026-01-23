from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from datetime import datetime

log2_bp = Blueprint('log2', __name__, template_folder='templates')

# Subsystem configuration
SUBSYSTEM_NAME = 'LOG2 - Fleet Operations'
ACCENT_COLOR = '#F97316'
BLUEPRINT_NAME = 'log2'

@log2_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/logistics/log2/login.html', remaining_seconds=remaining_seconds)
    
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
                    return redirect(url_for('log2.change_password'))

                # Check if account is approved
                if user.status != 'Active':
                    if user.status == 'Pending':
                        flash('Your account is awaiting approval from HR3 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('subsystems/logistics/log2/login.html')

                # Clear IP lockout attempts on successful login
                register_successful_login()
                user.register_successful_login()
                
                if login_user(user):
                    days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                    if days_left <= 7:
                        flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    return redirect(url_for('log2.dashboard'))
                else:
                    flash('Login failed. Your account may be deactivated.', 'danger')
                    return render_template('subsystems/logistics/log2/login.html')
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/logistics/log2/login.html', remaining_seconds=remaining_seconds)
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
                return render_template('subsystems/logistics/log2/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/logistics/log2/login.html')

@log2_bp.route('/register', methods=['GET', 'POST'])
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
                department='LOGISTICS',
                status='Pending'
            )
            
            if new_user:
                flash('Registration successful! Your account is awaiting approval from HR3 Admin.', 'success')
                return redirect(url_for('log2.login'))
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
                           hub_route='portal.logistics_hub',
                           accent_color=ACCENT_COLOR)

@log2_bp.route('/change-password', methods=['GET', 'POST'])
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
            return redirect(url_for('log2.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('log2.login'))
    
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
            return redirect(url_for('log2.login'))
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html',
        subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@log2_bp.route('/dashboard')
@login_required
def dashboard():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Get counts from database
        v_resp = client.table('fleet_vehicles').select('status').execute()
        vehicles = v_resp.data if v_resp.data else []
        available_vehicles = len([v for v in vehicles if v.get('status') == 'Available'])
        
        d_resp = client.table('fleet_dispatch').select('status').eq('status', 'On Trip').execute()
        active_trips = len(d_resp.data) if d_resp.data else 0
        
        dr_resp = client.table('drivers').select('id').execute()
        total_drivers = len(dr_resp.data) if dr_resp.data else 0
        
    except Exception as e:
        print(f"Dashboard Stats Error: {e}")
        available_vehicles = 0
        active_trips = 0
        total_drivers = 0
        
    return render_template('subsystems/logistics/log2/dashboard.html',
                           available_vehicles=available_vehicles,
                           active_trips=active_trips,
                           total_drivers=total_drivers,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log2_bp.route('/vehicles')
@login_required
def list_vehicles():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    # Sort by ID descending as a safe alternative to created_at
    vehicles = client.table('fleet_vehicles').select('*').order('id', desc=True).execute()
    return render_template('subsystems/logistics/log2/vehicles.html',
                           vehicles=vehicles.data if vehicles.data else [],
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log2_bp.route('/vehicles/add', methods=['POST'])
@login_required
def add_vehicle():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        v_data = {
            'plate_number': request.form.get('plate_number'),
            'model_name': request.form.get('model_name'),
            'vehicle_type': request.form.get('vehicle_type'),
            'status': 'Available'
        }
        client.table('fleet_vehicles').insert(v_data).execute()
        flash('Vehicle added to fleet.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('log2.list_vehicles'))

@log2_bp.route('/vehicles/edit/<int:vehicle_id>', methods=['POST'])
@login_required
def edit_vehicle(vehicle_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        v_data = {
            'plate_number': request.form.get('plate_number'),
            'model_name': request.form.get('model_name'),
            'vehicle_type': request.form.get('vehicle_type'),
            'status': request.form.get('status')
        }
        client.table('fleet_vehicles').update(v_data).eq('id', vehicle_id).execute()
        flash('Vehicle updated successfully.', 'success')
    except Exception as e:
        flash(f'Update failed: {str(e)}', 'danger')
    return redirect(url_for('log2.list_vehicles'))

@log2_bp.route('/vehicles/delete/<int:vehicle_id>', methods=['POST'])
@login_required
def delete_vehicle(vehicle_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        client.table('fleet_vehicles').delete().eq('id', vehicle_id).execute()
        flash('Vehicle removed from fleet.', 'info')
    except Exception as e:
        flash(f'Delete failed: {str(e)}', 'danger')
    return redirect(url_for('log2.list_vehicles'))

@log2_bp.route('/dispatch')
@login_required
def dispatch_board():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch data separately and link in Python for maximum reliability
    try:
        # 1. Fetch Dispatches
        d_resp = client.table('fleet_dispatch').select('*').neq('status', 'Cancelled').order('departure_time', desc=True).execute()
        raw_dispatches = d_resp.data if d_resp.data else []
        
        # 2. Fetch All Vehicles and Drivers for linking
        v_resp = client.table('fleet_vehicles').select('*').execute()
        dr_resp = client.table('drivers').select('*').execute()
        
        vehicles_all = v_resp.data if v_resp.data else []
        drivers_all = dr_resp.data if dr_resp.data else []
        
        # Create lookup maps
        v_map = {str(v['id']): v for v in vehicles_all}
        dr_map = {str(d['id']): d for d in drivers_all}
        
        processed_trips = []
        for trip in raw_dispatches:
            v_id = str(trip.get('vehicle_id'))
            d_id = str(trip.get('driver_id'))
            
            v_info = v_map.get(v_id, {})
            d_info = dr_map.get(d_id, {})
            
            processed_trips.append({
                'id': trip['id'],
                'license_plate': v_info.get('plate_number', 'N/A'),
                'make': v_info.get('vehicle_type', 'Fleet'),
                'model': v_info.get('model_name', 'Vehicle'),
                'driver_name': d_info.get('full_name', 'Unknown'),
                'destination': trip.get('destination', 'N/A'),
                'departure_time': trip.get('departure_time'),
                'arrival_time': trip.get('return_time'),
                'status': trip.get('status', 'Unknown')
            })
            
        # 3. Filter available resources for the dropdowns
        # We'll be more lenient with the status check
        def is_available(status):
            if not status: return True
            return status.lower() in ['available', 'active', 'ready']
            
        available_vehicles = [v for v in vehicles_all if is_available(v.get('status'))]
        available_drivers = [d for d in drivers_all if is_available(d.get('status'))]
        
    except Exception as e:
        print(f"Dispatch Board Data Error: {e}")
        processed_trips = []
        available_vehicles = []
        available_drivers = []
    
    return render_template('subsystems/logistics/log2/dispatch.html',
                           dispatches=processed_trips,
                           available_vehicles_list=available_vehicles,
                           available_drivers_list=available_drivers,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log2_bp.route('/dispatch/create', methods=['POST'])
@login_required
def create_dispatch():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        v_id = request.form.get('vehicle_id')
        d_id = request.form.get('driver_id')
        
        dispatch_data = {
            'vehicle_id': v_id,
            'driver_id': d_id,
            'destination': request.form.get('destination'),
            'purpose': request.form.get('purpose'),
            'status': 'On Trip',
            'logged_by': current_user.id
        }
        client.table('fleet_dispatch').insert(dispatch_data).execute()
        # Update statuses
        client.table('fleet_vehicles').update({'status': 'In Use'}).eq('id', v_id).execute()
        client.table('drivers').update({'status': 'On Trip'}).eq('id', d_id).execute()
        
        flash('Vehicle dispatched successfully.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('log2.dispatch_board'))

@log2_bp.route('/dispatch/complete', methods=['POST'])
@login_required
def complete_dispatch():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        dispatch_id = request.form.get('dispatch_id')
        # Get trip details to release resources
        trip = client.table('fleet_dispatch').select('vehicle_id, driver_id').eq('id', dispatch_id).single().execute()
        if trip.data:
            client.table('fleet_dispatch').update({
                'status': 'Completed',
                'return_time': datetime.utcnow().isoformat()
            }).eq('id', dispatch_id).execute()
            
            client.table('fleet_vehicles').update({'status': 'Available'}).eq('id', trip.data['vehicle_id']).execute()
            client.table('drivers').update({'status': 'Active'}).eq('id', trip.data['driver_id']).execute()
            
            flash('Trip marked as completed.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('log2.dispatch_board'))

@log2_bp.route('/dispatch/cancel', methods=['POST'])
@login_required
def cancel_dispatch():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        dispatch_id = request.form.get('dispatch_id')
        trip = client.table('fleet_dispatch').select('vehicle_id, driver_id').eq('id', dispatch_id).single().execute()
        
        if trip.data:
            client.table('fleet_dispatch').update({'status': 'Cancelled'}).eq('id', dispatch_id).execute()
            client.table('fleet_vehicles').update({'status': 'Available'}).eq('id', trip.data['vehicle_id']).execute()
            client.table('drivers').update({'status': 'Active'}).eq('id', trip.data['driver_id']).execute()
            flash('Dispatch cancelled.', 'info')
    except Exception as e:
        flash(f'Cancel failed: {str(e)}', 'danger')
    return redirect(url_for('log2.dispatch_board'))

@log2_bp.route('/costs')
@login_required
def cost_analysis():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch costs with vehicle info
    costs_resp = client.table('fleet_costs').select('*, fleet_vehicles(plate_number)').order('log_date', desc=True).execute()
    raw_costs = costs_resp.data if costs_resp.data else []
    
    # Process costs for table
    processed_costs = []
    total_costs = 0
    fuel_costs = 0
    maint_costs = 0
    
    for c in raw_costs:
        amount = float(c.get('amount') or 0)
        total_costs += amount
        
        if c.get('cost_type') == 'Fuel':
            fuel_costs += amount
        elif c.get('cost_type') in ['Maintenance', 'Repair']:
            maint_costs += amount
            
        processed_costs.append({
            'id': c['id'],
            'log_date': c.get('log_date'),
            'license_plate': c['fleet_vehicles']['plate_number'] if c.get('fleet_vehicles') else 'N/A',
            'cost_type': c.get('cost_type'),
            'amount': amount,
            'description': c.get('description')
        })
    
    # Fetch vehicles for the dropdown
    v_resp = client.table('fleet_vehicles').select('id, plate_number, model_name, vehicle_type').execute()
    vehicles = v_resp.data if v_resp.data else []
    
    return render_template('subsystems/logistics/log2/costs.html',
                           costs=processed_costs,
                           total_costs=total_costs,
                           fuel_costs=fuel_costs,
                           maint_costs=maint_costs,
                           vehicles=vehicles,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log2_bp.route('/costs/add', methods=['POST'])
@login_required
def add_cost():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        cost_data = {
            'vehicle_id': request.form.get('vehicle_id'),
            'cost_type': request.form.get('cost_type'),
            'amount': request.form.get('amount'),
            'description': request.form.get('description'),
            'logged_by': current_user.id
        }
        client.table('fleet_costs').insert(cost_data).execute()
        flash('Expense logged successfully.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('log2.cost_analysis'))

@log2_bp.route('/costs/delete/<int:cost_id>', methods=['POST'])
@login_required
def delete_cost(cost_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        client.table('fleet_costs').delete().eq('id', cost_id).execute()
        flash('Transaction voided.', 'info')
    except Exception as e:
        flash(f'Delete failed: {str(e)}', 'danger')
    return redirect(url_for('log2.cost_analysis'))

@log2_bp.route('/costs/export')
@login_required
def export_costs():
    from utils.supabase_client import get_supabase_client
    import csv
    import io
    from flask import Response
    
    client = get_supabase_client()
    costs_resp = client.table('fleet_costs').select('*, fleet_vehicles(plate_number)').execute()
    costs = costs_resp.data if costs_resp.data else []
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Vehicle', 'Category', 'Amount', 'Description'])
    
    for c in costs:
        writer.writerow([
            c.get('log_date'),
            c['fleet_vehicles']['plate_number'] if c.get('fleet_vehicles') else 'N/A',
            c.get('cost_type'),
            c.get('amount'),
            c.get('description')
        ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=fleet_costs.csv"}
    )

@log2_bp.route('/drivers')
@login_required
def list_drivers():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    drivers_resp = client.table('drivers').select('*').order('full_name').execute()
    drivers = drivers_resp.data if drivers_resp.data else []
    
    # Calculate stats
    total_drivers = len(drivers)
    available_drivers = len([d for d in drivers if d.get('status') == 'Active'])
    on_trip_drivers = len([d for d in drivers if d.get('status') == 'On Trip'])
    
    return render_template('subsystems/logistics/log2/drivers.html',
                           drivers=drivers,
                           total_drivers=total_drivers,
                           available_drivers=available_drivers,
                           on_trip_drivers=on_trip_drivers,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log2_bp.route('/drivers/add', methods=['POST'])
@login_required
def add_driver():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        dr_data = {
            'full_name': request.form.get('full_name'),
            'license_number': request.form.get('license_number'),
            'phone': request.form.get('phone'),
            'status': 'Active'
        }
        client.table('drivers').insert(dr_data).execute()
        flash('Driver added successfully.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('log2.list_drivers'))

@log2_bp.route('/drivers/edit/<int:driver_id>', methods=['POST'])
@login_required
def edit_driver(driver_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        dr_data = {
            'full_name': request.form.get('full_name'),
            'license_number': request.form.get('license_number'),
            'phone': request.form.get('phone'),
            'status': request.form.get('status')
        }
        client.table('drivers').update(dr_data).eq('id', driver_id).execute()
        flash('Driver updated.', 'success')
    except Exception as e:
        flash(f'Update failed: {str(e)}', 'danger')
    return redirect(url_for('log2.list_drivers'))

@log2_bp.route('/drivers/delete/<int:driver_id>', methods=['POST'])
@login_required
def delete_driver(driver_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        # Check if driver is on a trip
        driver = client.table('drivers').select('status').eq('id', driver_id).single().execute()
        if driver.data and driver.data.get('status') == 'On Trip':
            flash('Cannot delete a driver who is currently on a trip.', 'warning')
            return redirect(url_for('log2.list_drivers'))

        client.table('drivers').delete().eq('id', driver_id).execute()
        flash('Driver removed.', 'info')
    except Exception as e:
        flash(f'Delete failed: {str(e)}', 'danger')
    return redirect(url_for('log2.list_drivers'))

@log2_bp.route('/settings', methods=['GET', 'POST'])
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

@log2_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('log2.login'))

