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
        # Get active vehicles
        v_resp = client.table('fleet_vehicles').select('id', count='exact').eq('status', 'Available').execute()
        available_vehicles = v_resp.count or 0
        
        # Get active dispatches
        d_resp = client.table('fleet_dispatch').select('id', count='exact').eq('status', 'Active').execute()
        active_trips = d_resp.count or 0
        
        # Get total drivers
        dr_resp = client.table('drivers').select('id', count='exact').eq('status', 'Active').execute()
        total_drivers = dr_resp.count or 0
        
    except Exception as e:
        print(f"Error fetching stats: {e}")
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
    # Active trips
    # Note: Using * for all columns in fleet_dispatch and sub-selects for vehicles/drivers
    active = client.table('fleet_dispatch').select('*, fleet_vehicles(plate_number, model_name, vehicle_type), drivers(full_name)').neq('status', 'Cancelled').order('departure_time', desc=True).execute()
    
    processed_trips = []
    for trip in (active.data or []):
        processed_trips.append({
            'id': trip['id'],
            'license_plate': trip['fleet_vehicles']['plate_number'] if trip.get('fleet_vehicles') else 'N/A',
            'make': trip['fleet_vehicles']['vehicle_type'] if trip.get('fleet_vehicles') else 'Fleet',
            'model': trip['fleet_vehicles']['model_name'] if trip.get('fleet_vehicles') else 'Vehicle',
            'driver_name': trip['drivers']['full_name'] if trip.get('drivers') else 'Unknown',
            'destination': trip['destination'],
            'departure_time': trip['departure_time'],
            'arrival_time': trip['return_time'],
            'status': trip['status']
        })
    
    # Available resources for new dispatch
    vehicles = client.table('fleet_vehicles').select('*').eq('status', 'Available').execute()
    drivers = client.table('drivers').select('*').eq('status', 'Active').execute()
    
    return render_template('subsystems/logistics/log2/dispatch.html',
                           dispatches=processed_trips,
                           available_vehicles_list=vehicles.data if vehicles.data else [],
                           available_drivers_list=drivers.data if drivers.data else [],
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
        trip = client.table('fleet_dispatch').select('vehicle_id, driver_id', count='exact').eq('id', dispatch_id).single().execute()
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

@log2_bp.route('/costs')
@login_required
def cost_analysis():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    costs = client.table('fleet_costs').select('*, fleet_vehicles(plate_number)').order('log_date', desc=True).execute()
    vehicles = client.table('fleet_vehicles').select('id', 'plate_number').execute()
    
    return render_template('subsystems/logistics/log2/costs.html',
                           costs=costs.data if costs.data else [],
                           vehicles=vehicles.data if vehicles.data else [],
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

