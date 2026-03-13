from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from utils.hms_models import Notification
from datetime import datetime, timedelta

log2_bp = Blueprint('log2', __name__, template_folder='templates')

# Subsystem configuration
SUBSYSTEM_NAME = 'LOG2 - Fleet Operations'
ACCENT_COLOR = '#F97316'
BLUEPRINT_NAME = 'log2'


def _safe_float(value, default=0.0):
    try:
        if value is None or value == '':
            return default
        return float(value)
    except Exception:
        return default


def _safe_int(value, default=0):
    try:
        if value is None or value == '':
            return default
        return int(float(value))
    except Exception:
        return default


def _notify_by_severity(severity, title, message, target_url=None, driver_user_id=None):
    sev = (severity or 'LOW').upper()
    n_type = 'info'
    if sev in ('HIGH', 'CRITICAL'):
        n_type = 'danger'
    elif sev == 'MEDIUM':
        n_type = 'warning'

    Notification.create(
        subsystem='log2',
        title=title,
        message=message,
        n_type=n_type,
        sender_subsystem='log2',
        target_url=target_url
    )

    if driver_user_id and sev in ('MEDIUM', 'HIGH', 'CRITICAL'):
        Notification.create(
            user_id=driver_user_id,
            subsystem='log2',
            title=title,
            message=message,
            n_type=n_type,
            sender_subsystem='log2',
            target_url=target_url
        )


def _fleet_avg_efficiency(client):
    try:
        resp = client.table('vehicle_mileage_logs').select('fuel_efficiency_kmpl').not_.is_('fuel_efficiency_kmpl', 'null').execute()
        rows = resp.data or []
        vals = [
            _safe_float(r.get('fuel_efficiency_kmpl'))
            for r in rows
            if _safe_float(r.get('fuel_efficiency_kmpl')) > 0
        ]
        if not vals:
            return 0.0
        return sum(vals) / len(vals)
    except Exception:
        return 0.0


def _refresh_vehicle_maintenance_statuses(client, vehicle_id=None):
    try:
        query = client.table('vehicle_maintenance_schedules').select('*')
        if vehicle_id:
            query = query.eq('vehicle_id', vehicle_id)
        schedules = query.execute().data or []

        today = datetime.utcnow().date()
        for sched in schedules:
            sched_id = sched.get('id')
            status = sched.get('status') or 'UPCOMING'
            sched_date = sched.get('scheduled_date')

            new_status = status
            if status != 'COMPLETED':
                if sched_date:
                    try:
                        due_date = datetime.fromisoformat(str(sched_date)).date()
                    except Exception:
                        due_date = today

                    if due_date < today:
                        new_status = 'OVERDUE'
                    elif due_date == today:
                        new_status = 'DUE'
                    else:
                        new_status = 'UPCOMING'

            if new_status != status and sched_id:
                client.table('vehicle_maintenance_schedules').update({
                    'status': new_status,
                    'updated_at': datetime.utcnow().isoformat()
                }).eq('id', sched_id).execute()

                if new_status in ('DUE', 'OVERDUE'):
                    _notify_by_severity(
                        'HIGH' if new_status == 'OVERDUE' else 'MEDIUM',
                        title='Vehicle Maintenance Alert',
                        message=f"Vehicle #{sched.get('vehicle_id')} maintenance {new_status.lower()}: {sched.get('maintenance_type')}",
                        target_url=url_for('log2.vehicle_maintenance', vehicle_id=sched.get('vehicle_id'))
                    )
    except Exception as e:
        print(f"Maintenance status refresh error: {e}")


def _detect_trip_anomalies(client, trip, perf_payload):
    anomalies = []
    trip_id = trip.get('id')
    vehicle_id = trip.get('vehicle_id')
    driver_id = trip.get('driver_id')

    distance_km = _safe_float(perf_payload.get('distance_km'))
    fuel_used = _safe_float(perf_payload.get('fuel_used_liters'))
    fuel_cost = _safe_float(perf_payload.get('fuel_cost'))
    idle_minutes = _safe_int(perf_payload.get('idle_time_minutes'))
    harsh_total = _safe_int(perf_payload.get('harsh_braking_count')) + _safe_int(perf_payload.get('harsh_acceleration_count'))

    efficiency = (distance_km / fuel_used) if fuel_used > 0 else 0.0
    fleet_avg = _fleet_avg_efficiency(client)

    if fleet_avg > 0 and efficiency > 0 and efficiency < (fleet_avg * 0.75):
        anomalies.append(('EXCESSIVE_FUEL', 'MEDIUM', f'Fuel efficiency {efficiency:.2f} km/L is below 75% of fleet avg {fleet_avg:.2f} km/L.'))

    if idle_minutes > 60:
        anomalies.append(('IDLE_OVERRUN', 'LOW', f'Idle time exceeded threshold: {idle_minutes} minutes.'))

    if harsh_total > 5:
        anomalies.append(('HARSH_DRIVING', 'MEDIUM', f'Harsh driving events exceeded threshold: {harsh_total}.'))

    try:
        if fuel_cost > 0:
            avg_cost_resp = client.table('fleet_costs').select('amount').eq('cost_type', 'Fuel').execute()
            cost_vals = [_safe_float(r.get('amount')) for r in (avg_cost_resp.data or []) if _safe_float(r.get('amount')) > 0]
            if cost_vals:
                avg_fuel_cost = sum(cost_vals) / len(cost_vals)
                if avg_fuel_cost > 0 and fuel_cost > avg_fuel_cost * 1.5:
                    anomalies.append(('COST_SPIKE', 'MEDIUM', f'Fuel cost {fuel_cost:.2f} exceeds 150% of average {avg_fuel_cost:.2f}.'))
    except Exception:
        pass

    created = []
    for anomaly_type, severity, description in anomalies:
        try:
            inserted = client.table('fleet_anomalies').insert({
                'vehicle_id': vehicle_id,
                'driver_id': driver_id,
                'trip_id': trip_id,
                'anomaly_type': anomaly_type,
                'severity': severity,
                'description': description,
                'detected_at': datetime.utcnow().isoformat(),
                'auto_notified': True
            }).execute()
            created.append(inserted.data[0] if inserted.data else {
                'anomaly_type': anomaly_type,
                'severity': severity,
                'description': description
            })
        except Exception:
            created.append({'anomaly_type': anomaly_type, 'severity': severity, 'description': description})

        _notify_by_severity(
            severity,
            title=f"Fleet Anomaly: {anomaly_type}",
            message=description,
            target_url=url_for('log2.list_anomalies'),
            driver_user_id=None
        )

    return created


def _run_post_trip_analysis(client, trip, form_data):
    trip_id = trip.get('id')
    vehicle_id = trip.get('vehicle_id')
    driver_id = trip.get('driver_id')

    odometer_start = _safe_float(form_data.get('odometer_start'))
    odometer_end = _safe_float(form_data.get('odometer_end'))
    distance_km = max(0.0, odometer_end - odometer_start) if odometer_end and odometer_start else _safe_float(form_data.get('distance_km'))
    fuel_used = _safe_float(form_data.get('fuel_used_liters'))
    fuel_cost = _safe_float(form_data.get('fuel_cost'))
    idle_minutes = _safe_int(form_data.get('idle_time_minutes'))
    harsh_brake = _safe_int(form_data.get('harsh_braking_count'))
    harsh_accel = _safe_int(form_data.get('harsh_acceleration_count'))

    efficiency = (distance_km / fuel_used) if fuel_used > 0 else 0.0
    departure_time = trip.get('departure_time')
    now_iso = datetime.utcnow().isoformat()

    if vehicle_id:
        try:
            client.table('fleet_vehicles').update({
                'current_odometer': odometer_end if odometer_end > 0 else None
            }).eq('id', vehicle_id).execute()
        except Exception:
            pass

    try:
        client.table('vehicle_mileage_logs').insert({
            'vehicle_id': vehicle_id,
            'trip_id': trip_id,
            'odometer_start': odometer_start if odometer_start > 0 else None,
            'odometer_end': odometer_end if odometer_end > 0 else None,
            'mileage_km': distance_km,
            'fuel_used_liters': fuel_used,
            'fuel_cost': fuel_cost,
            'fuel_efficiency_kmpl': efficiency if efficiency > 0 else None,
            'logged_by': current_user.id,
            'logged_at': now_iso
        }).execute()
    except Exception as e:
        print(f"Mileage log insert warning: {e}")

    perf_payload = {
        'distance_km': distance_km,
        'fuel_used_liters': fuel_used,
        'fuel_cost': fuel_cost,
        'idle_time_minutes': idle_minutes,
        'harsh_braking_count': harsh_brake,
        'harsh_acceleration_count': harsh_accel
    }
    anomalies = _detect_trip_anomalies(client, trip, perf_payload)

    perf_score = max(0.0, min(100.0,
        (30.0 if trip.get('status') == 'Completed' else 20.0)
        + (25.0 if efficiency >= 8 else max(0.0, efficiency * 2.5))
        + max(0.0, 25.0 - (harsh_brake + harsh_accel) * 2.0)
        + max(0.0, 20.0 - (idle_minutes / 3.0))
    ))

    try:
        client.table('driver_trip_performance').insert({
            'driver_id': driver_id,
            'trip_id': trip_id,
            'vehicle_id': vehicle_id,
            'start_time': departure_time,
            'end_time': now_iso,
            'distance_km': distance_km,
            'fuel_used_liters': fuel_used,
            'idle_time_minutes': idle_minutes,
            'harsh_braking_count': harsh_brake,
            'harsh_acceleration_count': harsh_accel,
            'on_time_delivery': True,
            'performance_score': round(perf_score, 2),
            'anomalies': anomalies or []
        }).execute()
    except Exception as e:
        print(f"Trip performance insert warning: {e}")

    if fuel_cost > 0:
        try:
            client.table('fleet_costs').insert({
                'vehicle_id': vehicle_id,
                'dispatch_id': trip_id,
                'cost_type': 'Fuel',
                'amount': fuel_cost,
                'description': f'Auto-logged from trip #{trip_id}',
                'logged_by': current_user.id,
                'log_date': datetime.utcnow().date().isoformat()
            }).execute()
        except Exception as e:
            print(f"Auto fuel cost insert warning: {e}")

    _refresh_vehicle_maintenance_statuses(client, vehicle_id=vehicle_id)

    return {
        'distance_km': distance_km,
        'fuel_used_liters': fuel_used,
        'fuel_cost': fuel_cost,
        'odometer_start': odometer_start if odometer_start > 0 else None,
        'odometer_end': odometer_end if odometer_end > 0 else None,
        'idle_time_minutes': idle_minutes,
        'harsh_braking_count': harsh_brake,
        'harsh_acceleration_count': harsh_accel,
        'post_trip_analysis_done': True
    }

@log2_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked(subsystem=BLUEPRINT_NAME)
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
                        flash('Your account is awaiting approval from HR2 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('subsystems/logistics/log2/login.html')

                # Clear IP lockout attempts on successful login
                register_successful_login(subsystem=BLUEPRINT_NAME)
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
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt(subsystem=BLUEPRINT_NAME)
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/logistics/log2/login.html', remaining_seconds=remaining_seconds)
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
                return render_template('subsystems/logistics/log2/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/logistics/log2/login.html')


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
@policy_required(BLUEPRINT_NAME)
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

        _refresh_vehicle_maintenance_statuses(client)
        m_resp = client.table('vehicle_maintenance_schedules').select('status').in_('status', ['DUE', 'OVERDUE']).execute()
        maintenance_due = len(m_resp.data) if m_resp.data else 0

        since_7d = (datetime.utcnow() - timedelta(days=7)).isoformat()
        a_resp = client.table('fleet_anomalies').select('id').gte('detected_at', since_7d).execute()
        anomalies_week = len(a_resp.data) if a_resp.data else 0

        fleet_avg_eff = _fleet_avg_efficiency(client)
        
    except Exception as e:
        print(f"Dashboard Stats Error: {e}")
        available_vehicles = 0
        active_trips = 0
        total_drivers = 0
        maintenance_due = 0
        anomalies_week = 0
        fleet_avg_eff = 0.0
        
    return render_template('subsystems/logistics/log2/dashboard.html',
                           available_vehicles=available_vehicles,
                           active_trips=active_trips,
                           total_drivers=total_drivers,
                           maintenance_due=maintenance_due,
                           anomalies_week=anomalies_week,
                           fleet_avg_eff=fleet_avg_eff,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log2_bp.route('/vehicles')
@login_required
@policy_required(BLUEPRINT_NAME)
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
@policy_required(BLUEPRINT_NAME)
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
        
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, f"Add Vehicle: {v_data['plate_number']}", BLUEPRINT_NAME, v_data)
        
        flash('Vehicle added to fleet.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('log2.list_vehicles'))

@log2_bp.route('/vehicles/edit/<int:vehicle_id>', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
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
        
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, f"Update Vehicle: {v_data['plate_number']}", BLUEPRINT_NAME, v_data)
        
        flash('Vehicle updated successfully.', 'success')
    except Exception as e:
        flash(f'Update failed: {str(e)}', 'danger')
    return redirect(url_for('log2.list_vehicles'))

@log2_bp.route('/vehicles/delete/<int:vehicle_id>', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def delete_vehicle(vehicle_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        # Get plate for log before deleting
        v = client.table('fleet_vehicles').select('plate_number').eq('id', vehicle_id).single().execute()
        plate = v.data['plate_number'] if v.data else "Unknown"

        client.table('fleet_vehicles').delete().eq('id', vehicle_id).execute()
        
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, f"Delete Vehicle: {plate}", BLUEPRINT_NAME, {"id": vehicle_id})
        
        flash('Vehicle removed from fleet.', 'info')
    except Exception as e:
        flash(f'Delete failed: {str(e)}', 'danger')
    return redirect(url_for('log2.list_vehicles'))

@log2_bp.route('/dispatch')
@login_required
@policy_required(BLUEPRINT_NAME)
def dispatch_board():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Fetch active and recently completed dispatches (last 24h)
        # We fetch all currently 'On Trip' and then some recent ones
        d_resp = client.table('fleet_dispatch').select('*').neq('status', 'Cancelled').order('departure_time', desc=True).limit(50).execute()
        raw_dispatches = d_resp.data if d_resp.data else []
        
        # 2. Fetch All Vehicles and Drivers for linking
        v_resp = client.table('fleet_vehicles').select('*').execute()
        dr_resp = client.table('drivers').select('*').execute()
        
        vehicles_all = v_resp.data if v_resp.data else []
        drivers_all = dr_resp.data if dr_resp.data else []
        
        # Calculate Board Metrics
        active_trips = sum(1 for d in raw_dispatches if d.get('status') == 'On Trip')
        total_fleet = len(vehicles_all)
        available_v = sum(1 for v in vehicles_all if v.get('status', '').lower() in ['available', 'active', 'ready'])
        
        metrics = {
            'active_trips': active_trips,
            'available_fleet': available_v,
            'total_fleet': total_fleet,
            'utilization': round((active_trips / total_fleet * 100), 1) if total_fleet > 0 else 0
        }
        
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
                'status': trip.get('status', 'Unknown'),
                'purpose': trip.get('purpose', 'N/A')
            })
            
        available_vehicles = [v for v in vehicles_all if v.get('status', '').lower() in ['available', 'active', 'ready']]
        available_drivers = [d for d in drivers_all if d.get('status', '').lower() in ['available', 'active', 'ready']]
        
    except Exception as e:
        print(f"Dispatch Board Data Error: {e}")
        processed_trips = []
        available_vehicles = []
        available_drivers = []
        metrics = {'active_trips': 0, 'available_fleet': 0, 'total_fleet': 0, 'utilization': 0}
    
    return render_template('subsystems/logistics/log2/dispatch.html',
                           dispatches=processed_trips,
                           available_vehicles_list=available_vehicles,
                           available_drivers_list=available_drivers,
                           metrics=metrics,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log2_bp.route('/dispatch/create', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
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
        
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Dispatch Vehicle", BLUEPRINT_NAME, {"vehicle_id": v_id, "driver_id": d_id})
        
        flash('Vehicle dispatched successfully.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('log2.dispatch_board'))

@log2_bp.route('/dispatch/complete', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def complete_dispatch():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        dispatch_id = request.form.get('dispatch_id')
        # Get trip details to release resources
        trip = client.table('fleet_dispatch').select('*').eq('id', dispatch_id).single().execute()
        if trip.data:
            analysis_updates = _run_post_trip_analysis(client, trip.data, request.form)

            dispatch_update = {
                'status': 'Completed',
                'return_time': datetime.utcnow().isoformat()
            }
            dispatch_update.update(analysis_updates)

            client.table('fleet_dispatch').update({
                **dispatch_update
            }).eq('id', dispatch_id).execute()
            
            client.table('fleet_vehicles').update({'status': 'Available'}).eq('id', trip.data['vehicle_id']).execute()
            client.table('drivers').update({'status': 'Active'}).eq('id', trip.data['driver_id']).execute()
            
            from utils.hms_models import AuditLog
            AuditLog.log(current_user.id, "Complete Trip", BLUEPRINT_NAME, {"dispatch_id": dispatch_id})
            
            flash('Trip marked as completed with post-trip analytics.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('log2.dispatch_board'))

@log2_bp.route('/dispatch/cancel', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
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
@policy_required(BLUEPRINT_NAME)
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
@policy_required(BLUEPRINT_NAME)
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
        
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, f"Log Expense: {cost_data['cost_type']} - ${cost_data['amount']}", BLUEPRINT_NAME, cost_data)
        
        flash('Expense logged successfully.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('log2.cost_analysis'))

@log2_bp.route('/costs/delete/<int:cost_id>', methods=['POST'])
@login_required
def delete_cost(cost_id):
    if not current_user.is_admin():
        flash('Unauthorized: Only administrators can void cost records.', 'danger')
        return redirect(url_for('log2.dashboard'))
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        # Get details for audit log
        c = client.table('fleet_costs').select('cost_type, amount').eq('id', cost_id).single().execute()
        
        client.table('fleet_costs').delete().eq('id', cost_id).execute()
        
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Void Expense", BLUEPRINT_NAME, c.data if c.data else {"id": cost_id})
        
        flash('Transaction voided.', 'info')
    except Exception as e:
        flash(f'Delete failed: {str(e)}', 'danger')
    return redirect(url_for('log2.cost_analysis'))

@log2_bp.route('/costs/export')
@login_required
def export_costs():
    if not current_user.is_admin():
        flash('Unauthorized: Data export is restricted to administrators.', 'danger')
        return redirect(url_for('log2.dashboard'))
    from utils.supabase_client import get_supabase_client
    import csv
    import io
    from flask import Response
    
    client = get_supabase_client()
    costs_resp = client.table('fleet_costs').select('*, fleet_vehicles(plate_number)').execute()
    costs = costs_resp.data if costs_resp.data else []
    
    from utils.hms_models import AuditLog
    AuditLog.log(current_user.id, "Export Costs Data", BLUEPRINT_NAME, {"count": len(costs)})
    
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
@policy_required(BLUEPRINT_NAME)
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
@policy_required(BLUEPRINT_NAME)
def add_driver():
    if not current_user.is_staff():
        flash('Unauthorized: Only authorized staff can add new drivers.', 'danger')
        return redirect(url_for('log2.dashboard'))
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
        
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, f"Add Driver: {dr_data['full_name']}", BLUEPRINT_NAME, dr_data)
        
        flash('Driver added successfully.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('log2.list_drivers'))

@log2_bp.route('/drivers/edit/<int:driver_id>', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def edit_driver(driver_id):
    if not current_user.is_staff():
        flash('Unauthorized: Only authorized staff can modify driver details.', 'danger')
        return redirect(url_for('log2.dashboard'))
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
        
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, f"Update Driver: {dr_data['full_name']}", BLUEPRINT_NAME, dr_data)
        
        flash('Driver updated.', 'success')
    except Exception as e:
        flash(f'Update failed: {str(e)}', 'danger')
    return redirect(url_for('log2.list_drivers'))

@log2_bp.route('/drivers/delete/<int:driver_id>', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def delete_driver(driver_id):
    if not current_user.is_staff():
        flash('Unauthorized: Only authorized staff can remove drivers.', 'danger')
        return redirect(url_for('log2.dashboard'))
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        # Check if driver is on a trip
        driver = client.table('drivers').select('full_name, status').eq('id', driver_id).single().execute()
        if driver.data and driver.data.get('status') == 'On Trip':
            flash('Cannot delete a driver who is currently on a trip.', 'warning')
            return redirect(url_for('log2.list_drivers'))

        client.table('drivers').delete().eq('id', driver_id).execute()
        
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, f"Delete Driver: {driver.data['full_name'] if driver.data else 'Unknown'}", BLUEPRINT_NAME, {"id": driver_id})
        
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

@log2_bp.route('/dispatch-logs')
@login_required
@policy_required(BLUEPRINT_NAME)
def dispatch_logs():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    date_filter = request.args.get('date')
    status_filter = request.args.get('status')
    
    try:
        # Fetch dispatches with vehicle and driver info
        query = client.table('fleet_dispatch').select('*, fleet_vehicles(plate_number, model_name), drivers(full_name)')
        
        if date_filter:
            query = query.gte('departure_time', f"{date_filter}T00:00:00")\
                         .lte('departure_time', f"{date_filter}T23:59:59")
        
        if status_filter:
            query = query.eq('status', status_filter)
        else:
            # Default to historical (not on trip) or just all
            pass
            
        d_resp = query.order('departure_time', desc=True).limit(200).execute()
        logs = d_resp.data if d_resp.data else []
        
    except Exception as e:
        print(f"Dispatch Logs Error: {e}")
        logs = []
        
    return render_template('subsystems/logistics/log2/dispatch_logs.html',
                           logs=logs,
                           current_date=date_filter,
                           current_status=status_filter,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log2_bp.route('/resource-map')
@login_required
@policy_required(BLUEPRINT_NAME)
def resource_map():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Fetch vehicles that are "In Use"
        v_resp = client.table('fleet_vehicles').select('*').eq('status', 'In Use').execute()
        active_vehicles = v_resp.data if v_resp.data else []
        
        # Since we don't have real coordinates, we'll assign random dummy ones for simulation
        import random
        for v in active_vehicles:
            v['lat'] = 14.5995 + (random.random() - 0.5) * 0.1
            v['lng'] = 120.9842 + (random.random() - 0.5) * 0.1
            
    except Exception as e:
        print(f"Resource Map Error: {e}")
        active_vehicles = []
        
    return render_template('subsystems/logistics/log2/resource_map.html',
                           active_vehicles=active_vehicles,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@log2_bp.route('/vehicles/<int:vehicle_id>/maintenance')
@login_required
@policy_required(BLUEPRINT_NAME)
def vehicle_maintenance(vehicle_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        _refresh_vehicle_maintenance_statuses(client, vehicle_id=vehicle_id)
        vehicle_resp = client.table('fleet_vehicles').select('*').eq('id', vehicle_id).single().execute()
        schedules_resp = client.table('vehicle_maintenance_schedules').select('*').eq('vehicle_id', vehicle_id).order('scheduled_date', desc=False).execute()

        vehicle = vehicle_resp.data or {}
        schedules = schedules_resp.data or []
    except Exception as e:
        flash(f'Unable to load maintenance records: {e}', 'danger')
        return redirect(url_for('log2.list_vehicles'))

    return render_template(
        'subsystems/logistics/log2/vehicle_maintenance.html',
        vehicle=vehicle,
        schedules=schedules,
        subsystem_name=SUBSYSTEM_NAME,
        accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME
    )


@log2_bp.route('/vehicles/<int:vehicle_id>/maintenance/add', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def add_maintenance_schedule(vehicle_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        payload = {
            'vehicle_id': vehicle_id,
            'maintenance_type': request.form.get('maintenance_type'),
            'scheduled_date': request.form.get('scheduled_date'),
            'interval_km': _safe_float(request.form.get('interval_km')) or None,
            'interval_days': _safe_int(request.form.get('interval_days')) or None,
            'assigned_to': _safe_int(request.form.get('assigned_to')) or None,
            'notes': request.form.get('notes'),
            'status': 'UPCOMING',
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }
        client.table('vehicle_maintenance_schedules').insert(payload).execute()
        flash('Maintenance schedule added.', 'success')
    except Exception as e:
        flash(f'Failed to add maintenance schedule: {e}', 'danger')
    return redirect(url_for('log2.vehicle_maintenance', vehicle_id=vehicle_id))


@log2_bp.route('/maintenance/<int:schedule_id>/complete', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def complete_maintenance_schedule(schedule_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        sched_resp = client.table('vehicle_maintenance_schedules').select('*').eq('id', schedule_id).single().execute()
        sched = sched_resp.data or {}
        vehicle_id = sched.get('vehicle_id')
        completed_date = request.form.get('completed_date') or datetime.utcnow().date().isoformat()
        completed_cost = _safe_float(request.form.get('completed_cost'))

        client.table('vehicle_maintenance_schedules').update({
            'status': 'COMPLETED',
            'last_done_date': completed_date,
            'completed_cost': completed_cost if completed_cost > 0 else None,
            'completed_by': current_user.id,
            'completed_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }).eq('id', schedule_id).execute()

        if vehicle_id:
            client.table('fleet_vehicles').update({
                'last_maintenance_date': completed_date,
                'maintenance_status': 'OK'
            }).eq('id', vehicle_id).execute()

        if vehicle_id and completed_cost > 0:
            client.table('fleet_costs').insert({
                'vehicle_id': vehicle_id,
                'cost_type': 'Maintenance',
                'amount': completed_cost,
                'description': f"Maintenance: {sched.get('maintenance_type')}",
                'logged_by': current_user.id,
                'log_date': datetime.utcnow().date().isoformat()
            }).execute()

        flash('Maintenance marked as completed.', 'success')
        if vehicle_id:
            return redirect(url_for('log2.vehicle_maintenance', vehicle_id=vehicle_id))
    except Exception as e:
        flash(f'Failed to complete maintenance schedule: {e}', 'danger')
    return redirect(url_for('log2.list_vehicles'))


@log2_bp.route('/anomalies')
@login_required
@policy_required(BLUEPRINT_NAME)
def list_anomalies():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        anomalies_resp = client.table('fleet_anomalies').select('*').order('detected_at', desc=True).limit(300).execute()
        anomalies = anomalies_resp.data or []
    except Exception as e:
        print(f'Anomalies fetch error: {e}')
        anomalies = []

    return render_template(
        'subsystems/logistics/log2/anomalies.html',
        anomalies=anomalies,
        subsystem_name=SUBSYSTEM_NAME,
        accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME
    )


@log2_bp.route('/anomalies/<int:anomaly_id>/ack', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def acknowledge_anomaly(anomaly_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        client.table('fleet_anomalies').update({
            'acknowledged': True,
            'acknowledged_by': current_user.id,
            'acknowledged_at': datetime.utcnow().isoformat()
        }).eq('id', anomaly_id).execute()
        flash('Anomaly acknowledged.', 'success')
    except Exception as e:
        flash(f'Failed to acknowledge anomaly: {e}', 'danger')
    return redirect(url_for('log2.list_anomalies'))


@log2_bp.route('/drivers/<int:driver_id>/performance')
@login_required
@policy_required(BLUEPRINT_NAME)
def driver_performance(driver_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        driver_resp = client.table('drivers').select('*').eq('id', driver_id).single().execute()
        perf_resp = client.table('driver_trip_performance').select('*').eq('driver_id', driver_id).order('created_at', desc=True).limit(100).execute()
        perf_rows = perf_resp.data or []

        avg_score = round(sum(_safe_float(r.get('performance_score')) for r in perf_rows) / len(perf_rows), 2) if perf_rows else 0.0
        on_time_count = sum(1 for r in perf_rows if r.get('on_time_delivery'))

        stats = {
            'trip_count': len(perf_rows),
            'avg_score': avg_score,
            'on_time_rate': round((on_time_count / len(perf_rows) * 100), 1) if perf_rows else 0.0
        }
    except Exception as e:
        flash(f'Failed to load driver performance: {e}', 'danger')
        return redirect(url_for('log2.list_drivers'))

    return render_template(
        'subsystems/logistics/log2/driver_performance.html',
        driver=driver_resp.data or {},
        performance_rows=perf_rows,
        stats=stats,
        subsystem_name=SUBSYSTEM_NAME,
        accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME
    )


@log2_bp.route('/cost-analysis')
@login_required
@policy_required(BLUEPRINT_NAME)
def cost_analysis_hub():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        reports = client.table('cost_analysis_reports').select('*').order('created_at', desc=True).limit(50).execute().data or []
    except Exception:
        reports = []

    budget_allocated = 0.0
    try:
        # Preferred budget source if available
        b_rows = client.table('department_budgets').select('*').eq('subsystem', 'log2').execute().data or []
        budget_allocated = sum(_safe_float(r.get('allocated_amount')) for r in b_rows)
    except Exception:
        try:
            # Fallback source from finance approvals
            b_rows = client.table('procurement_budget_approvals').select('*').eq('status', 'APPROVED').execute().data or []
            budget_allocated = sum(_safe_float(r.get('approved_amount')) for r in b_rows)
        except Exception:
            budget_allocated = 0.0

    return render_template(
        'subsystems/logistics/log2/cost_analysis_hub.html',
        reports=reports,
        budget_allocated=budget_allocated,
        subsystem_name=SUBSYSTEM_NAME,
        accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME
    )


@log2_bp.route('/cost-analysis/generate', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def generate_cost_analysis_report():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        period_start = request.form.get('period_start')
        period_end = request.form.get('period_end')
        if not period_start or not period_end:
            flash('Please provide period start and end.', 'warning')
            return redirect(url_for('log2.cost_analysis_hub'))

        fuel_rows = client.table('fleet_costs').select('*').eq('cost_type', 'Fuel').gte('log_date', period_start).lte('log_date', period_end).execute().data or []
        maint_rows = client.table('fleet_costs').select('*').in_('cost_type', ['Maintenance', 'Repair']).gte('log_date', period_start).lte('log_date', period_end).execute().data or []

        total_fuel = sum(_safe_float(r.get('amount')) for r in fuel_rows)
        total_maint = sum(_safe_float(r.get('amount')) for r in maint_rows)
        total_driver = 0.0
        total_cost = total_fuel + total_maint + total_driver

        budget_allocated = 0.0
        try:
            b_rows = client.table('department_budgets').select('*').eq('subsystem', 'log2').execute().data or []
            budget_allocated = sum(_safe_float(r.get('allocated_amount')) for r in b_rows)
        except Exception:
            pass

        suggestions = []
        if budget_allocated and total_cost > budget_allocated:
            suggestions.append({
                'type': 'BUDGET',
                'action': 'Review high-cost routes and re-balance schedules to off-peak windows.',
                'impact': 'Expected 8-12% monthly savings'
            })
        if total_fuel > (total_cost * 0.6 if total_cost > 0 else 0):
            suggestions.append({
                'type': 'FUEL',
                'action': 'Investigate high fuel-share vehicles and optimize idle time.',
                'impact': 'Expected 5-10% fuel cost reduction'
            })
        if not suggestions:
            suggestions.append({
                'type': 'STABILITY',
                'action': 'Current costs are within expected range. Continue monitoring.',
                'impact': 'Maintain baseline performance'
            })

        report_no = f"CAR-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        client.table('cost_analysis_reports').insert({
            'report_no': report_no,
            'period_start': period_start,
            'period_end': period_end,
            'total_fuel_cost': total_fuel,
            'total_maintenance_cost': total_maint,
            'total_driver_cost': total_driver,
            'total_cost': total_cost,
            'budget_allocated': budget_allocated,
            'budget_variance': total_cost - budget_allocated,
            'optimization_suggestions': suggestions,
            'created_by': current_user.id,
            'created_at': datetime.utcnow().isoformat()
        }).execute()

        flash('Cost analysis report generated.', 'success')
    except Exception as e:
        flash(f'Failed to generate report: {e}', 'danger')
    return redirect(url_for('log2.cost_analysis_hub'))


@log2_bp.route('/cost-analysis/<int:report_id>/send-to-finance', methods=['POST'])
@login_required
@policy_required(BLUEPRINT_NAME)
def send_cost_report_to_finance(report_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        report_resp = client.table('cost_analysis_reports').select('*').eq('id', report_id).single().execute()
        report = report_resp.data or {}
        if not report:
            flash('Report not found.', 'danger')
            return redirect(url_for('log2.cost_analysis_hub'))

        client.table('cost_analysis_reports').update({
            'sent_to_finance': True,
            'sent_at': datetime.utcnow().isoformat()
        }).eq('id', report_id).execute()

        Notification.create(
            subsystem='financials',
            title='LOG2 Cost Optimization Report',
            message=(
                f"Report {report.get('report_no')} submitted. Total cost: {report.get('total_cost')} "
                f"| Budget variance: {report.get('budget_variance')}"
            ),
            n_type='info',
            sender_subsystem='log2',
            target_url=url_for('log2.cost_analysis_hub')
        )

        flash('Report sent to Finance.', 'success')
    except Exception as e:
        flash(f'Failed to send report: {e}', 'danger')
    return redirect(url_for('log2.cost_analysis_hub'))

@log2_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('log2.login'))



