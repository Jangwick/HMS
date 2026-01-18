from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error, get_supabase_client
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
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
def dashboard():
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    
    supabase = get_supabase_client()
    today = datetime.utcnow().strftime('%Y-%m-%d')
    
    # Get stats
    try:
        # Lab stats
        lab_orders_count = supabase.table('lab_orders').select('id', count='exact').execute().count or 0
        pending_lab_count = supabase.table('lab_orders').select('id', count='exact').eq('status', 'Pending').execute().count or 0
        
        # Pharmacy stats
        low_stock_count = supabase.table('inventory').select('id', count='exact').lt('quantity', 10).eq('category', 'Medical').execute().count or 0
        
        # Today's activity
        today_appointments = supabase.table('appointments').select('id', count='exact').eq('appointment_date', today).execute().count or 0
        
        metrics = {
            'total_lab_orders': lab_orders_count,
            'pending_labs': pending_lab_count,
            'low_stock_items': low_stock_count,
            'today_patients': today_appointments
        }
        
    except Exception as e:
        print(f"Error fetching dashboard metrics: {e}")
        metrics = {
            'total_lab_orders': 0,
            'pending_labs': 0,
            'low_stock_items': 0,
            'today_patients': 0
        }

    return render_template('subsystems/core_transaction/ct2/dashboard.html', 
                           now=datetime.utcnow,
                           metrics=metrics,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/lab/orders')
@login_required
def lab_orders():
    supabase = get_supabase_client()
    try:
        response = supabase.table('lab_orders').select('*, patients(first_name, last_name, patient_id_alt)').order('created_at', desc=True).execute()
        orders = response.data if response.data else []
    except Exception as e:
        print(f"DEBUG Error fetching lab orders: {e}")
        flash(f"Error fetching lab orders: {str(e)}", "danger")
        orders = []
        
    return render_template('subsystems/core_transaction/ct2/lab_orders.html', 
                           now=datetime.utcnow,
                           orders=orders,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/pharmacy/inventory')
@login_required
def pharmacy_inventory():
    supabase = get_supabase_client()
    try:
        response = supabase.table('inventory').select('*').eq('category', 'Medical').order('item_name').execute()
        items = response.data if response.data else []
    except Exception as e:
        flash(f"Error fetching inventory: {str(e)}", "danger")
        items = []
        
    return render_template('subsystems/core_transaction/ct2/pharmacy_inventory.html', 
                           now=datetime.utcnow,
                           items=items,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@ct2_bp.route('/pharmacy/dispense', methods=['GET', 'POST'])
@login_required
def dispense_meds():
    supabase = get_supabase_client()
    if request.method == 'POST':
        # Logic for dispensing meds would go here
        flash('Medication dispensed successfully!', 'success')
        return redirect(url_for('ct2.pharmacy_inventory'))
    
    try:
        # Get pending prescriptions or patients with recent clinical notes
        # For now, just getting patients to demo
        response = supabase.table('patients').select('id, first_name, last_name, patient_id_alt').limit(50).execute()
        patients = response.data if response.data else []
        
        # Also get medication list for dropdown
        med_response = supabase.table('inventory').select('id, item_name, quantity').eq('category', 'Medical').gt('quantity', 0).execute()
        medications = med_response.data if med_response.data else []
    except Exception as e:
        flash(f"Error fetching data: {str(e)}", "danger")
        patients = []
        medications = []

    return render_template('subsystems/core_transaction/ct2/dispense_meds.html', 
                           now=datetime.utcnow,
                           patients=patients,
                           medications=medications,
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
