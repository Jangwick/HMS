from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from datetime import datetime

log1_bp = Blueprint('log1', __name__, template_folder='templates')

# Subsystem configuration
SUBSYSTEM_NAME = 'LOG1 - Inventory Management'
ACCENT_COLOR = '[#F59E0B]'
BLUEPRINT_NAME = 'log1'

@log1_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked()
    if locked:
        flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
        return render_template('subsystems/logistics/log1/login.html', remaining_seconds=remaining_seconds)
    
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
                    return redirect(url_for('log1.change_password'))

                # Check if account is approved
                if user.status != 'Active':
                    if user.status == 'Pending':
                        flash('Your account is awaiting approval from HR3 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('subsystems/logistics/log1/login.html')

                # Clear IP lockout attempts on successful login
                register_successful_login()
                user.register_successful_login()
                
                if login_user(user):
                    days_left = (user.password_expires_at - now_utc).days if user.password_expires_at else 999
                    if days_left <= 7:
                        flash(f'Warning: Your password will expire in {days_left} days. Please update it soon.', 'warning')
                    return redirect(url_for('log1.dashboard'))
                else:
                    flash('Login failed. Your account may be deactivated.', 'danger')
                    return render_template('subsystems/logistics/log1/login.html')
            else:
                # Register failed attempt by IP
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt()
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/logistics/log1/login.html', remaining_seconds=remaining_seconds)
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
                return render_template('subsystems/logistics/log1/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/logistics/log1/login.html')

@log1_bp.route('/register', methods=['GET', 'POST'])
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
                return redirect(url_for('log1.login'))
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

@log1_bp.route('/change-password', methods=['GET', 'POST'])
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
            return redirect(url_for('log1.login'))
    elif current_user.is_authenticated:
        user = current_user
        is_expired = False
    else:
        flash('Please login first.', 'danger')
        return redirect(url_for('log1.login'))
    
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
            return redirect(url_for('log1.login'))
        except PasswordValidationError as e:
            for error in e.errors:
                flash(error, 'danger')
        except Exception as e:
            flash('An error occurred while updating password.', 'danger')
    
    return render_template('shared/change_password.html',
        subsystem_name=SUBSYSTEM_NAME, accent_color=ACCENT_COLOR,
        blueprint_name=BLUEPRINT_NAME, is_expired=is_expired)

@log1_bp.route('/dashboard')
@login_required
def dashboard():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    # Fetch stats
    total_items = client.table('inventory').select('id', count='exact').execute().count
    low_stock = client.table('inventory').select('id', count='exact').lte('quantity', 10).execute().count
    
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
    return render_template('subsystems/logistics/log1/dashboard.html', 
                           now=datetime.utcnow,
                           total_items=total_items,
                           low_stock_count=low_stock,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log1_bp.route('/inventory')
@login_required
def list_inventory():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    response = client.table('inventory').select('*').execute()
    items = response.data if response.data else []
    return render_template('subsystems/logistics/log1/inventory.html', 
                           items=items,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log1_bp.route('/inventory/add', methods=['GET', 'POST'])
@login_required
def add_inventory_item():
    if request.method == 'POST':
        from utils.supabase_client import get_supabase_client
        client = get_supabase_client()
        data = {
            'item_name': request.form.get('item_name'),
            'category': request.form.get('category'),
            'quantity': int(request.form.get('quantity')),
            'unit': request.form.get('unit'),
            'reorder_level': int(request.form.get('reorder_level')),
            'batch_number': request.form.get('batch_number'),
            'expiry_date': request.form.get('expiry_date')
        }
        client.table('inventory').insert(data).execute()
        flash('Item added to inventory!', 'success')
        return redirect(url_for('log1.list_inventory'))
    return render_template('subsystems/logistics/log1/add_item.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log1_bp.route('/settings', methods=['GET', 'POST'])
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

@log1_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('log1.login'))
