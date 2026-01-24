from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from utils.supabase_client import User, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from utils.hms_models import InventoryItem, AuditLog
from datetime import datetime, timedelta

log1_bp = Blueprint('log1', __name__, template_folder='templates')

# Subsystem configuration
SUBSYSTEM_NAME = 'LOG1 - Inventory Management'
ACCENT_COLOR = '#F59E0B'
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
@policy_required(BLUEPRINT_NAME)
def dashboard():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Fetch stats
    total_items = 0
    low_stock = 0
    inventory_value = 0
    cat_labels = []
    cat_values = []
    
    try:
        # Total items and low stock
        inv_data = client.table('inventory').select('*').execute()
        items = inv_data.data if inv_data.data else []
        total_items = len(items)
        
        low_stock = sum(1 for item in items if (item.get('quantity') or 0) <= (item.get('reorder_level') or 10))
        
        # Category breakdown
        cats = {}
        for item in items:
            c = item.get('category') or 'Other'
            cats[c] = cats.get(c, 0) + 1
        cat_labels = list(cats.keys())
        cat_values = list(cats.values())
        
        # Asset stats
        assets_resp = client.table('assets').select('id', count='exact').execute()
        total_assets = assets_resp.count or 0
        
        # Procurement stats
        po_resp = client.table('purchase_orders').select('id', count='exact').eq('status', 'Pending').execute()
        pending_pos = po_resp.count or 0

        # Document stats
        doc_resp = client.table('log_documents').select('id', count='exact').execute()
        total_docs = doc_resp.count or 0

    except Exception as e:
        print(f"Error fetching dashboard stats: {e}")
        total_assets = 0
        pending_pos = 0
        total_docs = 0

    # Placeholder values for trend chart
    consumption_labels = ["Jan", "Feb", "Mar", "Apr", "May", "Jun"]
    consumption_values = [12, 19, 3, 5, 2, 3]
    
    if current_user.should_warn_password_expiry():
        days_left = current_user.days_until_password_expiry()
        flash(f'Your password will expire in {days_left} days. Please update it soon.', 'warning')
        
    return render_template('subsystems/logistics/log1/dashboard.html', 
                           now=datetime.utcnow,
                           total_items=total_items,
                           low_stock_count=low_stock,
                           total_assets=total_assets,
                           pending_pos=pending_pos,
                           total_docs=total_docs,
                           cat_labels=cat_labels,
                           cat_values=cat_values,
                           consumption_labels=consumption_labels,
                           consumption_values=consumption_values,
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
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_inventory'))
        
    if request.method == 'POST':
        try:
            from utils.supabase_client import get_supabase_client
            client = get_supabase_client()
            
            # Get form data and convert to appropriate types
            quantity = request.form.get('quantity', '0')
            reorder_level = request.form.get('reorder_level', '10')
            
            data = {
                'item_name': request.form.get('item_name'),
                'category': request.form.get('category'),
                'quantity': int(quantity) if quantity else 0,
                'reorder_level': int(reorder_level) if reorder_level else 10,
                'batch_number': request.form.get('batch_number'),
                'expiry_date': request.form.get('expiry_date') or None,
                'unit': request.form.get('unit', 'units'),
                'location': request.form.get('location', 'Warehouse')
            }
            
            client.table('inventory').insert(data).execute()
            flash('Item added to inventory!', 'success')
            return redirect(url_for('log1.list_inventory'))
        except Exception as e:
            flash(f'Error adding item: {format_db_error(e)}', 'danger')
            return render_template('subsystems/logistics/log1/add_item.html',
                                   subsystem_name=SUBSYSTEM_NAME,
                                   accent_color=ACCENT_COLOR,
                                   blueprint_name=BLUEPRINT_NAME)
            
    return render_template('subsystems/logistics/log1/add_item.html',
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log1_bp.route('/inventory/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_inventory_item(item_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_inventory'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    if request.method == 'POST':
        try:
            quantity = request.form.get('quantity', '0')
            reorder_level = request.form.get('reorder_level', '10')
            
            data = {
                'item_name': request.form.get('item_name'),
                'category': request.form.get('category'),
                'quantity': int(quantity) if quantity else 0,
                'reorder_level': int(reorder_level) if reorder_level else 10,
                'batch_number': request.form.get('batch_number'),
                'expiry_date': request.form.get('expiry_date') or None,
                'unit': request.form.get('unit', 'units'),
                'location': request.form.get('location')
            }
            
            client.table('inventory').update(data).eq('id', item_id).execute()
            flash('Item updated successfully!', 'success')
            return redirect(url_for('log1.list_inventory'))
        except Exception as e:
            flash(f'Error updating item: {str(e)}', 'danger')

    # Fetch item for the form
    resp = client.table('inventory').select('*').eq('id', item_id).single().execute()
    if not resp.data:
        flash('Item not found.', 'danger')
        return redirect(url_for('log1.list_inventory'))
        
    return render_template('subsystems/logistics/log1/edit_item.html',
                           item=resp.data,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log1_bp.route('/inventory/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_inventory_item(item_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_inventory'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        client.table('inventory').delete().eq('id', item_id).execute()
        flash('Item removed from inventory.', 'success')
    except Exception as e:
        flash(f'Error deleting item: {str(e)}', 'danger')
    return redirect(url_for('log1.list_inventory'))

@log1_bp.route('/inventory/history')
@login_required
def inventory_history():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Fetch dispensing history with related item and user names
        history_resp = client.table('dispensing_history').select('*, inventory(item_name), users(username)').order('dispensed_at', desc=True).execute()
        history = history_resp.data if history_resp.data else []
    except Exception as e:
        # Fallback if joins fail
        history_resp = client.table('dispensing_history').select('*').order('dispensed_at', desc=True).execute()
        history = history_resp.data if history_resp.data else []
        
    return render_template('subsystems/logistics/log1/history.html',
                           history=history,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log1_bp.route('/inventory/dispense', methods=['POST'])
@login_required
def dispense_item():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    item_id = request.form.get('item_id')
    quantity_to_dispense = int(request.form.get('quantity', 0))
    
    try:
        # Get current quantity
        item_resp = client.table('inventory').select('quantity, item_name').eq('id', item_id).single().execute()
        if not item_resp.data:
            flash('Item not found.', 'danger')
            return redirect(url_for('log1.list_inventory'))
            
        current_qty = item_resp.data.get('quantity', 0)
        if current_qty < quantity_to_dispense:
            flash(f'Insufficient stock for {item_resp.data.get("item_name")}.', 'danger')
            return redirect(url_for('log1.list_inventory'))
            
        # Update quantity
        client.table('inventory').update({'quantity': current_qty - quantity_to_dispense}).eq('id', item_id).execute()
        
        # Log in dispensing history
        client.table('dispensing_history').insert({
            'inventory_id': item_id,
            'quantity': quantity_to_dispense,
            'dispensed_by': current_user.id,
            'notes': request.form.get('notes', 'Standard dispensing')
        }).execute()
        
        flash(f'Successfully dispensed {quantity_to_dispense} units.', 'success')
    except Exception as e:
        flash(f'Error dispensing item: {str(e)}', 'danger')
        
    return redirect(url_for('log1.list_inventory'))

@log1_bp.route('/procurement')
@login_required
def procurement():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Try joint fetch first
        pos_resp = client.table('purchase_orders').select('*, suppliers(supplier_name)').execute()
        pos_data = pos_resp.data if pos_resp.data else []
    except Exception as e:
        print(f"Relationship join failed, using fallback: {e}")
        # Fallback: Fetch separately and join in Python if the DB relationship is missing
        try:
            pos_resp = client.table('purchase_orders').select('*').execute()
            suppliers_resp = client.table('suppliers').select('id, supplier_name').execute()
            
            raw_pos = pos_resp.data if pos_resp.data else []
            suppliers_dict = {s['id']: s for s in (suppliers_resp.data or [])}
            
            pos_data = []
            for po in raw_pos:
                po['suppliers'] = suppliers_dict.get(po['supplier_id'])
                pos_data.append(po)
        except Exception as e2:
            print(f"Procurement fetch failed: {e2}")
            pos_data = []
            
    suppliers = client.table('suppliers').select('*').execute()
    
    return render_template('subsystems/logistics/log1/procurement.html',
                           purchase_orders=pos_data,
                           suppliers=suppliers.data if suppliers.data else [],
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log1_bp.route('/procurement/po/add', methods=['POST'])
@login_required
def add_purchase_order():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.procurement'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        po_number = f"PO-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        po_data = {
            'po_number': po_number,
            'supplier_id': request.form.get('supplier_id'),
            'total_amount': float(request.form.get('total_amount', 0)),
            'status': 'Draft',
            'requested_by': current_user.id,
            'notes': request.form.get('notes')
        }
        
        # Insert PO record
        po_resp = client.table('purchase_orders').insert(po_data).execute()
        if po_resp.data:
            po_id = po_resp.data[0]['id']
            # Get items from hidden field (sent as JSON string from JS)
            items_json = request.form.get('po_items_json')
            if items_json:
                import json
                items = json.loads(items_json)
                for item in items:
                    item['po_id'] = po_id
                    client.table('po_items').insert(item).execute()
                    
        flash(f'Purchase Order {po_number} created successfully!', 'success')
    except Exception as e:
        flash(f'Error creating PO: {str(e)}', 'danger')
        
    return redirect(url_for('log1.procurement'))

@log1_bp.route('/procurement/po/<int:po_id>')
@login_required
def view_po(po_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        po = client.table('purchase_orders').select('*, suppliers(*)').eq('id', po_id).single().execute()
        items = client.table('po_items').select('*').eq('po_id', po_id).execute()
        
        return render_template('subsystems/logistics/log1/po_detail.html',
                               po=po.data,
                               items=items.data if items.data else [],
                               subsystem_name=SUBSYSTEM_NAME,
                               accent_color=ACCENT_COLOR,
                               blueprint_name=BLUEPRINT_NAME)
    except Exception as e:
        flash(f'Error fetching PO details: {str(e)}', 'danger')
        return redirect(url_for('log1.procurement'))

@log1_bp.route('/procurement/po/<int:po_id>/status', methods=['POST'])
@login_required
def update_po_status(po_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.procurement'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    new_status = request.form.get('status')
    
    try:
        # Get current PO
        po_resp = client.table('purchase_orders').select('*').eq('id', po_id).single().execute()
        if not po_resp.data:
            flash('PO not found.', 'danger')
            return redirect(url_for('log1.procurement'))
            
        old_status = po_resp.data['status']
        
        # Update status
        client.table('purchase_orders').update({'status': new_status}).eq('id', po_id).execute()
        
        # INTEGRATION: Generate Vendor Invoice in Financials
        # Trigger on 'Sent' or 'Approved' (Sent is used in the current UI workflow)
        if new_status in ['Sent', 'Approved'] and old_status not in ['Sent', 'Approved']:
            # 1. Ensure supplier exists as a vendor in Financials
            supplier_resp = client.table('suppliers').select('*').eq('id', po_resp.data['supplier_id']).single().execute()
            supplier = supplier_resp.data
            if supplier:
                # Find or create vendor in 'vendors' table
                vendor_resp = client.table('vendors').select('*').eq('name', supplier['supplier_name']).execute()
                if vendor_resp.data:
                    vendor_id = vendor_resp.data[0]['id']
                else:
                    new_v = client.table('vendors').insert({
                        'name': supplier['supplier_name'],
                        'email': supplier['email'],
                        'phone': supplier['phone']
                    }).execute()
                    vendor_id = new_v.data[0]['id']
                
                # 2. Create Vendor Invoice
                client.table('vendor_invoices').insert({
                    'vendor_id': vendor_id,
                    'invoice_number': f"INV-{po_resp.data['po_number']}",
                    'invoice_date': datetime.now().date().isoformat(),
                    'due_date': (datetime.now() + timedelta(days=30)).date().isoformat(),
                    'amount': po_resp.data['total_amount'],
                    'status': 'Unpaid',
                    'description': f"Auto-generated from PO #{po_resp.data['po_number']}"
                }).execute()
                flash('Vendor Invoice automatically generated in Financials.', 'info')

        # AUDIT LOG
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Update PO Status", BLUEPRINT_NAME, 
                     {"po_id": po_id, "new_status": new_status, "old_status": old_status})

        # If transitioning to "Received", automatically update inventory
        if new_status == 'Received' and old_status != 'Received':
            items_resp = client.table('po_items').select('*').eq('po_id', po_id).execute()
            if items_resp.data:
                for item in items_resp.data:
                    # Check if item exists in inventory (by name)
                    inv_resp = client.table('inventory').select('*').eq('item_name', item['item_name']).execute()
                    if inv_resp.data:
                        # Update existing
                        inv_id = inv_resp.data[0]['id']
                        new_qty = inv_resp.data[0]['quantity'] + item['quantity']
                        client.table('inventory').update({'quantity': new_qty}).eq('id', inv_id).execute()
                    else:
                        # Insert new
                        client.table('inventory').insert({
                            'item_name': item['item_name'],
                            'quantity': item['quantity'],
                            'category': 'General',
                            'unit': 'units',
                            'location': 'Warehouse'
                        }).execute()
                flash('PO status updated to Received. Inventory has been automatically updated.', 'success')
            else:
                flash(f'PO status updated to {new_status}.', 'success')
        else:
            flash(f'PO status updated to {new_status}.', 'success')
            
    except Exception as e:
        flash(f'Error updating PO status: {str(e)}', 'danger')
        
    return redirect(url_for('log1.view_po', po_id=po_id))

@log1_bp.route('/procurement/suppliers/add', methods=['POST'])
@login_required
def add_supplier():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.procurement'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        supplier_data = {
            'supplier_name': request.form.get('supplier_name'),
            'contact_person': request.form.get('contact_person'),
            'email': request.form.get('email'),
            'phone': request.form.get('phone'),
            'category': request.form.get('category'),
            'status': 'Active'
        }
        client.table('suppliers').insert(supplier_data).execute()
        flash('Supplier added successfully!', 'success')
    except Exception as e:
        flash(f'Error adding supplier: {str(e)}', 'danger')
        
    return redirect(url_for('log1.procurement'))

@log1_bp.route('/assets')
@login_required
def list_assets():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    assets = client.table('assets').select('*').execute()
    return render_template('subsystems/logistics/log1/assets.html',
                           assets=assets.data if assets.data else [],
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log1_bp.route('/assets/add', methods=['POST'])
@login_required
def add_asset():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_assets'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        asset_data = {
            'asset_name': request.form.get('asset_name'),
            'tag_number': request.form.get('tag_number'),
            'status': request.form.get('status', 'Active'),
            'warranty_expiry': request.form.get('warranty_expiry') or None,
            'last_maintenance': request.form.get('last_maintenance') or datetime.now().date().isoformat()
        }
        client.table('assets').insert(asset_data).execute()
        flash('Asset registered successfully!', 'success')
    except Exception as e:
        flash(f'Error adding asset: {str(e)}', 'danger')
        
    return redirect(url_for('log1.list_assets'))

@log1_bp.route('/assets/maintain/<int:asset_id>', methods=['POST'])
@login_required
def record_maintenance(asset_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_assets'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        notes = request.form.get('notes')
        cost = request.form.get('cost', 0)
        m_date = datetime.now().date().isoformat()
        
        # Log maintenance record
        log_data = {
            'asset_id': asset_id,
            'maintenance_date': m_date,
            'performed_by': current_user.id,
            'notes': notes,
            'cost': cost
        }
        client.table('asset_maintenance_logs').insert(log_data).execute()
        
        # Update asset last_maintenance date
        client.table('assets').update({'last_maintenance': m_date}).eq('id', asset_id).execute()
        
        flash('Maintenance record added successfully!', 'success')
    except Exception as e:
        flash(f'Error recording maintenance: {str(e)}', 'danger')
        
    return redirect(url_for('log1.list_assets'))

@log1_bp.route('/assets/update-status/<int:asset_id>/<string:status>')
@login_required
def update_asset_status(asset_id, status):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_assets'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('assets').update({'status': status}).eq('id', asset_id).execute()
        flash(f'Asset status updated to {status}.', 'success')
    except Exception as e:
        flash(f'Error updating status: {str(e)}', 'danger')
        
    return redirect(url_for('log1.list_assets'))

@log1_bp.route('/assets/delete/<int:asset_id>')
@login_required
def delete_asset(asset_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('assets').delete().eq('id', asset_id).execute()
        flash('Asset removed from registry.', 'success')
    except Exception as e:
        flash(f'Error deleting asset: {str(e)}', 'danger')
        
    return redirect(url_for('log1.list_assets'))

@log1_bp.route('/assets/history/<int:asset_id>')
@login_required
def view_asset_history(asset_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        asset = client.table('assets').select('*').eq('id', asset_id).single().execute()
        logs = client.table('asset_maintenance_logs').select('*, users(username)').eq('asset_id', asset_id).order('maintenance_date', desc=True).execute()
        
        return render_template('subsystems/logistics/log1/asset_history.html',
                               asset=asset.data,
                               logs=logs.data if logs.data else [],
                               subsystem_name=SUBSYSTEM_NAME,
                               accent_color=ACCENT_COLOR,
                               blueprint_name=BLUEPRINT_NAME)
    except Exception as e:
        flash(f'Error fetching history: {str(e)}', 'danger')
        return redirect(url_for('log1.list_assets'))

@log1_bp.route('/documents')
@login_required
def list_documents():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    docs = client.table('log_documents').select('*, users(username)').order('created_at', desc=True).execute()
    return render_template('subsystems/logistics/log1/documents.html',
                           documents=docs.data if docs.data else [],
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log1_bp.route('/documents/add', methods=['POST'])
@login_required
def add_document():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        doc_data = {
            'title': request.form.get('title'),
            'doc_type': request.form.get('doc_type'),
            'doc_number': request.form.get('doc_number'),
            'file_url': request.form.get('file_url'),
            'status': 'Pending',
            'uploaded_by': current_user.id
        }
        client.table('log_documents').insert(doc_data).execute()
        flash('Document record added successfully!', 'success')
    except Exception as e:
        flash(f'Error adding document: {str(e)}', 'danger')
        
    return redirect(url_for('log1.list_documents'))

@log1_bp.route('/documents/status/<int:doc_id>/<string:status>')
@login_required
def update_doc_status(doc_id, status):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('log_documents').update({'status': status}).eq('id', doc_id).execute()
        flash(f'Document status updated to {status}.', 'success')
    except Exception as e:
        flash(f'Error updating status: {str(e)}', 'danger')
        
    return redirect(url_for('log1.list_documents'))

@log1_bp.route('/documents/delete/<int:doc_id>')
@login_required
def delete_doc(doc_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('log_documents').delete().eq('id', doc_id).execute()
        flash('Document removed from archive.', 'success')
    except Exception as e:
        flash(f'Error deleting document: {str(e)}', 'danger')
        
    return redirect(url_for('log1.list_documents'))

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
