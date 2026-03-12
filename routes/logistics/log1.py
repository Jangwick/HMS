from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from utils.supabase_client import User, format_db_error
from utils.ip_lockout import is_ip_locked, register_failed_attempt, register_successful_login
from utils.password_validator import PasswordValidationError
from utils.policy import policy_required
from utils.hms_models import InventoryItem, AuditLog, Notification
from datetime import datetime, timedelta

log1_bp = Blueprint('log1', __name__, template_folder='templates')

# Subsystem configuration
SUBSYSTEM_NAME = 'LOG1 - Inventory Management'
ACCENT_COLOR = '#F59E0B'
BLUEPRINT_NAME = 'log1'


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _notify(subsystem, title, message, n_type='info', target_url=None, user_id=None, role=None):
    try:
        Notification.create(
            user_id=user_id,
            subsystem=subsystem,
            role=role,
            title=title,
            message=message,
            n_type=n_type,
            sender_subsystem=BLUEPRINT_NAME,
            target_url=target_url
        )
    except Exception:
        pass


def _notify_finance_users(client, title, message, target_url=None, n_type='warning'):
    sent_count = 0
    try:
        users_resp = client.table('users').select('id').eq('subsystem', 'financials').execute()
        finance_users = users_resp.data or []
        for user in finance_users:
            user_id = user.get('id')
            if not user_id:
                continue
            _notify(
                subsystem=None,
                user_id=user_id,
                title=title,
                message=message,
                n_type=n_type,
                target_url=target_url
            )
            sent_count += 1
    except Exception:
        pass

    if sent_count == 0:
        _notify(
            subsystem='financials',
            title=title,
            message=message,
            n_type=n_type,
            target_url=target_url
        )

    return sent_count


def _insert_supplier_document_record(client, doc_type, po=None, receiving_id=None, document_no=None, file_url=None, metadata=None):
    payload = {
        'title': f"{doc_type} {document_no or ''}".strip(),
        'doc_type': doc_type,
        'doc_number': document_no,
        'file_url': file_url or '#',
        'status': 'Recorded',
        'uploaded_by': current_user.id if current_user and getattr(current_user, 'id', None) else None,
        'metadata': metadata or {}
    }
    try:
        client.table('supplier_documents').insert({
            'doc_type': doc_type,
            'document_no': document_no,
            'supplier_id': po.get('supplier_id') if po else None,
            'requisition_id': po.get('id') if po else None,
            'receiving_id': receiving_id,
            'file_path': file_url,
            'metadata': metadata or {},
            'captured_via': 'AUTO_LINK',
            'created_by': payload['uploaded_by']
        }).execute()
    except Exception:
        try:
            client.table('log_documents').insert(payload).execute()
        except Exception:
            pass


def _create_finance_approval_for_po(client, po_id, requested_amount, requested_by):
    approval_payload = {
        'requisition_id': po_id,
        'requested_amount': requested_amount,
        'status': 'PENDING_FINANCE',
        'requested_by': requested_by,
        'requested_at': datetime.utcnow().isoformat()
    }
    try:
        client.table('procurement_budget_approvals').insert(approval_payload).execute()
        return True
    except Exception:
        try:
            client.table('purchase_orders').update({
                'finance_approval_status': 'PENDING_FINANCE',
                'finance_requested_at': datetime.utcnow().isoformat()
            }).eq('id', po_id).execute()
            return True
        except Exception:
            return False


def _create_purchase_requisition_for_out_of_stock(client, item_name, quantity, notes=None, project_id=None):
    requisition_no = f"PR-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    payload = {
        'requisition_no': requisition_no,
        'item_name': item_name,
        'quantity': quantity,
        'status': 'Pending Finance Approval',
        'requested_by': current_user.id,
        'notes': notes or 'Auto-generated from out-of-stock material request.'
    }
    if project_id is not None:
        payload['project_id'] = project_id

    try:
        req_resp = client.table('purchase_requisitions').insert(payload).execute()
        requisition_id = req_resp.data[0]['id'] if req_resp.data else None
    except Exception:
        # Fallback: create PO draft directly if requisition table is unavailable
        po_number = f"PO-AUTO-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        po_resp = client.table('purchase_orders').insert({
            'po_number': po_number,
            'supplier_id': None,
            'total_amount': 0,
            'status': 'Pending Finance Approval',
            'requested_by': current_user.id,
            'notes': f"Auto-generated for out-of-stock item: {item_name} x {quantity}"
        }).execute()
        requisition_id = po_resp.data[0]['id'] if po_resp.data else None

    if requisition_id:
        try:
            client.table('procurement_budget_approvals').insert({
                'requisition_id': requisition_id,
                'requested_amount': 0,
                'status': 'PENDING_FINANCE',
                'requested_by': current_user.id,
                'requested_at': datetime.utcnow().isoformat()
            }).execute()
        except Exception:
            pass

    return requisition_id


def _parse_iso_date(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except Exception:
        return None


def _get_available_batches(client, item_name):
    try:
        resp = client.table('inventory').select('*').eq('item_name', item_name).execute()
        return [row for row in (resp.data or []) if _safe_float(row.get('quantity')) > 0]
    except Exception:
        return []


def _recommend_batch(batches, strategy='FEFO'):
    strategy = (strategy or 'FEFO').upper()
    if not batches:
        return None

    if strategy == 'FIFO':
        # First In, First Out: oldest arrival first
        def fifo_key(row):
            created = _parse_iso_date(row.get('created_at')) or _parse_iso_date(row.get('received_at'))
            return (created or datetime.min, _safe_int(row.get('id')))
        ordered = sorted(batches, key=fifo_key)
    else:
        # FEFO default: earliest expiration first, then oldest arrival
        def fefo_key(row):
            expiry = _parse_iso_date(row.get('expiry_date'))
            created = _parse_iso_date(row.get('created_at')) or _parse_iso_date(row.get('received_at'))
            # None expiry should go last
            return (expiry is None, expiry or datetime.max, created or datetime.min, _safe_int(row.get('id')))
        ordered = sorted(batches, key=fefo_key)

    return ordered[0]


def _resolve_request_item_name(client, req):
    requested_item_name = (req.get('requested_item_name') or '').strip()
    if requested_item_name:
        return requested_item_name

    item_id = req.get('item_id')
    if not item_id:
        return None

    try:
        inv_resp = client.table('inventory').select('*').eq('id', item_id).single().execute()
        return (inv_resp.data or {}).get('item_name')
    except Exception:
        return None

@log1_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Check IP-based lockout first
    locked, remaining_seconds, unlock_time_str = is_ip_locked(subsystem=BLUEPRINT_NAME)
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
                        flash('Your account is awaiting approval from HR2 Admin.', 'info')
                    else:
                        flash('Your account has been rejected or deactivated.', 'danger')
                    return render_template('subsystems/logistics/log1/login.html')

                # Clear IP lockout attempts on successful login
                register_successful_login(subsystem=BLUEPRINT_NAME)
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
                is_now_locked, remaining_attempts, remaining_seconds, unlock_time_str = register_failed_attempt(subsystem=BLUEPRINT_NAME)
                
                if is_now_locked:
                    flash(f'Too many failed attempts. Try again at {unlock_time_str}', 'danger')
                    return render_template('subsystems/logistics/log1/login.html', remaining_seconds=remaining_seconds)
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
                return render_template('subsystems/logistics/log1/login.html', remaining_seconds=remaining_seconds)
            
    return render_template('subsystems/logistics/log1/login.html')


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

        # Project stats
        try:
            proj_resp = client.table('logistics_projects').select('id', count='exact').execute()
            total_projects = proj_resp.count or 0
            active_projects_resp = client.table('logistics_projects').select('id', count='exact').eq('status', 'In Progress').execute()
            active_projects = active_projects_resp.count or 0
        except Exception:
            total_projects = 0
            active_projects = 0

    except Exception as e:
        print(f"Error fetching dashboard stats: {e}")
        total_assets = 0
        pending_pos = 0
        total_docs = 0
        total_projects = 0
        active_projects = 0

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
                           total_projects=total_projects,
                           active_projects=active_projects,
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
            from utils.hms_models import AuditLog
            AuditLog.log(current_user.id, "Add Inventory Item", BLUEPRINT_NAME, {"item": data['item_name']})
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
            from utils.hms_models import AuditLog
            AuditLog.log(current_user.id, "Edit Inventory Item", BLUEPRINT_NAME, {"item_id": item_id, "item": data['item_name']})
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
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Delete Inventory Item", BLUEPRINT_NAME, {"item_id": item_id})
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
    storage_location = request.form.get('storage_location') or request.form.get('location') or 'Warehouse'
    recipient_name = request.form.get('recipient_name', '').strip()
    recipient_lang = request.form.get('recipient_lang', '').strip()
    project_id = request.form.get('project_id')
    project_id = _safe_int(project_id, None) if project_id else None
    
    try:
        # Get current quantity
        item_resp = client.table('inventory').select('quantity, item_name, reorder_level').eq('id', item_id).single().execute()
        if not item_resp.data:
            flash('Item not found.', 'danger')
            return redirect(url_for('log1.list_inventory'))
            
        current_qty = item_resp.data.get('quantity', 0)
        reorder_level = item_resp.data.get('reorder_level', 10)
        item_name = item_resp.data.get('item_name')

        if current_qty < quantity_to_dispense:
            try:
                client.table('material_requests').insert({
                    'request_no': f"MR-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    'project_id': project_id,
                    'requested_by': current_user.id,
                    'requesting_department_id': 0,
                    'item_id': _safe_int(item_id),
                    'storage_location_id': 0,
                    'quantity': quantity_to_dispense,
                    'recipient_name': recipient_name or current_user.username,
                    'recipient_lang': recipient_lang,
                    'status': 'REJECTED_OUT_OF_STOCK',
                    'rejection_reason': 'Out of Stock',
                    'created_at': datetime.utcnow().isoformat(),
                    'updated_at': datetime.utcnow().isoformat()
                }).execute()
            except Exception:
                pass

            requisition_id = _create_purchase_requisition_for_out_of_stock(
                client,
                item_name=item_name,
                quantity=quantity_to_dispense,
                notes=f"Requested by {recipient_name or current_user.username}; location: {storage_location}",
                project_id=project_id
            )

            _notify(
                subsystem=BLUEPRINT_NAME,
                user_id=current_user.id,
                title='Material Request Rejected: Out of Stock',
                message=f"Request for {item_name} ({quantity_to_dispense}) cannot be fulfilled. Procurement requisition has been generated.",
                n_type='warning',
                target_url=url_for('log1.list_inventory')
            )
            _notify(
                subsystem='log2',
                title='New Purchase Requisition',
                message=f"Out-of-stock escalation: {item_name} x {quantity_to_dispense}. Requisition ID: {requisition_id or 'N/A'}.",
                n_type='info',
                target_url=url_for('log1.procurement')
            )
            _notify(
                subsystem='financials',
                title='Action Required: Finance Approval Needed',
                message=f"Budget approval required for out-of-stock requisition ({item_name} x {quantity_to_dispense}).",
                n_type='warning',
                target_url=url_for('log1.procurement')
            )

            flash(f'Insufficient stock for {item_name}. Request marked Out of Stock, requestor notified, and procurement requisition created.', 'warning')
            return redirect(url_for('log1.list_inventory'))
            
        # Update quantity
        new_qty = current_qty - quantity_to_dispense
        client.table('inventory').update({'quantity': new_qty}).eq('id', item_id).execute()
        
        # Log in dispensing history
        client.table('dispensing_history').insert({
            'inventory_id': item_id,
            'quantity': quantity_to_dispense,
            'dispensed_by': current_user.id,
            'notes': request.form.get('notes', 'Standard dispensing')
        }).execute()

        # Record inbound department/project request fulfillment if table exists
        try:
            client.table('material_requests').insert({
                'request_no': f"MR-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                'project_id': project_id,
                'requested_by': current_user.id,
                'requesting_department_id': 0,
                'item_id': _safe_int(item_id),
                'storage_location_id': 0,
                'quantity': quantity_to_dispense,
                'recipient_name': recipient_name or current_user.username,
                'recipient_lang': recipient_lang,
                'status': 'DELIVERED',
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }).execute()
        except Exception:
            pass

        if project_id:
            try:
                client.table('project_material_tracking').insert({
                    'project_id': project_id,
                    'material_request_id': None,
                    'stage': 'DELIVERING_MATERIALS',
                    'status': 'COMPLETED',
                    'notes': f"Delivered {quantity_to_dispense} of {item_name} from {storage_location}.",
                    'updated_by': current_user.id,
                    'updated_at': datetime.utcnow().isoformat()
                }).execute()
            except Exception:
                pass

        # Low stock notification for Procurement (LOG2)
        if new_qty <= reorder_level:
            from utils.hms_models import Notification
            Notification.create(
                subsystem='log2',
                title="Low Stock Alert",
                message=f"Stock for '{item_name}' has reached {new_qty}, which is at or below the reorder level ({reorder_level}).",
                n_type="warning",
                sender_subsystem=BLUEPRINT_NAME,
                target_url=url_for('log1.list_inventory') # Link back to inventory to see status
            )
        
        flash(f'Successfully dispensed {quantity_to_dispense} units.', 'success')
    except Exception as e:
        flash(f'Error dispensing item: {str(e)}', 'danger')
        
    return redirect(url_for('log1.list_inventory'))


@log1_bp.route('/requests')
@login_required
def list_material_requests():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    status_filter = request.args.get('status', '').strip()

    requests_data = []
    try:
        query = client.table('material_requests').select('*').order('created_at', desc=True)
        if status_filter:
            query = query.eq('status', status_filter)
        resp = query.execute()
        requests_data = resp.data or []
    except Exception as e:
        flash(f'Unable to load material requests: {e}', 'warning')

    return render_template('subsystems/logistics/log1/material_requests.html',
                           requests=requests_data,
                           status_filter=status_filter,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)


@log1_bp.route('/requests/create', methods=['POST'])
@login_required
def create_material_request():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    item_id = _safe_int(request.form.get('item_id'))
    storage_location_id = _safe_int(request.form.get('storage_location_id'))
    quantity = _safe_float(request.form.get('quantity'))
    recipient_name = (request.form.get('recipient_name') or '').strip()
    recipient_lang = (request.form.get('recipient_lang') or '').strip()
    requested_item_name = (request.form.get('requested_item_name') or '').strip()
    project_id = request.form.get('project_id')
    project_id = _safe_int(project_id, None) if project_id else None

    if (not item_id and not requested_item_name) or not storage_location_id or quantity <= 0 or not recipient_name:
        flash('Item (ID or name), storage location, quantity, and recipient are required.', 'danger')
        return redirect(url_for('log1.list_inventory'))

    try:
        request_no = f"MR-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        client.table('material_requests').insert({
            'request_no': request_no,
            'project_id': project_id,
            'requested_by': current_user.id,
            'requesting_department_id': _safe_int(request.form.get('requesting_department_id')),
            'item_id': item_id,
            'requested_item_name': requested_item_name or None,
            'storage_location_id': storage_location_id,
            'quantity': quantity,
            'recipient_name': recipient_name,
            'recipient_lang': recipient_lang,
            'status': 'PENDING',
            'allocation_strategy': (request.form.get('allocation_strategy') or 'FEFO').upper(),
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }).execute()

        _notify(
            subsystem=BLUEPRINT_NAME,
            title='New Material Request',
            message=f"{recipient_name} requested item {requested_item_name or f'#{item_id}'}, qty {quantity}.",
            n_type='info',
            target_url=url_for('log1.list_material_requests')
        )

        flash('Material request created successfully.', 'success')
    except Exception as e:
        flash(f'Error creating material request: {e}', 'danger')

    return redirect(url_for('log1.list_material_requests'))


@log1_bp.route('/requests/<int:request_id>/validate', methods=['POST'])
@login_required
def validate_material_request(request_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_material_requests'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    strategy = (request.form.get('allocation_strategy') or 'FEFO').upper()
    if strategy not in ['FIFO', 'FEFO']:
        strategy = 'FEFO'

    try:
        req_resp = client.table('material_requests').select('*').eq('id', request_id).single().execute()
        req = req_resp.data or {}
        requested_qty = _safe_float(req.get('quantity'))
        item_name = _resolve_request_item_name(client, req)

        if not item_name:
            flash('Cannot validate request: item name could not be resolved.', 'danger')
            return redirect(url_for('log1.list_material_requests'))

        batches = _get_available_batches(client, item_name)
        suggested = _recommend_batch(batches, strategy=strategy)

        if not suggested:
            client.table('material_requests').update({
                'status': 'REJECTED_OUT_OF_STOCK',
                'rejection_reason': 'Out of Stock',
                'allocation_strategy': strategy,
                'validated_by': current_user.id,
                'validated_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }).eq('id', request_id).execute()

            requisition_id = _create_purchase_requisition_for_out_of_stock(
                client,
                item_name=item_name,
                quantity=requested_qty,
                notes=f"Auto-escalated during request validation ({strategy}).",
                project_id=req.get('project_id')
            )
            _notify(
                subsystem=BLUEPRINT_NAME,
                user_id=req.get('requested_by'),
                title='Request Rejected: Out of Stock',
                message=f"No available batch found for {item_name}. Requisition {requisition_id or 'N/A'} created.",
                n_type='warning',
                target_url=url_for('log1.list_material_requests')
            )
            flash('No available batch found. Request was rejected and escalated to procurement.', 'warning')
            return redirect(url_for('log1.list_material_requests'))

        suggested_qty = _safe_float(suggested.get('quantity'))
        notes = f"Suggested batch {suggested.get('batch_number') or 'N/A'} (stock: {suggested_qty}). Strategy: {strategy}."
        if suggested_qty < requested_qty:
            notes += ' Partial stock only; admin override may be needed.'

        client.table('material_requests').update({
            'status': 'FOR_DELIVERY',
            'allocation_strategy': strategy,
            'suggested_batch_id': suggested.get('id'),
            'suggested_batch_number': suggested.get('batch_number'),
            'validated_by': current_user.id,
            'validated_at': datetime.utcnow().isoformat(),
            'suggestion_notes': notes,
            'updated_at': datetime.utcnow().isoformat()
        }).eq('id', request_id).execute()

        flash(f"Request validated. Recommended batch: {suggested.get('batch_number') or suggested.get('id')} ({strategy}).", 'success')
    except Exception as e:
        flash(f'Error validating request: {e}', 'danger')

    return redirect(url_for('log1.list_material_requests'))


@log1_bp.route('/requests/<int:request_id>/approve', methods=['POST'])
@login_required
def approve_material_request(request_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_material_requests'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        client.table('material_requests').update({
            'status': 'FOR_DELIVERY',
            'updated_at': datetime.utcnow().isoformat()
        }).eq('id', request_id).execute()
        flash('Request approved and marked for delivery.', 'success')
    except Exception as e:
        flash(f'Error approving request: {e}', 'danger')
    return redirect(url_for('log1.list_material_requests'))


@log1_bp.route('/requests/<int:request_id>/reject-out-of-stock', methods=['POST'])
@login_required
def reject_material_request_out_of_stock(request_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_material_requests'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        req_resp = client.table('material_requests').select('*').eq('id', request_id).single().execute()
        req = req_resp.data or {}

        client.table('material_requests').update({
            'status': 'REJECTED_OUT_OF_STOCK',
            'rejection_reason': 'Out of Stock',
            'updated_at': datetime.utcnow().isoformat()
        }).eq('id', request_id).execute()

        requisition_id = _create_purchase_requisition_for_out_of_stock(
            client,
            item_name=f"Item #{req.get('item_id')}",
            quantity=_safe_float(req.get('quantity')),
            notes='Escalated from material request rejection.',
            project_id=req.get('project_id')
        )

        _notify(
            subsystem=BLUEPRINT_NAME,
            user_id=req.get('requested_by'),
            title='Request Rejected: Out of Stock',
            message=f"Your material request #{request_id} was rejected due to insufficient stock.",
            n_type='warning',
            target_url=url_for('log1.list_material_requests')
        )
        _notify(
            subsystem='log2',
            title='Out-of-Stock Requisition Created',
            message=f"Material request #{request_id} escalated to procurement (Requisition ID: {requisition_id or 'N/A'}).",
            n_type='info',
            target_url=url_for('log1.procurement')
        )
        flash('Request rejected as out-of-stock, requestor notified, and procurement escalation created.', 'success')
    except Exception as e:
        flash(f'Error rejecting request: {e}', 'danger')
    return redirect(url_for('log1.list_material_requests'))


@log1_bp.route('/requests/<int:request_id>/deliver', methods=['POST'])
@login_required
def deliver_material_request(request_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_material_requests'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        req_resp = client.table('material_requests').select('*').eq('id', request_id).single().execute()
        req = req_resp.data or {}

        requested_qty = _safe_float(req.get('quantity'))
        override_batch_id = _safe_int(request.form.get('override_batch_id'), None)
        selected_batch_id = override_batch_id or req.get('suggested_batch_id')

        # If no suggested/override batch, compute one on the fly
        if not selected_batch_id:
            item_name = _resolve_request_item_name(client, req)
            strategy = (req.get('allocation_strategy') or 'FEFO').upper()
            batches = _get_available_batches(client, item_name) if item_name else []
            suggested = _recommend_batch(batches, strategy=strategy)
            selected_batch_id = suggested.get('id') if suggested else None

        if not selected_batch_id:
            flash('Delivery failed: no batch selected or suggested.', 'danger')
            return redirect(url_for('log1.list_material_requests'))

        batch_resp = client.table('inventory').select('*').eq('id', selected_batch_id).single().execute()
        batch = batch_resp.data or {}
        batch_qty = _safe_float(batch.get('quantity'))

        if batch_qty < requested_qty:
            flash('Selected batch has insufficient quantity. Please validate again or choose override batch.', 'warning')
            return redirect(url_for('log1.list_material_requests'))

        new_batch_qty = batch_qty - requested_qty
        client.table('inventory').update({'quantity': new_batch_qty}).eq('id', selected_batch_id).execute()

        client.table('material_requests').update({
            'status': 'DELIVERED',
            'dispensed_batch_id': selected_batch_id,
            'dispensed_batch_number': batch.get('batch_number'),
            'updated_at': datetime.utcnow().isoformat()
        }).eq('id', request_id).execute()

        if req.get('project_id'):
            try:
                client.table('project_material_tracking').insert({
                    'project_id': req.get('project_id'),
                    'material_request_id': request_id,
                    'stage': 'DELIVERING_MATERIALS',
                    'status': 'COMPLETED',
                    'notes': f"Material request #{request_id} delivered.",
                    'updated_by': current_user.id,
                    'updated_at': datetime.utcnow().isoformat()
                }).execute()
            except Exception:
                pass

        _notify(
            subsystem=BLUEPRINT_NAME,
            user_id=req.get('requested_by'),
            title='Material Request Delivered',
            message=f"Your material request #{request_id} has been delivered.",
            n_type='success',
            target_url=url_for('log1.list_material_requests')
        )

        flash(f"Request delivered using batch {batch.get('batch_number') or selected_batch_id}.", 'success')
    except Exception as e:
        flash(f'Error delivering request: {e}', 'danger')
    return redirect(url_for('log1.list_material_requests'))

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
            'finance_approval_status': 'PENDING_FINANCE',
            'requested_by': current_user.id,
            'notes': request.form.get('notes')
        }
        
        # Insert PO record
        po_resp = client.table('purchase_orders').insert(po_data).execute()
        if po_resp.data:
            po_id = po_resp.data[0]['id']
            _create_finance_approval_for_po(client, po_id, po_data['total_amount'], current_user.id)
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

        finance_approval = None
        try:
            approval_resp = client.table('procurement_budget_approvals').select('*').eq('requisition_id', po_id).order('requested_at', desc=True).limit(1).execute()
            finance_approval = approval_resp.data[0] if approval_resp.data else None
        except Exception:
            pass

        discrepancy_reports = []
        try:
            dr_resp = client.table('discrepancy_reports').select('*').eq('receiving_id', po_id).order('created_at', desc=True).execute()
            discrepancy_reports = dr_resp.data or []
        except Exception:
            pass
        
        return render_template('subsystems/logistics/log1/po_detail.html',
                               po=po.data,
                               items=items.data if items.data else [],
                               finance_approval=finance_approval,
                               discrepancy_reports=discrepancy_reports,
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
        
        # Finance gate: cannot send/approve/receive without finance approval
        finance_approved = False
        try:
            fa_resp = client.table('procurement_budget_approvals').select('*').eq('requisition_id', po_id).order('requested_at', desc=True).limit(1).execute()
            if fa_resp.data and (fa_resp.data[0].get('status') == 'APPROVED'):
                finance_approved = True
        except Exception:
            # fallback to PO column
            finance_approved = (po_resp.data.get('finance_approval_status') == 'APPROVED')

        if new_status in ['Sent', 'Approved', 'Received'] and not finance_approved:
            flash('Finance budget approval is required before progressing this PO.', 'warning')
            return redirect(url_for('log1.view_po', po_id=po_id))

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

                _insert_supplier_document_record(
                    client,
                    doc_type='PO',
                    po=po_resp.data,
                    receiving_id=None,
                    document_no=po_resp.data.get('po_number'),
                    metadata={'source': 'purchase_orders', 'po_id': po_id}
                )

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

                _insert_supplier_document_record(
                    client,
                    doc_type='DR',
                    po=po_resp.data,
                    receiving_id=po_id,
                    document_no=f"DR-{po_resp.data.get('po_number')}",
                    metadata={'source': 'receiving', 'po_id': po_id}
                )
                flash('PO status updated to Received. Inventory has been automatically updated.', 'success')
            else:
                flash(f'PO status updated to {new_status}.', 'success')
        else:
            flash(f'PO status updated to {new_status}.', 'success')
            
    except Exception as e:
        flash(f'Error updating PO status: {str(e)}', 'danger')
        
    return redirect(url_for('log1.view_po', po_id=po_id))


@log1_bp.route('/procurement/po/<int:po_id>/submit-finance', methods=['POST'])
@login_required
def submit_po_finance_approval(po_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.procurement'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        po_resp = client.table('purchase_orders').select('*').eq('id', po_id).single().execute()
        po = po_resp.data or {}
        ok = _create_finance_approval_for_po(client, po_id, _safe_float(po.get('total_amount')), current_user.id)
        if ok:
            client.table('purchase_orders').update({'finance_approval_status': 'PENDING_FINANCE'}).eq('id', po_id).execute()
            _notify(
                subsystem=BLUEPRINT_NAME,
                user_id=current_user.id,
                title='PO Submitted to Finance',
                message=f"PO {po.get('po_number')} was submitted for finance approval.",
                n_type='info',
                target_url=url_for('log1.view_po', po_id=po_id)
            )
            _notify_finance_users(
                client=client,
                title='Action Required: Procurement Budget Approval',
                message=f"PO {po.get('po_number')} requires finance approval. Total amount: ${_safe_float(po.get('total_amount')):,.2f}.",
                n_type='warning',
                target_url=url_for('log1.view_po', po_id=po_id)
            )
            _notify(
                subsystem='superadmin',
                title='PO Submitted for Finance Approval',
                message=f"LOG1 submitted PO {po.get('po_number')} for finance approval.",
                n_type='warning',
                target_url=url_for('log1.view_po', po_id=po_id)
            )
            flash('PO submitted for finance budget approval.', 'success')
        else:
            flash('Unable to create finance approval record.', 'danger')
    except Exception as e:
        flash(f'Error submitting finance approval: {e}', 'danger')

    return redirect(url_for('log1.view_po', po_id=po_id))


@log1_bp.route('/finance/approvals/<int:po_id>/approve', methods=['POST'])
@login_required
def approve_finance_budget(po_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.procurement'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        approved_amount = _safe_float(request.form.get('approved_amount'))
        remarks = request.form.get('finance_remarks', '').strip()
        updated = False
        try:
            client.table('procurement_budget_approvals').update({
                'status': 'APPROVED',
                'approved_amount': approved_amount,
                'finance_remarks': remarks,
                'approved_by': current_user.id,
                'decided_at': datetime.utcnow().isoformat()
            }).eq('requisition_id', po_id).execute()
            updated = True
        except Exception:
            pass

        client.table('purchase_orders').update({'finance_approval_status': 'APPROVED'}).eq('id', po_id).execute()
        _notify(
            subsystem='log2',
            title='Budget Approved',
            message=f"Finance approved budget for PO #{po_id}.",
            n_type='success',
            target_url=url_for('log1.view_po', po_id=po_id)
        )
        flash('Finance budget approved.', 'success')
    except Exception as e:
        flash(f'Error approving finance budget: {e}', 'danger')
    return redirect(url_for('log1.view_po', po_id=po_id))


@log1_bp.route('/finance/approvals/<int:po_id>/reject', methods=['POST'])
@login_required
def reject_finance_budget(po_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.procurement'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    try:
        remarks = request.form.get('finance_remarks', '').strip()
        try:
            client.table('procurement_budget_approvals').update({
                'status': 'REJECTED',
                'finance_remarks': remarks,
                'approved_by': current_user.id,
                'decided_at': datetime.utcnow().isoformat()
            }).eq('requisition_id', po_id).execute()
        except Exception:
            pass
        client.table('purchase_orders').update({'finance_approval_status': 'REJECTED'}).eq('id', po_id).execute()
        _notify(
            subsystem='log2',
            title='Budget Rejected',
            message=f"Finance rejected budget for PO #{po_id}. Remarks: {remarks or 'N/A'}",
            n_type='danger',
            target_url=url_for('log1.view_po', po_id=po_id)
        )
        flash('Finance budget rejected.', 'warning')
    except Exception as e:
        flash(f'Error rejecting finance budget: {e}', 'danger')
    return redirect(url_for('log1.view_po', po_id=po_id))


@log1_bp.route('/receiving/<int:po_id>/discrepancy', methods=['POST'])
@login_required
def create_discrepancy_report(po_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.view_po', po_id=po_id))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        po_resp = client.table('purchase_orders').select('*').eq('id', po_id).single().execute()
        po = po_resp.data or {}
        expected_qty = _safe_float(request.form.get('expected_qty'))
        received_qty = _safe_float(request.form.get('received_qty'))
        discrepancy_qty = max(0.0, expected_qty - received_qty)

        payload = {
            'report_no': f"DRPT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'receiving_id': po_id,
            'supplier_id': po.get('supplier_id'),
            'issue_type': request.form.get('issue_type') or 'SHORT_DELIVERY',
            'expected_qty': expected_qty,
            'received_qty': received_qty,
            'discrepancy_qty': discrepancy_qty,
            'remarks': request.form.get('remarks'),
            'status': 'OPEN',
            'created_by': current_user.id,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }

        created_id = None
        try:
            result = client.table('discrepancy_reports').insert(payload).execute()
            created_id = result.data[0]['id'] if result.data else None
        except Exception:
            # fallback via generic docs log to preserve trace
            client.table('log_documents').insert({
                'title': f"Discrepancy Report for {po.get('po_number')}",
                'doc_type': 'Discrepancy Report',
                'doc_number': payload['report_no'],
                'file_url': '#',
                'status': 'Open',
                'uploaded_by': current_user.id,
                'metadata': payload
            }).execute()

        flash('Discrepancy report created successfully.', 'success')
    except Exception as e:
        flash(f'Error creating discrepancy report: {e}', 'danger')
    return redirect(url_for('log1.view_po', po_id=po_id))


@log1_bp.route('/discrepancies/<int:report_id>/notify-supplier', methods=['POST'])
@login_required
def notify_discrepancy_supplier(report_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.procurement'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    try:
        dr_resp = client.table('discrepancy_reports').select('*').eq('id', report_id).single().execute()
        report = dr_resp.data or {}
        supplier_id = report.get('supplier_id')

        try:
            client.table('supplier_notifications').insert({
                'discrepancy_report_id': report_id,
                'supplier_id': supplier_id,
                'channel': request.form.get('channel') or 'PORTAL',
                'subject': f"Discrepancy Notice {report.get('report_no')}",
                'message': request.form.get('message') or 'Please review discrepancy report and provide correction.',
                'status': 'SENT',
                'sent_by': current_user.id,
                'sent_at': datetime.utcnow().isoformat()
            }).execute()
            client.table('discrepancy_reports').update({
                'status': 'SUPPLIER_NOTIFIED',
                'updated_at': datetime.utcnow().isoformat()
            }).eq('id', report_id).execute()
        except Exception:
            pass

        _notify(
            subsystem=BLUEPRINT_NAME,
            title='Supplier Notified',
            message=f"Supplier notified for discrepancy report #{report.get('report_no') or report_id}.",
            n_type='info',
            target_url=url_for('log1.procurement')
        )
        flash('Supplier notified successfully.', 'success')
    except Exception as e:
        flash(f'Error notifying supplier: {e}', 'danger')
    return redirect(url_for('log1.procurement'))

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

@log1_bp.route('/assets/edit/<int:asset_id>', methods=['POST'])
@login_required
def edit_asset(asset_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_assets'))
        
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        update_data = {
            'asset_name': request.form.get('asset_name'),
            'tag_number': request.form.get('tag_number'),
            'status': request.form.get('status', 'Active'),
            'warranty_expiry': request.form.get('warranty_expiry') or None
        }
        client.table('assets').update(update_data).eq('id', asset_id).execute()
        flash('Asset updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating asset: {str(e)}', 'danger')
        
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
        maintenance_type = request.form.get('maintenance_type', 'Other')
        m_date = datetime.now().date().isoformat()
        
        # Log maintenance record
        log_data = {
            'asset_id': asset_id,
            'maintenance_date': m_date,
            'performed_by': current_user.id,
            'notes': notes,
            'cost': cost,
            'maintenance_type': maintenance_type
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
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_assets'))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Delete maintenance logs first
        try:
            client.table('asset_maintenance_logs').delete().eq('asset_id', asset_id).execute()
        except Exception:
            pass
        client.table('assets').delete().eq('id', asset_id).execute()
        flash('Asset and all related records removed.', 'success')
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
        
        logs_data = logs.data if logs.data else []
        total_cost = sum(float(log.get('cost', 0) or 0) for log in logs_data)
        
        return render_template('subsystems/logistics/log1/asset_history.html',
                               asset=asset.data,
                               logs=logs_data,
                               total_cost=total_cost,
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
        title = request.form.get('title')
        doc_type = request.form.get('doc_type')
        doc_number = request.form.get('doc_number')
        file_url = request.form.get('file_url') or '#'
        
        # Handle File Upload if provided
        file = request.files.get('document_file')
        if file and file.filename:
            bucket_name = 'logistics_docs'
            filename = secure_filename(file.filename)
            # Create a unique path: subsystem/timestamp_filename
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            file_path = f"{BLUEPRINT_NAME}/{timestamp}_{filename}"
            
            try:
                # Read file content
                content = file.read()
                # Upload to Storage
                client.storage.from_(bucket_name).upload(
                    path=file_path,
                    file=content,
                    file_options={"content-type": file.content_type}
                )
                # Get Public URL
                file_url = client.storage.from_(bucket_name).get_public_url(file_path)
            except Exception as storage_err:
                print(f"Storage Error: {storage_err}")
                if 'Bucket not found' in str(storage_err):
                    flash(f'Storage bucket "{bucket_name}" not found. Please ensure it is created in Supabase.', 'warning')
                else:
                    flash(f'File upload failed: {str(storage_err)}', 'danger')

        doc_data = {
            'title': title,
            'doc_type': doc_type,
            'doc_number': doc_number,
            'file_url': file_url,
            'status': 'Pending',
            'uploaded_by': current_user.id
        }
        
        client.table('log_documents').insert(doc_data).execute()
        
        # Log Audit
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Upload Document", BLUEPRINT_NAME, {"title": title, "type": doc_type})
        
        flash('Document record added successfully!', 'success')
    except Exception as e:
        flash(f'Error adding document: {str(e)}', 'danger')
        
    return redirect(url_for('log1.list_documents'))


@log1_bp.route('/documents/auto-record', methods=['POST'])
@login_required
def auto_record_supplier_document():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    doc_type = (request.form.get('doc_type') or '').strip().upper()
    if doc_type not in ['PO', 'DR']:
        flash('Invalid document type. Use PO or DR.', 'danger')
        return redirect(url_for('log1.list_documents'))

    po_id = _safe_int(request.form.get('po_id'), None)
    receiving_id = _safe_int(request.form.get('receiving_id'), None)
    document_no = (request.form.get('document_no') or '').strip()
    file_url = (request.form.get('file_url') or '').strip() or '#'

    po_data = None
    if po_id:
        try:
            po_resp = client.table('purchase_orders').select('*').eq('id', po_id).single().execute()
            po_data = po_resp.data or None
            if not document_no:
                document_no = po_data.get('po_number') if po_data else None
        except Exception:
            po_data = None

    try:
        _insert_supplier_document_record(
            client,
            doc_type=doc_type,
            po=po_data,
            receiving_id=receiving_id,
            document_no=document_no,
            file_url=file_url,
            metadata={
                'source': 'manual_auto_record_endpoint',
                'po_id': po_id,
                'receiving_id': receiving_id
            }
        )
        flash(f'{doc_type} document recorded successfully.', 'success')
    except Exception as e:
        flash(f'Error auto-recording document: {e}', 'danger')

    return redirect(url_for('log1.list_documents'))

@log1_bp.route('/documents/status/<int:doc_id>/<string:status>')
@login_required
def update_doc_status(doc_id, status):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('log_documents').update({'status': status}).eq('id', doc_id).execute()
        
        # Log Audit
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, f"Update Document Status: {status}", BLUEPRINT_NAME, {"doc_id": doc_id, "new_status": status})
        
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
        
        # Log Audit
        from utils.hms_models import AuditLog
        AuditLog.log(current_user.id, "Delete Document", BLUEPRINT_NAME, {"doc_id": doc_id})
        
        flash('Document removed from archive.', 'success')
    except Exception as e:
        flash(f'Error deleting document: {str(e)}', 'danger')
        
    return redirect(url_for('log1.list_documents'))

# =============================================
# PROJECT LOGISTICS TRACKER (PLT) MODULE
# =============================================

@log1_bp.route('/projects')
@login_required
def list_projects():
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    # Get filter parameters
    status_filter = request.args.get('status', '')
    priority_filter = request.args.get('priority', '')
    category_filter = request.args.get('category', '')
    search_query = request.args.get('q', '')
    
    try:
        query = client.table('logistics_projects').select('*').order('created_at', desc=True)
        
        if status_filter:
            query = query.eq('status', status_filter)
        if priority_filter:
            query = query.eq('priority', priority_filter)
        if category_filter:
            query = query.eq('category', category_filter)
        
        response = query.execute()
        projects = response.data if response.data else []
        
        # Client-side search filter (Supabase free tier may not support ilike well)
        if search_query:
            search_lower = search_query.lower()
            projects = [p for p in projects if 
                        search_lower in (p.get('project_name', '') or '').lower() or
                        search_lower in (p.get('project_code', '') or '').lower() or
                        search_lower in (p.get('description', '') or '').lower()]
    except Exception as e:
        print(f"Error fetching projects: {e}")
        projects = []
    
    return render_template('subsystems/logistics/log1/projects.html',
                           projects=projects,
                           status_filter=status_filter,
                           priority_filter=priority_filter,
                           category_filter=category_filter,
                           search_query=search_query,
                           subsystem_name=SUBSYSTEM_NAME,
                           accent_color=ACCENT_COLOR,
                           blueprint_name=BLUEPRINT_NAME)

@log1_bp.route('/projects/add', methods=['POST'])
@login_required
def add_project():
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_projects'))
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        project_data = {
            'project_name': request.form.get('project_name'),
            'project_code': request.form.get('project_code') or None,
            'description': request.form.get('description') or None,
            'priority': request.form.get('priority', 'Normal'),
            'status': 'Planning',
            'progress': 0,
            'start_date': request.form.get('start_date') or None,
            'end_date': request.form.get('end_date') or None,
            'category': request.form.get('category', 'Other'),
            'budget': float(request.form.get('budget') or 0),
            'created_by': current_user.id
        }
        
        result = client.table('logistics_projects').insert(project_data).execute()
        
        # Log activity
        if result.data:
            log_project_activity(client, result.data[0]['id'], current_user.id, 
                               "Project Created", f"Created project '{project_data['project_name']}'")
        
        AuditLog.log(current_user.id, "Create Logistics Project", BLUEPRINT_NAME, 
                     {"project": project_data['project_name']})
        
        flash('Logistics project created successfully!', 'success')
    except Exception as e:
        flash(f'Error creating project: {str(e)}', 'danger')
    
    return redirect(url_for('log1.list_projects'))

@log1_bp.route('/projects/<int:project_id>')
@login_required
def view_project(project_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        project_resp = client.table('logistics_projects').select('*').eq('id', project_id).single().execute()
        if not project_resp.data:
            flash('Project not found.', 'danger')
            return redirect(url_for('log1.list_projects'))
        
        # Fetch milestones
        try:
            milestones_resp = client.table('project_milestones').select('*').eq('project_id', project_id).order('due_date').execute()
            milestones = milestones_resp.data if milestones_resp.data else []
        except Exception:
            milestones = []
        
        # Fetch tasks
        try:
            tasks_resp = client.table('project_tasks').select('*').eq('project_id', project_id).order('created_at', desc=True).execute()
            tasks = tasks_resp.data if tasks_resp.data else []
        except Exception:
            tasks = []
        
        # Fetch expenses
        try:
            expenses_resp = client.table('project_expenses').select('*').eq('project_id', project_id).order('date_incurred', desc=True).execute()
            expenses = expenses_resp.data if expenses_resp.data else []
        except Exception:
            expenses = []
        
        # Calculate total spent
        total_spent = sum(float(e.get('amount', 0)) for e in expenses)
        
        # Fetch activity log
        try:
            activities_resp = client.table('project_activities').select('*').eq('project_id', project_id).order('created_at', desc=True).limit(20).execute()
            activities = activities_resp.data if activities_resp.data else []
        except Exception:
            activities = []

        # Fetch project material tracking (real-time flow)
        try:
            tracking_resp = client.table('project_material_tracking').select('*').eq('project_id', project_id).order('updated_at', desc=True).execute()
            material_tracking = tracking_resp.data if tracking_resp.data else []
        except Exception:
            material_tracking = []
        
        return render_template('subsystems/logistics/log1/project_detail.html',
                               project=project_resp.data,
                               milestones=milestones,
                               tasks=tasks,
                               expenses=expenses,
                               total_spent=total_spent,
                               activities=activities,
                               material_tracking=material_tracking,
                               subsystem_name=SUBSYSTEM_NAME,
                               accent_color=ACCENT_COLOR,
                               blueprint_name=BLUEPRINT_NAME)
    except Exception as e:
        flash(f'Error loading project: {str(e)}', 'danger')
        return redirect(url_for('log1.list_projects'))

@log1_bp.route('/projects/edit/<int:project_id>', methods=['POST'])
@login_required
def edit_project(project_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_projects'))
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        project_data = {
            'project_name': request.form.get('project_name'),
            'project_code': request.form.get('project_code') or None,
            'description': request.form.get('description') or None,
            'priority': request.form.get('priority', 'Normal'),
            'status': request.form.get('status', 'Planning'),
            'progress': int(request.form.get('progress', 0)),
            'start_date': request.form.get('start_date') or None,
            'end_date': request.form.get('end_date') or None,
            'category': request.form.get('category', 'Other'),
            'budget': float(request.form.get('budget') or 0),
        }
        
        client.table('logistics_projects').update(project_data).eq('id', project_id).execute()
        
        log_project_activity(client, project_id, current_user.id, 
                           "Project Updated", f"Updated project details for '{project_data['project_name']}'")
        
        AuditLog.log(current_user.id, "Edit Logistics Project", BLUEPRINT_NAME, 
                     {"project_id": project_id, "project": project_data['project_name']})
        
        flash('Project updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating project: {str(e)}', 'danger')
    
    return redirect(url_for('log1.view_project', project_id=project_id))

@log1_bp.route('/projects/delete/<int:project_id>')
@login_required
def delete_project(project_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_projects'))
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        # Delete associated data first
        for table in ['project_milestones', 'project_tasks', 'project_expenses', 'project_activities']:
            try:
                client.table(table).delete().eq('project_id', project_id).execute()
            except Exception:
                pass
        
        client.table('logistics_projects').delete().eq('id', project_id).execute()
        
        AuditLog.log(current_user.id, "Delete Logistics Project", BLUEPRINT_NAME, 
                     {"project_id": project_id})
        
        flash('Project deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error deleting project: {str(e)}', 'danger')
    
    return redirect(url_for('log1.list_projects'))

@log1_bp.route('/projects/status/<int:project_id>/<string:status>')
@login_required
def update_project_status(project_id, status):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_projects'))
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        update_data = {'status': status}
        if status == 'Completed':
            update_data['progress'] = 100
        
        client.table('logistics_projects').update(update_data).eq('id', project_id).execute()
        
        log_project_activity(client, project_id, current_user.id, 
                           "Status Changed", f"Project status changed to '{status}'")
        
        AuditLog.log(current_user.id, "Update Project Status", BLUEPRINT_NAME, 
                     {"project_id": project_id, "new_status": status})
        
        flash(f'Project status updated to {status}.', 'success')
    except Exception as e:
        flash(f'Error updating project status: {str(e)}', 'danger')
    
    return redirect(url_for('log1.view_project', project_id=project_id))


@log1_bp.route('/projects/<int:project_id>/materials-request', methods=['POST'])
@login_required
def request_project_materials(project_id):
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    item_id = _safe_int(request.form.get('item_id'))
    storage_location_id = _safe_int(request.form.get('storage_location_id'))
    quantity = _safe_float(request.form.get('quantity'))
    recipient_name = (request.form.get('recipient_name') or current_user.username).strip()
    recipient_lang = (request.form.get('recipient_lang') or '').strip()

    if not item_id or not storage_location_id or quantity <= 0:
        flash('Item, storage location, and quantity are required.', 'danger')
        return redirect(url_for('log1.view_project', project_id=project_id))

    try:
        req_no = f"MR-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        req_resp = client.table('material_requests').insert({
            'request_no': req_no,
            'project_id': project_id,
            'requested_by': current_user.id,
            'requesting_department_id': 0,
            'item_id': item_id,
            'storage_location_id': storage_location_id,
            'quantity': quantity,
            'recipient_name': recipient_name,
            'recipient_lang': recipient_lang,
            'status': 'PENDING',
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }).execute()
        material_request_id = req_resp.data[0]['id'] if req_resp.data else None

        client.table('project_material_tracking').insert({
            'project_id': project_id,
            'material_request_id': material_request_id,
            'stage': 'REQUEST_PROJECT_MATERIALS',
            'status': 'IN_PROGRESS',
            'notes': f"Requested item #{item_id} qty {quantity}",
            'updated_by': current_user.id,
            'updated_at': datetime.utcnow().isoformat()
        }).execute()

        # Optional immediate stock check and escalation
        try:
            inv_resp = client.table('inventory').select('*').eq('id', item_id).single().execute()
            inv = inv_resp.data or {}
            current_qty = _safe_float(inv.get('quantity'))
            item_name = inv.get('item_name') or f"Item #{item_id}"

            if current_qty < quantity:
                client.table('material_requests').update({
                    'status': 'REJECTED_OUT_OF_STOCK',
                    'rejection_reason': 'Out of Stock',
                    'updated_at': datetime.utcnow().isoformat()
                }).eq('id', material_request_id).execute()

                requisition_id = _create_purchase_requisition_for_out_of_stock(
                    client,
                    item_name=item_name,
                    quantity=quantity,
                    notes=f"Project #{project_id} request auto-escalated.",
                    project_id=project_id
                )

                client.table('project_material_tracking').insert({
                    'project_id': project_id,
                    'material_request_id': material_request_id,
                    'stage': 'REQUEST_PROJECT_MATERIALS',
                    'status': 'BLOCKED',
                    'notes': f"Out of stock. Escalated to procurement requisition {requisition_id or 'N/A'}.",
                    'updated_by': current_user.id,
                    'updated_at': datetime.utcnow().isoformat()
                }).execute()

                _notify(
                    subsystem=BLUEPRINT_NAME,
                    user_id=current_user.id,
                    title='Project Material Request Blocked',
                    message=f"Insufficient stock for {item_name}. Escalated to procurement.",
                    n_type='warning',
                    target_url=url_for('log1.view_project', project_id=project_id)
                )

                flash('Project material request is out of stock and has been escalated to procurement.', 'warning')
                return redirect(url_for('log1.view_project', project_id=project_id))
        except Exception:
            pass

        flash('Project material request submitted.', 'success')
    except Exception as e:
        flash(f'Error requesting project materials: {e}', 'danger')

    return redirect(url_for('log1.view_project', project_id=project_id))


@log1_bp.route('/projects/<int:project_id>/materials-status', methods=['POST'])
@login_required
def update_project_material_status(project_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.view_project', project_id=project_id))

    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()

    stage = request.form.get('stage') or 'DELIVERING_MATERIALS'
    status = request.form.get('status') or 'IN_PROGRESS'
    notes = request.form.get('notes') or ''
    material_request_id = _safe_int(request.form.get('material_request_id'), None)

    try:
        client.table('project_material_tracking').insert({
            'project_id': project_id,
            'material_request_id': material_request_id,
            'stage': stage,
            'status': status,
            'notes': notes,
            'updated_by': current_user.id,
            'updated_at': datetime.utcnow().isoformat()
        }).execute()

        if stage == 'DELIVERING_MATERIALS' and status == 'COMPLETED':
            if material_request_id:
                try:
                    client.table('material_requests').update({
                        'status': 'DELIVERED',
                        'updated_at': datetime.utcnow().isoformat()
                    }).eq('id', material_request_id).execute()
                except Exception:
                    pass

        flash('Project materials tracking updated.', 'success')
    except Exception as e:
        flash(f'Error updating project materials tracking: {e}', 'danger')

    return redirect(url_for('log1.view_project', project_id=project_id))

# --- Milestones ---

@log1_bp.route('/projects/<int:project_id>/milestones/add', methods=['POST'])
@login_required
def add_milestone(project_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.view_project', project_id=project_id))
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        milestone_data = {
            'project_id': project_id,
            'title': request.form.get('title'),
            'description': request.form.get('description') or None,
            'due_date': request.form.get('due_date') or None,
            'status': 'Pending'
        }
        
        client.table('project_milestones').insert(milestone_data).execute()
        
        recalculate_project_progress(client, project_id)
        log_project_activity(client, project_id, current_user.id, 
                           "Milestone Added", f"Added milestone '{milestone_data['title']}'")
        
        flash('Milestone added successfully!', 'success')
    except Exception as e:
        flash(f'Error adding milestone: {str(e)}', 'danger')
    
    return redirect(url_for('log1.view_project', project_id=project_id))

@log1_bp.route('/milestones/<int:milestone_id>/status/<string:status>')
@login_required
def update_milestone_status(milestone_id, status):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_projects'))
    
    project_id = request.args.get('project_id', type=int)
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('project_milestones').update({'status': status}).eq('id', milestone_id).execute()
        
        if project_id:
            recalculate_project_progress(client, project_id)
            log_project_activity(client, project_id, current_user.id, 
                               "Milestone Updated", f"Milestone status changed to '{status}'")
        
        flash(f'Milestone status updated to {status}.', 'success')
    except Exception as e:
        flash(f'Error updating milestone: {str(e)}', 'danger')
    
    if project_id:
        return redirect(url_for('log1.view_project', project_id=project_id))
    return redirect(url_for('log1.list_projects'))

@log1_bp.route('/milestones/<int:milestone_id>/delete')
@login_required
def delete_milestone(milestone_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_projects'))
    
    project_id = request.args.get('project_id', type=int)
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('project_milestones').delete().eq('id', milestone_id).execute()
        
        if project_id:
            recalculate_project_progress(client, project_id)
            log_project_activity(client, project_id, current_user.id, 
                               "Milestone Deleted", "A milestone was removed")
        
        flash('Milestone deleted.', 'success')
    except Exception as e:
        flash(f'Error deleting milestone: {str(e)}', 'danger')
    
    if project_id:
        return redirect(url_for('log1.view_project', project_id=project_id))
    return redirect(url_for('log1.list_projects'))

# --- Tasks ---

@log1_bp.route('/projects/<int:project_id>/tasks/add', methods=['POST'])
@login_required
def add_task(project_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.view_project', project_id=project_id))
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        task_data = {
            'project_id': project_id,
            'title': request.form.get('title'),
            'description': request.form.get('description') or None,
            'assigned_to': request.form.get('assigned_to') or None,
            'priority': request.form.get('priority', 'Normal'),
            'due_date': request.form.get('due_date') or None,
            'status': 'To Do',
            'created_by': current_user.id
        }
        
        client.table('project_tasks').insert(task_data).execute()
        
        recalculate_project_progress(client, project_id)
        log_project_activity(client, project_id, current_user.id, 
                           "Task Added", f"Added task '{task_data['title']}'")
        
        flash('Task added successfully!', 'success')
    except Exception as e:
        flash(f'Error adding task: {str(e)}', 'danger')
    
    return redirect(url_for('log1.view_project', project_id=project_id))

@log1_bp.route('/tasks/<int:task_id>/status/<string:status>')
@login_required
def update_task_status(task_id, status):
    project_id = request.args.get('project_id', type=int)
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('project_tasks').update({'status': status}).eq('id', task_id).execute()
        
        if project_id:
            recalculate_project_progress(client, project_id)
            log_project_activity(client, project_id, current_user.id, 
                               "Task Updated", f"Task status changed to '{status}'")
        
        flash(f'Task status updated to {status}.', 'success')
    except Exception as e:
        flash(f'Error updating task: {str(e)}', 'danger')
    
    if project_id:
        return redirect(url_for('log1.view_project', project_id=project_id))
    return redirect(url_for('log1.list_projects'))

@log1_bp.route('/tasks/<int:task_id>/delete')
@login_required
def delete_task(task_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_projects'))
    
    project_id = request.args.get('project_id', type=int)
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('project_tasks').delete().eq('id', task_id).execute()
        
        if project_id:
            recalculate_project_progress(client, project_id)
            log_project_activity(client, project_id, current_user.id, 
                               "Task Deleted", "A task was removed")
        
        flash('Task deleted.', 'success')
    except Exception as e:
        flash(f'Error deleting task: {str(e)}', 'danger')
    
    if project_id:
        return redirect(url_for('log1.view_project', project_id=project_id))
    return redirect(url_for('log1.list_projects'))

# --- Expenses ---

@log1_bp.route('/projects/<int:project_id>/expenses/add', methods=['POST'])
@login_required
def add_expense(project_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.view_project', project_id=project_id))
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        expense_data = {
            'project_id': project_id,
            'description': request.form.get('description'),
            'amount': float(request.form.get('amount', 0)),
            'category': request.form.get('category', 'Other'),
            'date_incurred': request.form.get('date_incurred') or None,
            'recorded_by': current_user.id
        }
        
        client.table('project_expenses').insert(expense_data).execute()
        
        log_project_activity(client, project_id, current_user.id, 
                           "Expense Recorded", f"${expense_data['amount']:.2f} - {expense_data['description']}")
        
        flash('Expense recorded successfully!', 'success')
    except Exception as e:
        flash(f'Error recording expense: {str(e)}', 'danger')
    
    return redirect(url_for('log1.view_project', project_id=project_id))

@log1_bp.route('/expenses/<int:expense_id>/delete')
@login_required
def delete_expense(expense_id):
    if not current_user.is_admin():
        flash('Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('log1.list_projects'))
    
    project_id = request.args.get('project_id', type=int)
    
    from utils.supabase_client import get_supabase_client
    client = get_supabase_client()
    
    try:
        client.table('project_expenses').delete().eq('id', expense_id).execute()
        
        if project_id:
            log_project_activity(client, project_id, current_user.id, 
                               "Expense Deleted", "An expense record was removed")
        
        flash('Expense deleted.', 'success')
    except Exception as e:
        flash(f'Error deleting expense: {str(e)}', 'danger')
    
    if project_id:
        return redirect(url_for('log1.view_project', project_id=project_id))
    return redirect(url_for('log1.list_projects'))

# --- Activity Logger Helper ---

def log_project_activity(client, project_id, user_id, action, details=None):
    """Log an activity entry for a project."""
    try:
        client.table('project_activities').insert({
            'project_id': project_id,
            'user_id': user_id,
            'action': action,
            'details': details
        }).execute()
    except Exception as e:
        print(f"Error logging project activity: {e}")

def recalculate_project_progress(client, project_id):
    """Auto-calculate project progress based on completed tasks and milestones.
    Tasks contribute 70% weight, milestones contribute 30% weight.
    If only tasks exist, they count 100%. Same for milestones only."""
    try:
        # Fetch tasks
        tasks_resp = client.table('project_tasks').select('status').eq('project_id', project_id).execute()
        tasks = tasks_resp.data if tasks_resp.data else []
        
        # Fetch milestones
        milestones_resp = client.table('project_milestones').select('status').eq('project_id', project_id).execute()
        milestones = milestones_resp.data if milestones_resp.data else []
        
        # If no tasks and no milestones, don't auto-update (keep manual value)
        if not tasks and not milestones:
            return
        
        # Calculate task completion
        task_progress = 0
        if tasks:
            done_tasks = sum(1 for t in tasks if t.get('status') == 'Done')
            task_progress = (done_tasks / len(tasks)) * 100
        
        # Calculate milestone completion
        milestone_progress = 0
        if milestones:
            done_milestones = sum(1 for m in milestones if m.get('status') == 'Completed')
            milestone_progress = (done_milestones / len(milestones)) * 100
        
        # Weighted average (or 100% weight if only one type exists)
        if tasks and milestones:
            progress = int((task_progress * 0.7) + (milestone_progress * 0.3))
        elif tasks:
            progress = int(task_progress)
        else:
            progress = int(milestone_progress)
        
        # Update project progress
        client.table('logistics_projects').update({'progress': progress}).eq('id', project_id).execute()
    except Exception as e:
        print(f"Error recalculating project progress: {e}")

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


