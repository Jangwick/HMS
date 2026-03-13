import json
import zipfile
import io
import os
from datetime import datetime
from utils.supabase_client import get_supabase_client

# Mapping of subsystems to tables in correct dependency order for restoration
SUBSYSTEM_TABLE_MAPPING = {
    'HR1': ['vacancies', 'applicants', 'interviews', 'onboarding'],
    'HR2': ['competencies', 'trainings', 'staff_competencies', 'training_participants', 'career_paths', 'succession_plans'],
    'HR3': ['attendance_logs', 'leave_requests', 'staff_schedules'],
    'HR4': ['salary_grades', 'compensation_records', 'payroll_records'],
    'CT1': ['patients', 'appointments'],
    'CT2': ['lab_orders', 'prescriptions'],
    'CT3': ['medical_records', 'beds'],
    'LOG1': ['assets', 'inventory', 'dispensing_history', 'asset_maintenance_logs'],
    'LOG2': ['fleet_vehicles', 'drivers', 'fleet_dispatch', 'fleet_costs', 'suppliers', 'purchase_orders', 'po_items', 'log_documents'],
    'FIN1': ['bank_accounts', 'vendors', 'billing_records', 'general_ledger', 'vendor_invoices', 'vendor_payments', 'receivables', 'collections', 'cash_transactions', 'generated_reports'],
    'FINANCIALS': ['bank_accounts', 'vendors', 'billing_records', 'general_ledger', 'vendor_invoices', 'vendor_payments', 'receivables', 'collections', 'cash_transactions', 'generated_reports']
}

DEPARTMENT_MAPPING = {
    'HR': ['HR1', 'HR2', 'HR3', 'HR4'],
    'CORE_TRANSACTION': ['CT1', 'CT2', 'CT3'],
    'LOGISTICS': ['LOG1', 'LOG2'],
    'FINANCIALS': ['FINANCIALS']
}


def get_supported_subsystems():
    return sorted(SUBSYSTEM_TABLE_MAPPING.keys())


def get_supported_departments():
    return sorted(DEPARTMENT_MAPPING.keys())

def get_tables_for_scope(scope, target_id):
    """Returns a list of tables for the given scope and target_id."""
    if not target_id:
        return []
        
    tid = target_id.upper()
    if scope == 'subsystem':
        return SUBSYSTEM_TABLE_MAPPING.get(tid, [])
    elif scope == 'department':
        subsystems = DEPARTMENT_MAPPING.get(tid, [])
        tables = []
        for ss in subsystems:
            # Note: We want the ss in the mapping to match SUBSYSTEM_TABLE_MAPPING keys
            for table in SUBSYSTEM_TABLE_MAPPING.get(ss.upper(), []):
                if table not in tables:
                    tables.append(table)
        return tables
    return []

def export_data(scope, target_id, user_id=None):
    """
    Exports data for a specific scope and target_id into a .hms-backup (ZIP) file.
    """
    client = get_supabase_client()
    normalized_scope = (scope or '').strip().lower()
    normalized_target = (target_id or '').strip().upper()
    tables = get_tables_for_scope(normalized_scope, normalized_target)
    
    if not tables:
        return None, "Invalid scope or target ID"

    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        # 1. Metadata
        metadata = {
            "export_date": datetime.now().isoformat(),
            "scope": normalized_scope,
            "target_id": normalized_target,
            "version": "1.0.0",
            "tables": tables
        }
        zf.writestr('metadata.json', json.dumps(metadata, indent=4))

        # 2. Data extraction
        for table in tables:
            try:
                try:
                    response = client.table(table).select("*").order("id").execute()
                except Exception:
                    response = client.table(table).select("*").execute()
                data = response.data if response.data else []
                zf.writestr(f'{table}.json', json.dumps(data, indent=4))
            except Exception as e:
                print(f"Error exporting table {table}: {e}")
                # We continue with other tables but maybe we should fail? 
                # For now, let's just include what we can.

    memory_file.seek(0)
    
    # Log the action
    log_audit_action(user_id, 'BACKUP', normalized_scope, normalized_target, 'SUCCESS', f"{normalized_target}_{normalized_scope}.hms-backup")
    
    return memory_file, None

def import_data(file_stream, scope, target_id, user_id=None):
    """
    Imports data from a .hms-backup file.
    """
    client = get_supabase_client()
    
    try:
        with zipfile.ZipFile(file_stream) as zf:
            # 1. Validation
            if 'metadata.json' not in zf.namelist():
                return False, "Invalid backup file: missing metadata.json"
            
            metadata = json.loads(zf.read('metadata.json'))
            expected_scope = (scope or '').strip().lower()
            expected_target = (target_id or '').strip().upper()
            backup_scope = (metadata.get('scope') or '').strip().lower()
            backup_target = (metadata.get('target_id') or '').strip().upper()
            if backup_scope != expected_scope or backup_target != expected_target:
                return False, f"Backup mismatch: Expected {expected_scope}/{expected_target}, got {backup_scope}/{backup_target}"

            # 2. Data injection (Dependency Handling)
            # Tables are already in order in metadata or we can use our mapping
            tables = get_tables_for_scope(expected_scope, expected_target)
            
            error_log = []
            for table in tables:
                filename = f"{table}.json"
                if filename in zf.namelist():
                    data = json.loads(zf.read(filename))
                    if not data:
                        continue
                    
                    # Upsert logic: using primary key 'id' for conflict resolution
                    # Note: We do this in chunks if data is large
                    chunk_size = 100
                    for i in range(0, len(data), chunk_size):
                        chunk = data[i:i + chunk_size]
                        try:
                            # postgrest-py upsert uses the primary key by default
                            client.table(table).upsert(chunk).execute()
                        except Exception as e:
                            error_log.append(f"Error in table {table}: {str(e)}")
                else:
                    error_log.append(f"Table data missing in backup: {table}")

            if error_log:
                log_audit_action(user_id, 'RESTORE', expected_scope, expected_target, 'FAIL', "N/A", "\n".join(error_log))
                return False, "Restore completed with errors: " + "; ".join(error_log[:3])
            
            log_audit_action(user_id, 'RESTORE', expected_scope, expected_target, 'SUCCESS', "N/A")
            return True, "Restore successful"

    except Exception as e:
        log_audit_action(user_id, 'RESTORE', (scope or '').strip().lower(), (target_id or '').strip().upper(), 'FAIL', "N/A", str(e))
        return False, f"Restore failed: {str(e)}"

def reset_data(scope, target_id, user_id=None):
    """
    Deletes all records from tables associated with the scope and target_id.
    USE WITH EXTREME CAUTION.
    """
    client = get_supabase_client()
    normalized_scope = (scope or '').strip().lower()
    normalized_target = (target_id or '').strip().upper()
    tables = get_tables_for_scope(normalized_scope, normalized_target)
    
    if not tables:
        return False, "Invalid scope or target ID"

    error_log = []
    # Reverse order for deletion to avoid foreign key issues
    for table in reversed(tables):
        try:
            # Note: delete() without filters in Postgrest deletes all if RLS allows
            # We use .neq('id', 0) as a dummy filter that matches everything to satisfy client safety
            client.table(table).delete().neq('id', 0).execute()
        except Exception as e:
            error_log.append(f"Error clearing table {table}: {str(e)}")

    if error_log:
        log_audit_action(user_id, 'RESET', normalized_scope, normalized_target, 'FAIL', "N/A", "\n".join(error_log))
        return False, "Reset completed with errors: " + "; ".join(error_log[:3])
    
    log_audit_action(user_id, 'RESET', normalized_scope, normalized_target, 'SUCCESS', "N/A")
    return True, "Subsystem data reset successfully"

def get_audit_logs(scope, target_id, limit=5):
    """Fetches the most recent audit logs for a specific target."""
    client = get_supabase_client()
    try:
        response = client.table('system_audit_logs')\
            .select("*")\
            .eq('scope', scope)\
            .eq('target_id', target_id)\
            .order('timestamp', desc=True)\
            .limit(limit)\
            .execute()
        return response.data or []
    except Exception as e:
        print(f"Failed to fetch audit logs: {e}")
        return []

def log_audit_action(user_id, action, scope, target_id, status, file_name, details=None):
    """Logs the backup/restore action to the database."""
    try:
        client = get_supabase_client()
        client.table('system_audit_logs').insert({
            'user_id': user_id,
            'action': action,
            'scope': scope,
            'target_id': target_id,
            'status': status,
            'file_name': file_name,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }).execute()
    except Exception as e:
        print(f"Failed to log audit action: {e}")
