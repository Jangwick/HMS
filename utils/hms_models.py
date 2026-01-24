from datetime import datetime
from utils.supabase_client import get_supabase_client

class Patient:
    def __init__(self, data: dict = None):
        if data:
            self.id = data.get('id')
            self.patient_id_alt = data.get('patient_id_alt')
            self.first_name = data.get('first_name')
            self.last_name = data.get('last_name')
            self.dob = data.get('dob')
            self.gender = data.get('gender')
            self.contact_number = data.get('contact_number')
            self.address = data.get('address')
            self.insurance_info = data.get('insurance_info') or {}
            self.created_at = data.get('created_at')

    @staticmethod
    def create(data: dict):
        client = get_supabase_client()
        # Generate a patient ID if not provided
        if not data.get('patient_id_alt'):
            now = datetime.now()
            data['patient_id_alt'] = f"PAT-{now.strftime('%Y%m%d')}-{now.strftime('%H%M%S')}"
        
        response = client.table('patients').insert(data).execute()
        if response.data:
            return Patient(response.data[0])
        return None

    @staticmethod
    def get_all():
        client = get_supabase_client()
        response = client.table('patients').select('*').execute()
        return [Patient(d) for d in response.data] if response.data else []

    @staticmethod
    def search(query: str):
        client = get_supabase_client()
        response = client.table('patients').select('*').or_(
            f"first_name.ilike.%{query}%,last_name.ilike.%{query}%,patient_id_alt.ilike.%{query}%"
        ).execute()
        return [Patient(d) for d in response.data] if response.data else []

class Appointment:
    def __init__(self, data: dict = None):
        if data:
            self.id = data.get('id')
            self.patient_id = data.get('patient_id')
            self.doctor_id = data.get('doctor_id')
            self.appointment_date = data.get('appointment_date')
            self.status = data.get('status')
            self.type = data.get('type')
            self.created_at = data.get('created_at')
            self.notes = data.get('notes')
            # Joined data
            self.patient = Patient(data.get('patients')) if data.get('patients') else None
            self.doctor = data.get('users') if data.get('users') else None

    @staticmethod
    def create(data: dict):
        client = get_supabase_client()
        response = client.table('appointments').insert(data).execute()
        if response.data:
            return Appointment(response.data[0])
        return None

    @staticmethod
    def get_upcoming():
        client = get_supabase_client()
        # Joins patients and the doctor (users table)
        response = client.table('appointments').select('*, patients(*), users(*)').gte('appointment_date', datetime.now().isoformat()).order('appointment_date').limit(10).execute()
        return [Appointment(d) for d in response.data] if response.data else []

class InventoryItem:
    def __init__(self, data: dict = None):
        if data:
            self.id = data.get('id')
            self.item_name = data.get('item_name')
            self.category = data.get('category')
            self.batch_number = data.get('batch_number')
            self.quantity = data.get('quantity')
            self.unit = data.get('unit')
            self.expiry_date = data.get('expiry_date')
            self.location = data.get('location')
            self.last_updated = data.get('last_updated')

    @staticmethod
    def get_all(category=None):
        client = get_supabase_client()
        query = client.table('inventory').select('*')
        if category:
            query = query.eq('category', category)
        response = query.order('item_name').execute()
        return [InventoryItem(d) for d in response.data] if response.data else []

    @staticmethod
    def create(data: dict):
        client = get_supabase_client()
        response = client.table('inventory').insert(data).execute()
        return response.data

    @staticmethod
    def update(item_id, data: dict):
        client = get_supabase_client()
        response = client.table('inventory').update(data).eq('id', item_id).execute()
        return response.data

    @staticmethod
    def delete(item_id):
        client = get_supabase_client()
        response = client.table('inventory').delete().eq('id', item_id).execute()
        return response.data

    @staticmethod
    def get_low_stock(threshold=10):
        client = get_supabase_client()
        response = client.table('inventory').select('*').lt('quantity', threshold).execute()
        return [InventoryItem(d) for d in response.data] if response.data else []

class DispenseRecord:
    def __init__(self, data: dict = None):
        if data:
            self.id = data.get('id')
            self.inventory_item_id = data.get('inventory_item_id')
            self.patient_id = data.get('patient_id')
            self.quantity = data.get('quantity')
            self.dispensed_by = data.get('dispensed_by')
            self.dispensed_at = data.get('dispensed_at')
            self.notes = data.get('notes')
            # Joined data
            self.item = InventoryItem(data.get('inventory')) if data.get('inventory') else None
            self.patient = Patient(data.get('patients')) if data.get('patients') else None
            self.staff = data.get('users') if data.get('users') else None

    @staticmethod
    def get_history(limit=50):
        client = get_supabase_client()
        response = client.table('dispensing_history').select('*, inventory(*), patients(*), users(*)').order('dispensed_at', desc=True).limit(limit).execute()
        return [DispenseRecord(d) for d in response.data] if response.data else []

class Applicant:
    def __init__(self, data: dict = None):
        if data:
            self.id = data.get('id')
            self.first_name = data.get('first_name')
            self.last_name = data.get('last_name')
            self.email = data.get('email')
            self.phone = data.get('phone')
            self.source = data.get('source')
            self.status = data.get('status')
            self.documents = data.get('documents') or []
            self.created_at = data.get('created_at')

    @staticmethod
    def get_all():
        client = get_supabase_client()
        response = client.table('applicants').select('*').order('created_at', desc=True).execute()
        return [Applicant(d) for d in response.data] if response.data else []

    @staticmethod
    def update_status(applicant_id, status):
        client = get_supabase_client()
        response = client.table('applicants').update({'status': status}).eq('id', applicant_id).execute()
        return response.data

class Interview:
    def __init__(self, data: dict = None):
        if data:
            self.id = data.get('id')
            self.applicant_id = data.get('applicant_id')
            self.interviewer_id = data.get('interviewer_id')
            self.interview_date = data.get('interview_date')
            self.location = data.get('location')
            self.notes = data.get('notes')
            self.status = data.get('status')
            self.created_at = data.get('created_at')
            # Joined data
            self.applicant = Applicant(data.get('applicants')) if data.get('applicants') else None

    @staticmethod
    def create(data: dict):
        client = get_supabase_client()
        response = client.table('interviews').insert(data).execute()
        if response.data:
            # Update applicant status to 'Interview'
            client.table('applicants').update({'status': 'Interview'}).eq('id', data['applicant_id']).execute()
            return Interview(response.data[0])
        return None

    @staticmethod
    def get_upcoming():
        client = get_supabase_client()
        response = client.table('interviews').select('*, applicants(*)').gte('interview_date', datetime.now().isoformat()).order('interview_date').execute()
        return [Interview(d) for d in response.data] if response.data else []

class LabOrder:
    def __init__(self, data: dict = None):
        if data:
            self.id = data.get('id')
            self.patient_id = data.get('patient_id')
            self.doctor_id = data.get('doctor_id')
            self.test_name = data.get('test_name')
            self.status = data.get('status')
            self.results = data.get('results') or {}
            self.critical_alert = data.get('critical_alert', False)
            self.created_at = data.get('created_at')
            # Joined data
            self.patient = Patient(data.get('patients')) if data.get('patients') else None
            self.doctor = data.get('users') if data.get('users') else None

    @staticmethod
    def create(data: dict):
        client = get_supabase_client()
        response = client.table('lab_orders').insert(data).execute()
        if response.data:
            return LabOrder(response.data[0])
        return None

    @staticmethod
    def get_all():
        client = get_supabase_client()
        response = client.table('lab_orders').select('*, patients(*), users(*)').order('created_at', desc=True).execute()
        return [LabOrder(d) for d in response.data] if response.data else []

    @staticmethod
    def get_recent(limit=5):
        client = get_supabase_client()
        response = client.table('lab_orders').select('*, patients(*), users(*)').order('created_at', desc=True).limit(limit).execute()
        return [LabOrder(d) for d in response.data] if response.data else []

    @staticmethod
    def update(order_id, data: dict):
        client = get_supabase_client()
        response = client.table('lab_orders').update(data).eq('id', order_id).execute()
        return response.data

class Billing:
    @staticmethod
    def post_charge(patient_id, amount, description, source_subsystem):
        from datetime import datetime, timedelta
        client = get_supabase_client()
        
        # Look for an existing unpaid bill for this patient
        try:
            # Get the most recent unpaid bill for this patient
            res = client.table('billing_records').select('*').eq('patient_id', patient_id).eq('status', 'Unpaid').order('created_at', desc=True).limit(1).execute()
            
            if res.data:
                bill = res.data[0]
                new_total = float(bill.get('total_amount', 0)) + float(amount)
                new_desc = bill.get('description', '')
                if new_desc:
                    new_desc += f" | {description} ({source_subsystem})"
                else:
                    new_desc = f"{description} ({source_subsystem})"
                    
                client.table('billing_records').update({
                    'total_amount': new_total,
                    'description': new_desc
                }).eq('id', bill['id']).execute()
                
                # Update receivables if it exists
                client.table('receivables').update({
                    'amount_due': new_total
                }).eq('billing_id', bill['id']).execute()
                
                return bill['id']
            else:
                # Create a new bill
                bill_data = {
                    'patient_id': patient_id,
                    'total_amount': amount,
                    'status': 'Unpaid',
                    'description': f"{description} ({source_subsystem})",
                    'billing_date': datetime.now().isoformat()
                }
                new_bill = client.table('billing_records').insert(bill_data).execute()
                if new_bill.data:
                    bill_id = new_bill.data[0]['id']
                    # Create receivable
                    rec_data = {
                        'billing_id': bill_id,
                        'amount_due': amount,
                        'due_date': (datetime.now() + timedelta(days=30)).date().isoformat(),
                        'status': 'Unpaid'
                    }
                    client.table('receivables').insert(rec_data).execute()
                    return bill_id
        except Exception as e:
            print(f"Error in post_charge: {e}")
            return None

class AuditLog:
    @staticmethod
    def log(user_id, action, subsystem, details=None):
        client = get_supabase_client()
        data = {
            'user_id': user_id,
            'action': action,
            'subsystem': subsystem,
            'details': details or {},
            'created_at': datetime.now().isoformat()
        }
        try:
            client.table('audit_logs').insert(data).execute()
        except Exception as e:
            print(f"Failed to write audit log: {e}")
            # Silently fail to not block the main transaction
