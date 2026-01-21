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
            self.quantity = data.get('quantity')
            self.reorder_level = data.get('reorder_level')
            self.expiry_date = data.get('expiry_date')
            self.batch_number = data.get('batch_number')

    @staticmethod
    def get_low_stock():
        client = get_supabase_client()
        # Using a raw filter since quantity < reorder_level
        response = client.table('inventory').select('*').lt('quantity', 'reorder_level').execute()
        # Note: Supabase might not support column-to-column comparison directly in .lt() easily without RPC or raw SQL
        # For now, we'll fetch all and filter or use a safe default
        response = client.table('inventory').select('*').execute()
        return [InventoryItem(d) for d in response.data if d['quantity'] <= d['reorder_level']] if response.data else []

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
