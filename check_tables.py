import os
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

tables = [
    "users", "applicants", "vacancies", "competencies", "staff_competencies", 
    "trainings", "attendance_logs", "leave_requests", "patients", "appointments", 
    "lab_orders", "prescriptions", "beds", "inventory", "assets", 
    "fleet_vehicles", "billing_records", "general_ledger"
]

print("Checking tables...")
for table in tables:
    try:
        supabase.table(table).select("id").limit(1).execute()
        print(f"EXISTS: {table}")
    except Exception as e:
        err_msg = str(e)
        if "PGRST204" in err_msg or "PGRST205" in err_msg or "not found" in err_msg.lower():
            print(f"MISSING: {table}")
        else:
            print(f"ERROR: {table} - {err_msg[:100]}")
