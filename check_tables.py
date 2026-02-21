from utils.supabase_client import get_supabase_client

def list_tables():
    client = get_supabase_client()
    try:
        # There is no direct "list tables" in postgrest, but we can try to access common ones or use an RPC if available
        # Alternatively, we can check the scaffold.py if it lists them
        pass
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Just list some common HMS tables to see if they exist
    client = get_supabase_client()
    tables = ['patients', 'beds', 'wards', 'admissions', 'appointments', 'billing_records', 'users', 'audit_logs']
    for t in tables:
        try:
            res = client.table(t).select('id').limit(1).execute()
            print(f"Table '{t}' exists.")
        except:
            print(f"Table '{t}' does NOT exist or no 'id' column.")
