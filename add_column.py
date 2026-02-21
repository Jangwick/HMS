from utils.supabase_client import get_supabase_client

def attempt_add_column():
    client = get_supabase_client()
    try:
        # Many Supabase templates have a 'run_sql' or 'exec_sql' RPC for migrations
        sql = "ALTER TABLE beds ADD COLUMN IF NOT EXISTS patient_id INTEGER REFERENCES patients(id);"
        res = client.rpc('exec_sql', {'sql_query': sql}).execute()
        print("Successfully added patient_id to beds via exec_sql.")
    except Exception as e1:
        try:
             sql = "ALTER TABLE beds ADD COLUMN IF NOT EXISTS patient_id INTEGER REFERENCES patients(id);"
             res = client.rpc('run_sql', {'sql': sql}).execute()
             print("Successfully added patient_id to beds via run_sql.")
        except Exception as e2:
             print(f"Failed to add column via RPC. Errors: \n1: {e1}\n2: {e2}")

if __name__ == "__main__":
    attempt_add_column()
