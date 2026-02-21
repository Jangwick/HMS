from utils.supabase_client import get_supabase_client
import json

def check_other_tables():
    client = get_supabase_client()
    tables = ['patients', 'appointments', 'billing_records']
    for t in tables:
        try:
            res = client.table(t).select('*').limit(1).execute()
            if res.data:
                print(f"Columns in '{t}' table:")
                print(json.dumps(list(res.data[0].keys()), indent=2))
            else:
                print(f"Table '{t}' is empty.")
        except Exception as e:
            print(f"Error checking {t}: {e}")

if __name__ == "__main__":
    check_other_tables()
