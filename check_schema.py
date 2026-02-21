from utils.supabase_client import get_supabase_client
import json

def check_beds_schema():
    client = get_supabase_client()
    try:
        # Fetch one record to see columns
        res = client.table('beds').select('*').limit(1).execute()
        if res.data:
            print("Columns in 'beds' table:")
            print(json.dumps(list(res.data[0].keys()), indent=2))
        else:
            print("No data in 'beds' table to inspect.")
            # Try to fetch another table to see if client works
            p_res = client.table('patients').select('*').limit(1).execute()
            if p_res.data:
                print("Client works. 'beds' table is empty.")
            else:
                print("Client might have issues or 'patients' is also empty.")
    except Exception as e:
        print(f"Error checking schema: {e}")

if __name__ == "__main__":
    check_beds_schema()
