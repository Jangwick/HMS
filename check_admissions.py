from utils.supabase_client import get_supabase_client

def check_admissions_raw():
    client = get_supabase_client()
    try:
        res = client.table('admissions').select('*').limit(1).execute()
        print(f"Admissions data: {res.data}")
    except Exception as e:
        print(f"Error checking admissions: {e}")

if __name__ == "__main__":
    check_admissions_raw()
