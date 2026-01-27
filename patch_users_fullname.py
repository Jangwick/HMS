from utils.supabase_client import get_supabase_client
import sys

def patch_users_table():
    """
    Check if full_name column exists in users table, and add it if it doesn't.
    """
    print("Checking users table schema...")
    client = get_supabase_client()
    
    try:
        # Check if we can select full_name
        response = client.table('users').select('full_name').limit(1).execute()
        print("Column 'full_name' already exists in 'users' table.")
    except Exception as e:
        error_msg = str(e)
        if "Could not find the 'full_name' column" in error_msg or 'PGRST204' in error_msg:
            print("Column 'full_name' missing. Attempting to add it via SQL...")
            
            # Since the Supabase Python client doesn't support ALTER TABLE directly,
            # we provide the SQL instructions for the user.
            print("\n" + "="*50)
            print("SQL ACTION REQUIRED:")
            print("Please run the following SQL command in your Supabase SQL Editor:")
            print("\nALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(100);")
            print("="*50 + "\n")
            
            # We can also attempt to use RPC if they have a generic sql executor (unlikely)
            # but usually, users have to run this in the dashboard.
        else:
            print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    patch_users_table()
