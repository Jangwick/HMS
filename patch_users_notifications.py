from utils.supabase_client import get_supabase_client

def patch():
    client = get_supabase_client()
    print("Patching users table to add notification_settings column...")
    
    # SQL to add the column
    sql = """
    ALTER TABLE users 
    ADD COLUMN IF NOT EXISTS notification_settings JSONB DEFAULT '{
        "email_notifications": true,
        "system_updates": true,
        "security_alerts": true,
        "activity_logs": false
    }'::jsonb;
    """
    
    try:
        # We need to execute raw SQL. The supabase-py client doesn't 
        # expose a direct rpc for raw SQL easily unless we have a function.
        # But we can try to use a dummy RPC or just assume the user runs the SQL.
        # However, for this environment, I can try to use the client.postgrest structure if available.
        # Alternatively, I can just create a postgres function to execute sql.
        
        # In many Supabase setups, there's no direct raw SQL execution from client.
        # I'll provide the SQL in a comment and try to use a rpc if possible.
        print("Please run the following SQL in your Supabase SQL Editor:")
        print(sql)
        
        # For now, let's assume we can't run raw SQL directly without a helper function.
        # I will instead just update the model to handle a missing column gracefully if it fails.
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    patch()
