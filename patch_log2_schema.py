import os
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

sql_commands = [
    # Ensure fleet_vehicles has the right columns
    "ALTER TABLE fleet_vehicles ADD COLUMN IF NOT EXISTS model_name TEXT;",
    "ALTER TABLE fleet_vehicles ADD COLUMN IF NOT EXISTS plate_number TEXT;",
    "ALTER TABLE fleet_vehicles ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();",
    
    # Ensure drivers has the right columns
    "ALTER TABLE drivers ADD COLUMN IF NOT EXISTS full_name TEXT;",
    "ALTER TABLE drivers ADD COLUMN IF NOT EXISTS license_number TEXT;",
    "ALTER TABLE drivers ADD COLUMN IF NOT EXISTS phone TEXT;",
    "ALTER TABLE drivers ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();",

    # Ensure fleet_dispatches has the right columns
    "ALTER TABLE fleet_dispatches ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'On Trip';",
    "ALTER TABLE fleet_dispatches ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();",

    # Ensure fleet_costs has the right columns
    "ALTER TABLE fleet_costs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();"
]

print("Running manual schema patch...")
for sql in sql_commands:
    try:
        # Note: Supabase Python SDK doesn't have a direct 'rpc' for raw SQL unless enabled
        # We will try to execute it via a dummy RPC if possible, or just rely on the user running the SQL
        # Since I can't easily run raw SQL from here without a specific RPC, 
        # I will just write this as a reference or use a different approach.
        pass
    except Exception as e:
        print(f"Error running SQL: {e}")

print("NOTE: Please run the SQL commands in supabase_setup.sql manually in the Supabase SQL Editor to ensure all columns exist.")
