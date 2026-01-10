from app import create_app
from utils.supabase_client import User, SUBSYSTEM_CONFIG, is_supabase_configured

app = create_app()

def init_db():
    """
    Initialize the database with default admin users for all subsystems.
    Uses Supabase Python client.
    """
    with app.app_context():
        if not is_supabase_configured():
            print("ERROR: Supabase credentials not configured.")
            print("Please set SUPABASE_URL and SUPABASE_KEY in your .env file.")
            return
        
        print("Initializing Supabase Database...")
        print("Make sure you've run supabase_setup.sql first to create the users table.\n")
        
        for subsystem, config in SUBSYSTEM_CONFIG.items():
            username = f'admin_{subsystem}'
            email = f'admin@{subsystem}.hms.com'
            department = config['department']
            
            # Check if user already exists
            existing = User.get_by_username(username, subsystem)
            if not existing:
                try:
                    user = User.create(
                        username=username,
                        email=email,
                        password='Admin@12345',
                        subsystem=subsystem,
                        department=department,
                        role='Administrator',
                        status='Active',
                        skip_validation=True
                    )
                    if user:
                        print(f"Created {subsystem} admin: {username}")
                    else:
                        print(f"Failed to create {subsystem} admin: {username}")
                except Exception as e:
                    print(f"Error creating {subsystem} admin: {e}")
            else:
                print(f"User {username} already exists.")
        
        print("\nDatabase initialization complete.")

if __name__ == '__main__':
    init_db()
