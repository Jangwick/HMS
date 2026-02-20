from utils.supabase_client import User, get_supabase_client
from utils.password_validator import PasswordValidationError

def create_superadmin():
    username = "superadmin"
    email = "superadmin@hms.com"
    password = "Admin@12345"
    subsystem = "superadmin" # Virtual subsystem
    department = "System Administration"
    
    print(f"Creating SuperAdmin account: {username}")
    
    try:
        # Check if exists
        existing = User.get_by_username(username)
        if existing:
            print(f"User {username} already exists. Updating role to SuperAdmin...")
            existing.update(role='SuperAdmin', status='Active')
            print("Update complete.")
            return

        user = User.create(
            username=username,
            email=email,
            password=password,
            subsystem=subsystem,
            department=department,
            role='SuperAdmin',
            status='Active',
            skip_validation=True
        )
        if user:
            print(f"Successfully created SuperAdmin account!")
            print(f"Username: {username}")
            print(f"Password: {password}")
        else:
            print("Failed to create user.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    create_superadmin()
