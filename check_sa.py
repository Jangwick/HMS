from utils.supabase_client import User, get_supabase_client

def check_superadmins():
    print("Checking for SuperAdmin accounts...")
    users = User.get_all()
    superadmins = [u for u in users if u.is_super_admin()]
    
    if superadmins:
        for sa in superadmins:
            print(f"Username: {sa.username}, Role: {sa.role}, Subsystem: {sa.subsystem}")
    else:
        print("No SuperAdmin found.")

if __name__ == "__main__":
    check_superadmins()
