from app import create_app
from utils.supabase_client import get_supabase_client, User
app = create_app()
with app.app_context():
    client = get_supabase_client()
    print("=== ALL ADMIN/STAFF ACCOUNTS ===")
    resp = client.table('users').select('id, username, subsystem, role, status, department').in_('role', ['Admin', 'Administrator', 'SuperAdmin', 'HR_Staff', 'Manager']).execute()
    for u in (resp.data or []):
        print(f"  id={u['id']}  user={u['username']!r:25}  subsystem={str(u['subsystem'])!r:8}  role={u['role']!r:15}  status={u['status']!r}")

    print("\n=== ALL HR1-SUBSYSTEM USERS ===")
    resp2 = client.table('users').select('id, username, subsystem, role, status, department').eq('subsystem', 'hr1').execute()
    if not resp2.data:
        print("  [NONE FOUND] No users have subsystem='hr1'")
    for u in (resp2.data or []):
        print(f"  id={u['id']}  user={u['username']!r:25}  role={u['role']!r:15}  status={u['status']!r}")
