"""Reset admin_hr1 password and clear any lockout."""
import os
from dotenv import load_dotenv
load_dotenv()

from app import create_app

app = create_app()

with app.app_context():
    from utils.supabase_client import User, get_supabase_client

    user = User.get_by_username('admin_hr1', 'hr1')
    if not user:
        print("ERROR: admin_hr1 not found!")
    else:
        print(f"Found: id={user.id}  status={user.status}  subsystem={user.subsystem}")
        print(f"  password_expires_at = {user.password_expires_at}")
        print(f"  failed_attempts     = {getattr(user, 'failed_login_attempts', getattr(user, 'failed_attempts', 'N/A'))}")
        print(f"  locked_until        = {getattr(user, 'locked_until', getattr(user, 'account_locked_until', 'N/A'))}")

        # Reset password (skip policy validation)
        ok = user.set_password('Admin@12345', skip_validation=True)
        print(f"Password reset result: {ok}")

        # Also clear any per-account lockout fields
        client = get_supabase_client()
        client.table('users').update({
            'failed_login_attempts': 0,
            'account_locked_until': None,
        }).eq('id', user.id).execute()
        print("Cleared per-account lockout fields.")

    # Clear IP-based lockout for hr1 (in-memory dict)
    try:
        from utils.ip_lockout import _ip_lockouts
        keys_to_del = [k for k in _ip_lockouts if 'hr1' in str(k)]
        for k in keys_to_del:
            del _ip_lockouts[k]
        print(f"Cleared {len(keys_to_del)} IP lockout key(s) for hr1.")
    except Exception as e:
        print(f"Note (IP lockout): {e} — restart the Flask server to clear IP lockout.")

    print("\nDone. Try logging in with:  admin_hr1 / Admin@12345")
