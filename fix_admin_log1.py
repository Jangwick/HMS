#!/usr/bin/env python3
"""
Fix admin_log1 credentials for LOG1 subsystem
Run: python fix_admin_log1.py
"""

from utils.supabase_client import get_supabase_client, User
from werkzeug.security import generate_password_hash
import sys

def fix_admin_log1():
    client = get_supabase_client()
    
    print("=" * 60)
    print("LOG1 Admin Account Fixer")
    print("=" * 60)
    
    # Check if user exists
    username = 'admin_log1'
    try:
        response = client.table('users').select('*').eq('username', username).eq('subsystem', 'log1').execute()
        users = response.data or []
        
        if users:
            user = users[0]
            print(f"\n✓ Found user: {username}")
            print(f"  - Current Status: {user.get('status')}")
            print(f"  - Role: {user.get('role')}")
            print(f"  - Subsystem: {user.get('subsystem')}")
            
            # Option to reset password
            print("\n" + "=" * 60)
            action = input("\nWhat would you like to do?\n1. Reset password\n2. Activate account\n3. Both\n4. Cancel\n\nChoice (1-4): ").strip()
            
            if action in ['1', '3']:
                new_password = input("\nEnter new password for admin_log1: ").strip()
                if not new_password or len(new_password) < 8:
                    print("❌ Password must be at least 8 characters!")
                    return False
                
                hashed = generate_password_hash(new_password)
                try:
                    response = client.table('users').update({
                        'password_hash': hashed
                    }).eq('id', user['id']).execute()
                    
                    if response.data:
                        print(f"✓ Password reset successfully!")
                    else:
                        print(f"❌ Failed to reset password")
                        return False
                except Exception as e:
                    print(f"❌ Error resetting password: {str(e)}")
                    return False
            
            if action in ['2', '3']:
                response = client.table('users').update({
                    'status': 'Active'
                }).eq('id', user['id']).execute()
                
                if response.data:
                    print(f"✓ Account activated!")
                else:
                    print(f"❌ Failed to activate account")
                    return False
            
            print(f"\n✓ admin_log1 is now ready to use!")
            print(f"  - Username: {username}")
            print(f"  - Password: {new_password if action in ['1', '3'] else '(unchanged)'}")
            print(f"  - Status: Active")
            return True
            
        else:
            print(f"\n❌ User '{username}' not found in log1 subsystem")
            print("\nCreating new admin_log1 account...")
            
            password = input("Enter password for new admin_log1 account: ").strip()
            if not password or len(password) < 8:
                print("❌ Password must be at least 8 characters!")
                return False
            
            hashed = generate_password_hash(password)
            
            response = client.table('users').insert({
                'username': username,
                'email': f'{username}@hospital.local',
                'password_hash': hashed,
                'role': 'Administrator',
                'subsystem': 'log1',
                'status': 'Active'
            }).execute()
            
            if response.data:
                print(f"✓ New admin_log1 account created!")
                print(f"  - Username: {username}")
                print(f"  - Password: {password}")
                print(f"  - Role: Admin")
                print(f"  - Status: Active")
                return True
            else:
                print(f"❌ Failed to create account")
                return False
                
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

if __name__ == '__main__':
    try:
        if fix_admin_log1():
            print("\n" + "=" * 60)
            print("✓ Setup complete! You can now log in to LOG1.")
            print("=" * 60)
            sys.exit(0)
        else:
            print("\n❌ Setup failed.")
            sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)
