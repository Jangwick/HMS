#!/usr/bin/env python3
"""
Direct password reset for admin_log1
"""

from utils.supabase_client import get_supabase_client
from werkzeug.security import generate_password_hash

def reset_admin_log1():
    client = get_supabase_client()
    
    username = 'admin_log1'
    new_password = 'Admin@12345'
    
    print("Resetting admin_log1 credentials...")
    
    try:
        # Get user
        response = client.table('users').select('id').eq('username', username).eq('subsystem', 'log1').execute()
        users = response.data or []
        
        if not users:
            print(f"ERROR: User '{username}' not found in log1")
            return False
        
        user_id = users[0]['id']
        hashed = generate_password_hash(new_password)
        
        # Update password
        response = client.table('users').update({
            'password_hash': hashed
        }).eq('id', user_id).execute()
        
        if response.data:
            print(f"\n✓ SUCCESS! admin_log1 credentials reset")
            print(f"  Username: {username}")
            print(f"  Password: {new_password}")
            print(f"  Subsystem: log1")
            return True
        else:
            print("ERROR: Failed to update password")
            return False
            
    except Exception as e:
        print(f"ERROR: {str(e)}")
        return False

if __name__ == '__main__':
    reset_admin_log1()
