"""
Supabase client utility module.
Provides a Supabase client and User operations using the Supabase Python client.
"""

import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

# Load environment variables
load_dotenv()

# Supabase configuration
SUPABASE_URL: str = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY: str = os.environ.get("SUPABASE_KEY", "")

# Password expiry configuration
PASSWORD_EXPIRY_DAYS = 90
PASSWORD_WARNING_DAYS = 7

# Singleton client instance
_supabase_client: Client = None


def get_supabase_client() -> Client:
    """
    Get or create a Supabase client instance.
    Uses singleton pattern to reuse the same client.
    """
    global _supabase_client
    
    if _supabase_client is None:
        if not SUPABASE_URL or not SUPABASE_KEY:
            raise ValueError(
                "Supabase credentials not configured. "
                "Please set SUPABASE_URL and SUPABASE_KEY in your .env file."
            )
        _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
    
    return _supabase_client


def is_supabase_configured() -> bool:
    """Check if Supabase credentials are configured."""
    return bool(SUPABASE_URL and SUPABASE_KEY)


def format_db_error(e: Exception) -> str:
    """Format database exceptions into user-friendly messages."""
    error_msg = str(e)
    # Check for unique constraint violation (PostgreSQL error code 23505)
    if '23505' in error_msg or 'duplicate key' in error_msg.lower():
        if 'unique_email_per_subsystem' in error_msg or 'email' in error_msg.lower():
            return 'This email address is already registered in this subsystem.'
        if 'username' in error_msg.lower():
            return 'This username is already taken in this subsystem.'
        return 'A record with this information already exists in this subsystem.'
    
    return f'An error occurred: {error_msg}'


class User(UserMixin):
    """
    User model that works with Supabase.
    Single users table with subsystem field to differentiate access.
    """
    
    def __init__(self, data: dict = None):
        if data:
            self.id = data.get('id')
            self.username = data.get('username')
            self.email = data.get('email')
            self.password_hash = data.get('password_hash')
            self.subsystem = data.get('subsystem')
            self.department = data.get('department')
            self.role = data.get('role', 'Staff')
            self.password_created_at = self._parse_datetime(data.get('password_created_at'))
            self.password_expires_at = self._parse_datetime(data.get('password_expires_at'))
            self.password_history = data.get('password_history') or []
            self.failed_login_attempts = data.get('failed_login_attempts', 0)
            self.account_locked_until = self._parse_datetime(data.get('account_locked_until'))
            self.last_login = self._parse_datetime(data.get('last_login'))
            self.created_at = self._parse_datetime(data.get('created_at'))
            self._is_active = data.get('is_active', True)
            self.status = data.get('status', 'Pending') # Pending, Active, Rejected
    
    @property
    def is_active(self):
        """Override UserMixin's is_active property."""
        return self._is_active
    
    def _parse_datetime(self, value):
        """Parse datetime from string or return None."""
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        try:
            # Handle ISO format from Supabase
            return datetime.fromisoformat(value.replace('Z', '+00:00').replace('+00:00', ''))
        except (ValueError, AttributeError):
            return None
    
    def get_id(self):
        """Return composite ID for Flask-Login: subsystem-id"""
        return f"{self.subsystem}-{self.id}"
    
    def check_password(self, password: str) -> bool:
        """Verify password against stored hash."""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
    
    def is_password_expired(self) -> bool:
        """Check if the password has expired."""
        if self.password_expires_at:
            return datetime.utcnow() > self.password_expires_at
        return False
    
    def days_until_password_expiry(self) -> int:
        """Get the number of days until password expires."""
        if self.password_expires_at:
            delta = self.password_expires_at - datetime.utcnow()
            return max(0, delta.days)
        return 0
    
    def should_warn_password_expiry(self) -> bool:
        """Check if we should warn about password expiry (within 7 days)."""
        days_left = self.days_until_password_expiry()
        return 0 < days_left <= PASSWORD_WARNING_DAYS
    
    def is_locked(self) -> bool:
        """Check if account is locked."""
        if self.account_locked_until and self.account_locked_until > datetime.utcnow():
            return True
        return False
    
    @staticmethod
    def get_by_id(user_id: int) -> 'User':
        """Fetch user by ID."""
        try:
            client = get_supabase_client()
            response = client.table('users').select('*').eq('id', user_id).single().execute()
            if response.data:
                return User(response.data)
        except Exception:
            pass
        return None
    
    @staticmethod
    def get_by_username(username: str, subsystem: str = None) -> 'User':
        """Fetch user by username and optional subsystem (case-insensitive)."""
        try:
            client = get_supabase_client()
            query = client.table('users').select('*').ilike('username', username)
            if subsystem:
                query = query.eq('subsystem', subsystem)
            
            response = query.execute()
            if response.data:
                # If subsystem is provided, we should only get one due to unique constraint
                # If not, we return the first one found
                return User(response.data[0])
        except Exception:
            pass
        return None
    
    @staticmethod
    def get_by_composite_id(composite_id: str) -> 'User':
        """Fetch user by composite ID (subsystem-id format)."""
        try:
            if '-' in composite_id:
                subsystem, uid = composite_id.split('-', 1)
                return User.get_by_id(int(uid))
        except Exception:
            pass
        return None
    
    @staticmethod
    def get_all_by_subsystem(subsystem: str) -> list:
        """Fetch all users for a specific subsystem."""
        try:
            client = get_supabase_client()
            response = client.table('users').select('*').eq('subsystem', subsystem).execute()
            return [User(data) for data in response.data] if response.data else []
        except Exception:
            return []
    
    @staticmethod
    def get_all() -> list:
        """Fetch all users."""
        try:
            client = get_supabase_client()
            response = client.table('users').select('*').execute()
            return [User(data) for data in response.data] if response.data else []
        except Exception:
            return []
    
    @staticmethod
    def create(username: str, email: str, password: str, subsystem: str, 
               department: str, role: str = 'Staff', status: str = 'Pending', 
               skip_validation: bool = False) -> 'User':
        """
        Create a new user in the database.
        
        Args:
            username: User's username
            email: User's email
            password: Plain text password (will be hashed)
            subsystem: Subsystem code (hr1, hr2, ct1, etc.)
            department: Department name
            role: User role (default: Staff)
            skip_validation: Skip password validation (for initial setup)
        """
        if not skip_validation:
            from utils.password_validator import validate_password
            validate_password(password=password)
        
        now = datetime.utcnow()
        password_hash = generate_password_hash(password)
        
        data = {
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'subsystem': subsystem,
            'department': department,
            'role': role,
            'password_created_at': now.isoformat(),
            'password_expires_at': (now + timedelta(days=PASSWORD_EXPIRY_DAYS)).isoformat(),
            'password_history': [password_hash],
            'failed_login_attempts': 0,
            'is_active': status == 'Active',
            'status': status,
            'created_at': now.isoformat()
        }
        
        client = get_supabase_client()
        response = client.table('users').insert(data).execute()
        
        if response.data:
            return User(response.data[0])
        return None
    
    def update(self, **kwargs) -> bool:
        """Update user fields in the database."""
        # Convert datetime objects to ISO format
        update_data = {}
        for key, value in kwargs.items():
            if isinstance(value, datetime):
                update_data[key] = value.isoformat()
            else:
                update_data[key] = value
        
        client = get_supabase_client()
        response = client.table('users').update(update_data).eq('id', self.id).execute()
        
        # Update local attributes
        for key, value in kwargs.items():
            if key == 'is_active':
                self._is_active = value
            else:
                setattr(self, key, value)
        
        return bool(response.data)
    
    def set_password(self, password: str, skip_validation: bool = False) -> bool:
        """
        Set a new password for the user.
        
        Args:
            password: The new password
            skip_validation: Skip validation (for admin reset only)
        """
        if not skip_validation:
            from utils.password_validator import validate_password
            validate_password(
                password=password,
                password_history=self.password_history,
                check_uniqueness=True,
                current_user_id=self.id
            )
        
        now = datetime.utcnow()
        new_hash = generate_password_hash(password)
        
        # Update password history (keep last 5)
        history = self.password_history or []
        history.append(new_hash)
        if len(history) > 5:
            history.pop(0)
        
        return self.update(
            password_hash=new_hash,
            password_created_at=now,
            password_expires_at=now + timedelta(days=PASSWORD_EXPIRY_DAYS),
            password_history=history
        )
    
    def register_failed_login(self) -> None:
        """Register a failed login attempt."""
        attempts = (self.failed_login_attempts or 0) + 1
        update_data = {'failed_login_attempts': attempts}
        
        if attempts >= 5:
            lockout_minutes = (attempts - 4) * 5
            update_data['account_locked_until'] = (
                datetime.utcnow() + timedelta(minutes=lockout_minutes)
            )
        
        self.update(**update_data)
    
    def register_successful_login(self) -> None:
        """Register a successful login."""
        self.update(
            failed_login_attempts=0,
            account_locked_until=None,
            last_login=datetime.utcnow()
        )
    
    def delete(self) -> bool:
        """Delete the user from the database."""
        client = get_supabase_client()
        response = client.table('users').delete().eq('id', self.id).execute()
        return bool(response.data)


# Subsystem configuration mapping
SUBSYSTEM_CONFIG = {
    'hr1': {'department': 'HR', 'name': 'Recruitment'},
    'hr2': {'department': 'HR', 'name': 'Payroll Management'},
    'hr3': {'department': 'HR', 'name': 'Benefits Administration'},
    'hr4': {'department': 'HR', 'name': 'Compensation & Analytics'},
    'ct1': {'department': 'CORE_TRANSACTION', 'name': 'Patient Registration'},
    'ct2': {'department': 'CORE_TRANSACTION', 'name': 'Pharmacy & Labs'},
    'ct3': {'department': 'CORE_TRANSACTION', 'name': 'Medical Records'},
    'log1': {'department': 'LOGISTICS', 'name': 'Inventory Management'},
    'log2': {'department': 'LOGISTICS', 'name': 'Procurement'},
    'financials': {'department': 'FINANCIALS', 'name': 'Financial Management System'},
}
