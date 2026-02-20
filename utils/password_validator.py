"""
Password validation utility module.
Implements password requirements including:
- Length constraints (8-14 characters)
- Complexity requirements (uppercase, number, special character)
- Password history/uniqueness validation
"""

import re
from werkzeug.security import check_password_hash
from utils import config_manager

# Configuration
SPECIAL_CHARACTERS = r'$!@#$%^&*()_+\-=\[\]{}|;:\'",.\/<>?~`'

def get_constraints():
    policy = config_manager.get_password_policy()
    return policy['min_length'], policy['max_length']

class PasswordValidationError(Exception):
    """Custom exception for password validation errors."""
    def __init__(self, message, errors=None):
        super().__init__(message)
        self.message = message
        self.errors = errors or []


def validate_password_length(password):
    """
    Validate password length based on system policy.
    Returns: (is_valid, error_message or None)
    """
    min_l, max_l = get_constraints()
    length = len(password)
    if length < min_l or length > max_l:
        return False, f'Password must be {min_l}-{max_l} characters long. Currently {length} characters.'
    return True, None


def validate_password_complexity(password):
    """
    Validate password complexity requirements.
    - At least 1 uppercase letter (A-Z)
    - At least 1 numeric digit (0-9)
    - At least 1 special character
    Returns: (is_valid, error_messages list)
    """
    errors = []
    
    # Check for uppercase letter
    if not re.search(r'[A-Z]', password):
        errors.append('Password must contain at least 1 uppercase letter.')
    
    # Check for number
    if not re.search(r'[0-9]', password):
        errors.append('Password must contain at least 1 number.')
    
    # Check for special character
    if not re.search(r'[' + re.escape(SPECIAL_CHARACTERS) + r']', password):
        errors.append('Password must contain at least 1 special character.')
    
    return len(errors) == 0, errors


def check_password_in_history(password, password_history):
    """
    Check if password exists in user's password history.
    Returns: (is_unique, error_message or None)
    """
    if not password_history:
        return True, None
    
    for old_hash in password_history:
        if check_password_hash(old_hash, password):
            return False, 'This password was recently used. Please choose a different password.'
    
    return True, None


def check_password_across_accounts(password, current_user_id=None):
    """
    Check if password is used across any other user accounts in the system.
    This prevents users from using the same password on multiple subsystems.
    Uses Supabase to query all users.
    
    Args:
        password: The password to check
        current_user_id: The ID of the current user (to exclude from check)
    
    Returns: (is_unique, error_message or None)
    """
    try:
        from utils.supabase_client import User
        users = User.get_all()
        
        for user in users:
            # Skip the current user
            if current_user_id and user.id == current_user_id:
                continue
            
            # Check if password matches this user's password
            if user.password_hash and check_password_hash(user.password_hash, password):
                return False, 'This password is already in use on another account. Please choose a different password.'
    except Exception:
        # If we can't check, allow the password (fail open for this check)
        pass
    
    return True, None


def validate_password(password, password_history=None, check_uniqueness=False, 
                     current_user_id=None):
    """
    Comprehensive password validation.
    
    Args:
        password: The password to validate
        password_history: List of previous password hashes for this user
        check_uniqueness: Whether to check across all accounts
        current_user_id: Current user's ID (to exclude from uniqueness check)
    
    Returns: (is_valid, list of error messages)
    
    Raises:
        PasswordValidationError: If validation fails
    """
    all_errors = []
    
    # Step 1: Check length constraints
    is_valid, error = validate_password_length(password)
    if not is_valid:
        all_errors.append(error)
    
    # Step 2: Check complexity requirements
    is_valid, errors = validate_password_complexity(password)
    if not is_valid:
        all_errors.extend(errors)
    
    # Step 3: Check against password history
    if password_history:
        is_valid, error = check_password_in_history(password, password_history)
        if not is_valid:
            all_errors.append(error)
    
    # Step 4: Check across all accounts (if enabled)
    if check_uniqueness:
        is_valid, error = check_password_across_accounts(password, current_user_id)
        if not is_valid:
            all_errors.append(error)
    
    if all_errors:
        raise PasswordValidationError(
            'Password validation failed.',
            errors=all_errors
        )
    
    return True, []


def get_password_requirements():
    """
    Return a dictionary of password requirements for display purposes.
    """
    min_l, max_l = get_constraints()
    return {
        'min_length': min_l,
        'max_length': max_l,
        'requires_uppercase': True,
        'requires_number': True,
        'requires_special': True,
        'special_characters': SPECIAL_CHARACTERS
    }
