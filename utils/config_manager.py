import os

# Internal cache for settings to avoid repeated env lookups
_settings_cache = {}

def get_setting(key, default=None):
    """
    Get a system setting, prioritizing environment variables.
    This acts as a bridge for a future database-backed settings table.
    """
    # Check environment first
    val = os.environ.get(key)
    if val is not None:
        return val
    
    return default

def get_int_setting(key, default=0):
    """Get a system setting as an integer."""
    try:
        return int(get_setting(key, default))
    except (ValueError, TypeError):
        return default

def get_bool_setting(key, default=False):
    """Get a system setting as a boolean."""
    val = get_setting(key)
    if val is None:
        return default
    return str(val).lower() in ('true', '1', 'on', 'yes')

def set_setting(key, value):
    """
    Set a system setting (simulated persistence via os.environ).
    """
    os.environ[key] = str(value)

# Specialized Getters for Core Policies
def get_password_policy():
    return {
        'expiry_days': get_int_setting('PASSWORD_EXPIRY_DAYS', 90),
        'min_length': get_int_setting('PASSWORD_MIN_LENGTH', 8),
        'max_length': get_int_setting('PASSWORD_MAX_LENGTH', 14)
    }

def get_lockout_policy():
    return {
        'max_attempts': get_int_setting('MAX_LOGIN_ATTEMPTS', 5),
        'duration_mins': get_int_setting('LOCKOUT_DURATION_MINS', 30)
    }

def get_session_policy():
    return {
        'timeout_mins': get_int_setting('SESSION_TIMEOUT_MINS', 30)
    }

def is_global_maintenance():
    return get_bool_setting('MAINTENANCE_GLOBAL', False)

def is_subsystem_maintenance(subsystem_code):
    if not subsystem_code:
        return False
    return get_bool_setting(f'MAINTENANCE_{subsystem_code.upper()}', False)
