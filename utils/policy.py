from functools import wraps
from flask import flash, redirect, url_for, request, abort
from flask_login import current_user
from utils.hms_models import AuditLog

class HMSFundamentalsPolicy:
    """
    HMS Fundamentals Policy
    A centralized rules engine to ensure security, isolation, and integrity across all subsystems.
    """
    
    @staticmethod
    def check_access(subsystem_code: str):
        """
        Policy Rule 1: Identity & Isolation
        Ensures that a user can only access routes belonging to their assigned subsystem.
        Exception: HR3 Administrators can access all modules for oversight.
        """
        if not current_user.is_authenticated:
            return False, "Session required. Please login."
            
        # Policy Rule 2: Account Stewardship
        # Accounts must be in 'Active' status to perform any operations.
        if current_user.status != 'Active':
            return False, f"Your account status is currently '{current_user.status}'. Access to functional modules is restricted."

        # Global Administrator Privilege (HR3)
        if current_user.subsystem == 'hr3' and current_user.role in ['Admin', 'Administrator']:
            return True, None
            
        # Subsystem Isolation Check
        if current_user.subsystem != subsystem_code:
            # Audit unauthorized access attempts
            AuditLog.log(
                current_user.id, 
                "Unauthorized Access Attempt", 
                subsystem_code, 
                {"attempted_path": request.path, "user_subsystem": current_user.subsystem}
            )
            return False, f"Rule Violation: Your credentials are restricted to the {current_user.subsystem.upper()} department."
            
        return True, None

def policy_required(subsystem_code):
    """
    Decorator to enforce the HMS Fundamentals Policy on routes.
    Prevents cross-blueprint access and ensures account standing.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            authorized, message = HMSFundamentalsPolicy.check_access(subsystem_code)
            if not authorized:
                flash(message, 'danger')
                return redirect(url_for('portal.index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
