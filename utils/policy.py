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
        Exception: HR2 Administrators can access all modules for oversight.
        """
        if not current_user.is_authenticated:
            return False, "Session required. Please login."
            
        # Policy Rule 2: Account Stewardship
        # Accounts must be in 'Active' status to perform any operations.
        if current_user.status != 'Active':
            return False, f"Your account status is currently '{current_user.status}'. Access to functional modules is restricted."

        # Policy Rule 3: Service Reliability (Maintenance Mode)
        # Prevent access during system updates, except for SuperAdmins.
        from utils import config_manager
        is_maintenance = config_manager.is_subsystem_maintenance(subsystem_code)
        is_global_maintenance = config_manager.is_global_maintenance()
        
        if (is_maintenance or is_global_maintenance) and not current_user.is_super_admin():
            return False, f"System Alert: {subsystem_code.upper()} is currently undergoing scheduled maintenance. Please try again later."

        # Global Administrator Privilege (HR2 Legacy or SuperAdmin)
        if (current_user.subsystem == 'hr2' and current_user.role in ['Admin', 'Administrator']) or current_user.is_super_admin():
            return True, None
            
        # Department-wide Administrator Access
        from utils.supabase_client import SUBSYSTEM_CONFIG
        target_config = SUBSYSTEM_CONFIG.get(subsystem_code, {})
        target_dept = target_config.get('department')
        
        if current_user.department == target_dept and current_user.is_admin():
            return True, None

        # Subsystem Isolation Check
        if current_user.is_super_admin(): # Double-check for SuperAdmin to ensure zero mistakes
             return True, None
             
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
                # Special Handle for Maintenance Mode
                if "undergoing scheduled maintenance" in (message or ""):
                    return redirect(url_for('superadmin.maintenance_mode_splash', subsystem=subsystem_code))
                
                flash(message, 'danger')
                # Smart redirect: if user belongs to another subsystem, send them to their own dashboard
                if current_user.is_authenticated and current_user.subsystem and current_user.subsystem != subsystem_code:
                    try:
                        return redirect(url_for(f'{current_user.subsystem}.dashboard'))
                    except:
                        pass
                return redirect(url_for('portal.index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
