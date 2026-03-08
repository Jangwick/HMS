"""
Role-based access control guards for the HR module.
Provides decorators to enforce strict separation between account types.
"""

from functools import wraps
from flask import flash, redirect, url_for, abort
from flask_login import current_user


class HRRoles:
    """Strict role definitions for the HR module."""
    APPLICANT = 'Applicant'
    HR_STAFF = 'HR_Staff'
    INTERVIEWER = 'Interviewer'
    MANAGER = 'Manager'
    ADMIN = 'Admin'
    ADMINISTRATOR = 'Administrator'
    SUPER_ADMIN = 'SuperAdmin'
    STAFF = 'Staff'

    # Roles allowed to perform interviewer duties
    INTERVIEWER_CAPABLE = [HR_STAFF, INTERVIEWER, MANAGER, ADMIN, ADMINISTRATOR, SUPER_ADMIN, STAFF]

    # Roles that are strictly applicant-level (cannot access HR functions)
    APPLICANT_ONLY = [APPLICANT]

    # Roles that can manage probation cycles
    SUPERVISOR_ROLES = [HR_STAFF, MANAGER, ADMIN, ADMINISTRATOR, SUPER_ADMIN]

    # Roles that can approve recognitions
    APPROVER_ROLES = [MANAGER, ADMIN, ADMINISTRATOR, SUPER_ADMIN]

    @staticmethod
    def can_interview(role: str) -> bool:
        """Check if the given role can conduct interviews."""
        return role in HRRoles.INTERVIEWER_CAPABLE

    @staticmethod
    def is_applicant(role: str) -> bool:
        """Check if the given role is an applicant."""
        return role == HRRoles.APPLICANT

    @staticmethod
    def can_supervise(role: str) -> bool:
        """Check if the given role can supervise probation cycles."""
        return role in HRRoles.SUPERVISOR_ROLES

    @staticmethod
    def can_approve(role: str) -> bool:
        """Check if the given role can approve recognitions."""
        return role in HRRoles.APPROVER_ROLES


def hr_role_required(*allowed_roles):
    """
    Decorator that restricts access to specific HR roles.
    SuperAdmins always pass.

    Usage:
        @hr_role_required('HR_Staff', 'Interviewer', 'Manager', 'Admin')
        def my_route():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'danger')
                return redirect(url_for('hr1.login'))
            if current_user.is_super_admin():
                return f(*args, **kwargs)
            if current_user.role not in allowed_roles:
                flash('Access denied: insufficient role privileges.', 'danger')
                return redirect(url_for('hr1.dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def prevent_applicant_access(f):
    """
    Blocks any user with Applicant role from accessing the route.
    Used as a decorator on HR staff-only routes.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and HRRoles.is_applicant(current_user.role):
            flash('Applicant accounts cannot access HR staff functions.', 'danger')
            return redirect(url_for('portal.index'))
        return f(*args, **kwargs)
    return decorated_function


def supervisor_required(f):
    """
    Ensures only supervisors (Manager+) or SuperAdmins can access the route.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('hr1.login'))
        if current_user.is_super_admin():
            return f(*args, **kwargs)
        if not HRRoles.can_supervise(current_user.role):
            flash('Access denied: supervisor privileges required.', 'danger')
            return redirect(url_for('hr1.dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def validate_interviewer(user_id: int) -> bool:
    """
    Validate that a user has the appropriate role to be an interviewer.
    Returns True if valid, raises ValueError if not.
    """
    from utils.supabase_client import User
    user = User.get_by_id(user_id)
    if not user:
        raise ValueError("Interviewer user not found.")
    if not HRRoles.can_interview(user.role):
        raise ValueError(
            f"User '{user.username}' has role '{user.role}' and cannot be assigned as an interviewer. "
            f"Only users with HR Staff, Interviewer, Manager, or Admin roles can conduct interviews."
        )
    return True
