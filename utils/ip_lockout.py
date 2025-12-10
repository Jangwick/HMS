"""
IP-based login lockout system.

This module provides an in-memory tracking system for failed login attempts
based on IP address rather than user accounts. This prevents attackers from
locking out legitimate users by repeatedly failing login attempts.

The lockout uses incremental timeouts:
- 5 failed attempts: 5 minute lockout
- 6 failed attempts: 10 minute lockout
- 7 failed attempts: 15 minute lockout
- etc.
"""

from datetime import datetime, timedelta
from threading import Lock
from flask import request
import pytz

# Thread-safe storage for IP-based lockout tracking
_ip_attempts = {}
_ip_lockouts = {}
_lock = Lock()

# Configuration
MAX_ATTEMPTS_BEFORE_LOCKOUT = 5
BASE_LOCKOUT_MINUTES = 5


def get_client_ip():
    """Get the client's IP address, handling proxies."""
    # Check for X-Forwarded-For header (common with reverse proxies)
    if request.headers.get('X-Forwarded-For'):
        # Take the first IP in the chain (original client)
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    # Check for X-Real-IP header
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    # Fall back to remote_addr
    return request.remote_addr


def is_ip_locked(ip_address=None):
    """
    Check if an IP address is currently locked out.
    
    Args:
        ip_address: The IP to check. If None, uses the current request's IP.
        
    Returns:
        tuple: (is_locked: bool, remaining_seconds: int, unlock_time_str: str)
    """
    if ip_address is None:
        ip_address = get_client_ip()
    
    with _lock:
        if ip_address not in _ip_lockouts:
            return False, 0, None
        
        locked_until = _ip_lockouts[ip_address]
        now = datetime.utcnow()
        
        if locked_until > now:
            remaining_seconds = int((locked_until - now).total_seconds())
            
            # Convert to Manila time for display
            tz_manila = pytz.timezone('Asia/Manila')
            locked_until_utc = pytz.utc.localize(locked_until)
            unlock_time_manila = locked_until_utc.astimezone(tz_manila)
            unlock_time_str = unlock_time_manila.strftime("%I:%M%p").lower()
            
            return True, remaining_seconds, unlock_time_str
        else:
            # Lockout has expired, clean up
            del _ip_lockouts[ip_address]
            return False, 0, None


def register_failed_attempt(ip_address=None):
    """
    Register a failed login attempt for an IP address.
    
    Args:
        ip_address: The IP to register. If None, uses the current request's IP.
        
    Returns:
        tuple: (is_now_locked: bool, remaining_attempts: int, remaining_seconds: int, unlock_time_str: str)
    """
    if ip_address is None:
        ip_address = get_client_ip()
    
    with _lock:
        # Increment attempt counter
        if ip_address not in _ip_attempts:
            _ip_attempts[ip_address] = 0
        _ip_attempts[ip_address] += 1
        
        attempts = _ip_attempts[ip_address]
        
        # Check if we should lock
        if attempts >= MAX_ATTEMPTS_BEFORE_LOCKOUT:
            # Incremental lockout: (attempts - 4) * 5 minutes
            lockout_minutes = (attempts - MAX_ATTEMPTS_BEFORE_LOCKOUT + 1) * BASE_LOCKOUT_MINUTES
            locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)
            _ip_lockouts[ip_address] = locked_until
            
            remaining_seconds = int(lockout_minutes * 60)
            
            # Convert to Manila time for display
            tz_manila = pytz.timezone('Asia/Manila')
            locked_until_utc = pytz.utc.localize(locked_until)
            unlock_time_manila = locked_until_utc.astimezone(tz_manila)
            unlock_time_str = unlock_time_manila.strftime("%I:%M%p").lower()
            
            return True, 0, remaining_seconds, unlock_time_str
        else:
            remaining = MAX_ATTEMPTS_BEFORE_LOCKOUT - attempts
            return False, remaining, 0, None


def register_successful_login(ip_address=None):
    """
    Register a successful login, clearing failed attempts for the IP.
    
    Args:
        ip_address: The IP to clear. If None, uses the current request's IP.
    """
    if ip_address is None:
        ip_address = get_client_ip()
    
    with _lock:
        if ip_address in _ip_attempts:
            del _ip_attempts[ip_address]
        if ip_address in _ip_lockouts:
            del _ip_lockouts[ip_address]


def get_failed_attempts(ip_address=None):
    """
    Get the current number of failed attempts for an IP.
    
    Args:
        ip_address: The IP to check. If None, uses the current request's IP.
        
    Returns:
        int: Number of failed attempts
    """
    if ip_address is None:
        ip_address = get_client_ip()
    
    with _lock:
        return _ip_attempts.get(ip_address, 0)


def clear_all_lockouts():
    """Clear all IP lockouts (admin function)."""
    with _lock:
        _ip_attempts.clear()
        _ip_lockouts.clear()


def clear_ip_lockout(ip_address):
    """
    Clear lockout for a specific IP address.
    
    Args:
        ip_address: The IP to unlock.
    """
    with _lock:
        if ip_address in _ip_attempts:
            del _ip_attempts[ip_address]
        if ip_address in _ip_lockouts:
            del _ip_lockouts[ip_address]


def get_all_locked_ips():
    """
    Get all currently locked IP addresses.
    
    Returns:
        dict: {ip_address: locked_until_datetime}
    """
    now = datetime.utcnow()
    with _lock:
        # Return only IPs that are still locked
        return {
            ip: locked_until 
            for ip, locked_until in _ip_lockouts.items() 
            if locked_until > now
        }
