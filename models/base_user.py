from datetime import datetime, timedelta
import pytz
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

# Password expiry configuration
PASSWORD_EXPIRY_DAYS = 90  # Maximum 90 days
PASSWORD_WARNING_DAYS = 7  # Warn 7 days before expiry

class BaseUser(UserMixin, db.Model):
    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Security Fields
    password_created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    password_expires_at = db.Column(db.DateTime, nullable=False)
    password_history = db.Column(db.JSON, default=list) # Store last 5 hashes
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password, skip_validation=False):
        """
        Set user password with validation.
        
        Args:
            password: The new password to set
            skip_validation: Skip validation (for initial setup/admin reset only)
        """
        if not skip_validation:
            from utils.password_validator import validate_password
            from models.registry import model_registry
            
            # Validate password with all checks
            validate_password(
                password=password,
                password_history=self.password_history,
                check_uniqueness=True,
                user_models=model_registry,
                current_user_id=self.id,
                current_table=getattr(self, '__tablename__', None)
            )
        
        self.password_hash = generate_password_hash(password)
        self.password_created_at = datetime.utcnow()
        self.password_expires_at = datetime.utcnow() + timedelta(days=PASSWORD_EXPIRY_DAYS)
        
        # Update history
        history = self.password_history or []
        history.append(self.password_hash)
        if len(history) > 5:
            history.pop(0)
        self.password_history = history

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_password_expired(self):
        """Check if the password has expired."""
        if self.password_expires_at:
            return datetime.utcnow() > self.password_expires_at
        return False
    
    def days_until_password_expiry(self):
        """Get the number of days until password expires."""
        if self.password_expires_at:
            delta = self.password_expires_at - datetime.utcnow()
            return max(0, delta.days)
        return 0
    
    def should_warn_password_expiry(self):
        """Check if we should warn about password expiry (within 7 days)."""
        days_left = self.days_until_password_expiry()
        return 0 < days_left <= PASSWORD_WARNING_DAYS

    def is_locked(self):
        if self.account_locked_until and self.account_locked_until > datetime.utcnow():
            return True
        return False
        
    def register_failed_login(self):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            # Incremental lockout: 5 mins for 5th attempt, 10 for 6th, 15 for 7th, etc.
            # Formula: (attempts - 4) * 5 minutes
            lockout_minutes = (self.failed_login_attempts - 4) * 5
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)
            
    def register_successful_login(self):
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.last_login = datetime.utcnow()

    def get_id(self):
        # Return composite ID: "bind_key-id"
        # We assume __bind_key__ matches the subsystem code
        return f"{self.__bind_key__}-{self.id}"
