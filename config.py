import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-please-change-in-prod'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Base directory
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    
    # Database URIs - Using SQLite for development
    # In production, these would be PostgreSQL connection strings
    SQLALCHEMY_BINDS = {
        'hr1': f'sqlite:///{os.path.join(BASE_DIR, "instance", "hr1.db")}',
        'hr2': f'sqlite:///{os.path.join(BASE_DIR, "instance", "hr2.db")}',
        'hr3': f'sqlite:///{os.path.join(BASE_DIR, "instance", "hr3.db")}',
        'hr4': f'sqlite:///{os.path.join(BASE_DIR, "instance", "hr4.db")}',
        
        'ct1': f'sqlite:///{os.path.join(BASE_DIR, "instance", "ct1.db")}',
        'ct2': f'sqlite:///{os.path.join(BASE_DIR, "instance", "ct2.db")}',
        'ct3': f'sqlite:///{os.path.join(BASE_DIR, "instance", "ct3.db")}',
        
        'log1': f'sqlite:///{os.path.join(BASE_DIR, "instance", "log1.db")}',
        'log2': f'sqlite:///{os.path.join(BASE_DIR, "instance", "log2.db")}',
        
        'fin1': f'sqlite:///{os.path.join(BASE_DIR, "instance", "fin1.db")}',
        'fin2': f'sqlite:///{os.path.join(BASE_DIR, "instance", "fin2.db")}',
        'fin3': f'sqlite:///{os.path.join(BASE_DIR, "instance", "fin3.db")}',
        'fin4': f'sqlite:///{os.path.join(BASE_DIR, "instance", "fin4.db")}',
        'fin5': f'sqlite:///{os.path.join(BASE_DIR, "instance", "fin5.db")}',
    }
    
    # Default database (not really used but required by Flask-SQLAlchemy)
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(BASE_DIR, "instance", "main.db")}'

    # Session Configuration
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = False
    PERMANENT_SESSION_LIFETIME = 1800 # 30 minutes

    # Security
    BCRYPT_LOG_ROUNDS = 12
