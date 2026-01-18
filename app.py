from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_session import Session
from config import Config
import os

# Initialize extensions
csrf = CSRFProtect()
login_manager = LoginManager()

def create_app(config_class=Config):
    # Determine instance path: /tmp for Vercel, local 'instance' for development
    if os.environ.get('VERCEL'):
        instance_path = '/tmp/instance'
    else:
        instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
        
    app = Flask(__name__, instance_path=instance_path)

    app.config.from_object(config_class)

    try:
        os.makedirs(app.instance_path, exist_ok=True)
        session_dir = app.config.get('SESSION_FILE_DIR')
        if session_dir and app.config.get('SESSION_TYPE') == 'filesystem':
            os.makedirs(session_dir, exist_ok=True)
    except OSError:
        pass

    # Initialize extensions
    csrf.init_app(app)
    Session(app)
    login_manager.init_app(app)

    # Register Blueprints
    from routes.portal import portal_bp
    app.register_blueprint(portal_bp)

    # HR
    from routes.hr.hr1 import hr1_bp
    app.register_blueprint(hr1_bp, url_prefix='/hr/hr1')
    from routes.hr.hr2 import hr2_bp
    app.register_blueprint(hr2_bp, url_prefix='/hr/hr2')
    from routes.hr.hr3 import hr3_bp
    app.register_blueprint(hr3_bp, url_prefix='/hr/hr3')
    from routes.hr.hr4 import hr4_bp
    app.register_blueprint(hr4_bp, url_prefix='/hr/hr4')

    # Core Transaction
    from routes.core_transaction.ct1 import ct1_bp
    app.register_blueprint(ct1_bp, url_prefix='/core-transaction/ct1')
    from routes.core_transaction.ct2 import ct2_bp
    app.register_blueprint(ct2_bp, url_prefix='/core-transaction/ct2')
    from routes.core_transaction.ct3 import ct3_bp
    app.register_blueprint(ct3_bp, url_prefix='/core-transaction/ct3')

    # Logistics
    from routes.logistics.log1 import log1_bp
    app.register_blueprint(log1_bp, url_prefix='/logistics/log1')
    from routes.logistics.log2 import log2_bp
    app.register_blueprint(log2_bp, url_prefix='/logistics/log2')

    # Financials
    from routes.financials.fin1 import fin1_bp
    app.register_blueprint(fin1_bp, url_prefix='/financials/fin1')
    from routes.financials.fin2 import fin2_bp
    app.register_blueprint(fin2_bp, url_prefix='/financials/fin2')
    from routes.financials.fin3 import fin3_bp
    app.register_blueprint(fin3_bp, url_prefix='/financials/fin3')
    from routes.financials.fin4 import fin4_bp
    app.register_blueprint(fin4_bp, url_prefix='/financials/fin4')
    from routes.financials.fin5 import fin5_bp
    app.register_blueprint(fin5_bp, url_prefix='/financials/fin5')

    # User Loader for Flask-Login using Supabase
    @login_manager.user_loader
    def load_user(user_id):
        try:
            from utils.supabase_client import User
            return User.get_by_composite_id(user_id)
        except Exception:
            return None

    @app.context_processor
    def inject_now():
        from datetime import datetime
        return {'now': datetime.now}

    return app
