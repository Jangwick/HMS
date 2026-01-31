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

    from routes.admin import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')

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

    # Financials (Unified)
    from routes.financials.main import financials_bp
    app.register_blueprint(financials_bp, url_prefix='/financials')

    # User Loader for Flask-Login using Supabase
    @login_manager.user_loader
    def load_user(user_id):
        try:
            from utils.supabase_client import User
            return User.get_by_composite_id(user_id)
        except Exception:
            return None

    @app.template_filter('datetime')
    def format_datetime(value, format="%Y-%m-%d %H:%M"):
        if value is None:
            return ""
        if isinstance(value, str):
            try:
                from datetime import datetime
                # Handle ISO format and some potential variations
                if 'T' in value:
                    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                else:
                    dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                return dt.strftime(format)
            except Exception:
                return value
        return value.strftime(format)

    @app.context_processor
    def inject_now():
        from datetime import datetime
        return {'now': datetime.now}

    @app.context_processor
    def inject_notifications():
        from flask_login import current_user
        from utils.hms_models import Notification
        if current_user.is_authenticated:
            try:
                notifications = Notification.get_for_user(current_user)
                unread_count = Notification.get_unread_count(current_user)
                return {
                    'sys_notifications': notifications,
                    'unread_notifications_count': unread_count
                }
            except Exception as e:
                print(f"Context Processor Notification Error: {e}")
        return {
            'sys_notifications': [],
            'unread_notifications_count': 0
        }

    @app.context_processor
    def inject_attendance():
        from flask_login import current_user
        from utils.supabase_client import get_supabase_client
        if current_user.is_authenticated:
            try:
                client = get_supabase_client()
                active_log = client.table('attendance_logs').select('*').eq('user_id', current_user.id).is_('clock_out', 'null').execute()
                return {'active_attendance': active_log.data[0] if active_log.data else None}
            except Exception:
                pass
        return {'active_attendance': None}

    @app.after_request
    def add_header(response):
        """
        Add headers to both force latest IE rendering engine or Chrome Frame,
        and also to cache results for as little time as possible.
        """
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    return app
