from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from config import Config
import os

# Initialize extensions
db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure instance folder exists
    try:
        os.makedirs(os.path.join(app.instance_path))
    except OSError:
        pass

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
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

    # Dynamic User Loader
    from models.registry import model_registry
    
    @login_manager.user_loader
    def load_user(user_id):
        try:
            # Expecting format "subsystem-id"
            if '-' in user_id:
                subsystem, uid = user_id.split('-', 1)
                model = model_registry.get(subsystem)
                if model:
                    return model.query.get(int(uid))
            else:
                # Fallback for legacy or HR1 if it was created without composite ID logic initially
                # But since we updated BaseUser, it should be fine.
                # Just in case, try HR1
                from models.hr_user import HR1User
                return HR1User.query.get(int(user_id))
        except Exception:
            return None

    return app
