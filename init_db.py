from app import create_app, db
from models.registry import model_registry
import os

app = create_app()

def init_db():
    with app.app_context():
        # Create tables for all binds
        db.create_all()
        
        print("Initializing Databases...")
        
        for code, model in model_registry.items():
            username = f'admin_{code}'
            email = f'admin@{code}.hms.com'
            dept = model.department.default.arg if hasattr(model.department.default, 'arg') else 'UNKNOWN'
            
            if not model.query.filter_by(username=username).first():
                user = model(
                    username=username,
                    email=email,
                    department=dept,
                    role='Administrator'
                )
                user.set_password('Admin@12345')
                db.session.add(user)
                print(f"Created {code} user: {username}")
            else:
                print(f"User {username} already exists.")
        
        db.session.commit()
        print("Database initialization complete.")

if __name__ == '__main__':
    init_db()
