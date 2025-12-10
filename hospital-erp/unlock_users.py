from app import create_app, db
from models.registry import model_registry

app = create_app()

def unlock_users():
    with app.app_context():
        print("Unlocking all admin accounts...")
        for code, model in model_registry.items():
            username = f'admin_{code}'
            user = model.query.filter_by(username=username).first()
            if user:
                user.failed_login_attempts = 0
                user.account_locked_until = None
                db.session.commit()
                print(f"Unlocked {username}")
            else:
                print(f"User {username} not found")
        print("All accounts unlocked.")

if __name__ == '__main__':
    unlock_users()
