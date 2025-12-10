from app import db
from models.base_user import BaseUser

class LOG1User(BaseUser):
    __tablename__ = 'log1_users'
    department = db.Column(db.String(50), default='LOGISTICS')
    role = db.Column(db.String(50), default='Staff')

class LOG2User(BaseUser):
    __tablename__ = 'log2_users'
    department = db.Column(db.String(50), default='LOGISTICS')
    role = db.Column(db.String(50), default='Staff')
