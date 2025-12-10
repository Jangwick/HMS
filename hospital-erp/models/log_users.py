from app import db
from models.base_user import BaseUser

class LOG1User(BaseUser):
    __tablename__ = 'log1_users'
    __bind_key__ = 'log1'
    department = db.Column(db.String(50), default='LOGISTICS')
    role = db.Column(db.String(50), default='Staff')

class LOG2User(BaseUser):
    __tablename__ = 'log2_users'
    __bind_key__ = 'log2'
    department = db.Column(db.String(50), default='LOGISTICS')
    role = db.Column(db.String(50), default='Staff')
