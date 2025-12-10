from app import db
from models.base_user import BaseUser

class HR1User(BaseUser):
    __tablename__ = 'hr1_users'
    __bind_key__ = 'hr1'
    department = db.Column(db.String(50), default='HR')
    role = db.Column(db.String(50), default='Staff')

class HR2User(BaseUser):
    __tablename__ = 'hr2_users'
    __bind_key__ = 'hr2'
    department = db.Column(db.String(50), default='HR')
    role = db.Column(db.String(50), default='Staff')

class HR3User(BaseUser):
    __tablename__ = 'hr3_users'
    __bind_key__ = 'hr3'
    department = db.Column(db.String(50), default='HR')
    role = db.Column(db.String(50), default='Staff')

class HR4User(BaseUser):
    __tablename__ = 'hr4_users'
    __bind_key__ = 'hr4'
    department = db.Column(db.String(50), default='HR')
    role = db.Column(db.String(50), default='Staff')
