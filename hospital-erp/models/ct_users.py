from app import db
from models.base_user import BaseUser

class CT1User(BaseUser):
    __tablename__ = 'ct1_users'
    __bind_key__ = 'ct1'
    department = db.Column(db.String(50), default='CORE_TRANSACTION')
    role = db.Column(db.String(50), default='Staff')

class CT2User(BaseUser):
    __tablename__ = 'ct2_users'
    __bind_key__ = 'ct2'
    department = db.Column(db.String(50), default='CORE_TRANSACTION')
    role = db.Column(db.String(50), default='Staff')

class CT3User(BaseUser):
    __tablename__ = 'ct3_users'
    __bind_key__ = 'ct3'
    department = db.Column(db.String(50), default='CORE_TRANSACTION')
    role = db.Column(db.String(50), default='Staff')
