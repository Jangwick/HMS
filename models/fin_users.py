from app import db
from models.base_user import BaseUser

class FIN1User(BaseUser):
    __tablename__ = 'fin1_users'
    department = db.Column(db.String(50), default='FINANCIALS')
    role = db.Column(db.String(50), default='Staff')

class FIN2User(BaseUser):
    __tablename__ = 'fin2_users'
    department = db.Column(db.String(50), default='FINANCIALS')
    role = db.Column(db.String(50), default='Staff')

class FIN3User(BaseUser):
    __tablename__ = 'fin3_users'
    department = db.Column(db.String(50), default='FINANCIALS')
    role = db.Column(db.String(50), default='Staff')

class FIN4User(BaseUser):
    __tablename__ = 'fin4_users'
    department = db.Column(db.String(50), default='FINANCIALS')
    role = db.Column(db.String(50), default='Staff')

class FIN5User(BaseUser):
    __tablename__ = 'fin5_users'
    department = db.Column(db.String(50), default='FINANCIALS')
    role = db.Column(db.String(50), default='Staff')
