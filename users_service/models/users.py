"""Model for users service."""
import datetime
from flask_security import UserMixin
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import backref, relationship
from sqlalchemy_utils import EmailType
from itsdangerous import SignatureExpired, TimedJSONWebSignatureSerializer as Serializer
from users_service import APP, BCRYPT
from users_service.db import DB


class User(DB.Model, UserMixin):
    """Implementation of Users entity."""
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True)
    email = Column(EmailType, unique=True, nullable=False)
    first_name = Column(String(255), nullable=False)
    last_name = Column(String(255), nullable=False)
    google_id = Column(String(255), unique=True, nullable=True, default=None)
    password = Column(String(255), nullable=True, default=None)
    role_id = Column(Integer, ForeignKey('role.id'))
    create_date = Column(DateTime, nullable=False, default=datetime.datetime.now())
    update_date = Column(DateTime, nullable=False, default=datetime.datetime.now())

    def get_reset_token(self, expires_sec=7200):
        """Create reset password token"""
        serial = Serializer(APP.config.get('SECRET_KEY'), expires_sec)
        return serial.dumps({'user_id': self.user_id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        """Check reset password token"""
        serial = Serializer(APP.config.get('SECRET_KEY'))
        try:
            user_id = serial.loads(token)['user_id']
        except SignatureExpired:
            return None
        return User.query.get(user_id)

    def __init__(self, email, first_name, last_name, role_id, password=None, google_id=None):
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.google_id = google_id
        if password:
            self.password = BCRYPT.generate_password_hash(
                password, APP.config.get('BCRYPT_LOG_ROUNDS')
            ).decode()
        self.role_id = role_id


class Role(DB.Model): # pylint: disable=too-few-public-methods
    """Implementation of Roles entity."""
    __tablename__ = "role"

    id = Column(Integer, primary_key=True)
    role_name = Column(String(255), nullable=False)
    role_description = Column(String(255))
    users_roles = relationship('User', backref=backref('role', uselist=False))

    def __init__(self, role_name, role_description):
        self.role_name = role_name
        self.role_description = role_description
