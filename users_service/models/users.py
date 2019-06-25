"""Model for users service."""
import datetime
import jwt
from sqlalchemy import Column, Integer, String, SmallInteger, DateTime
from flask_security import UserMixin
from users_service import APP, BCRYPT
from users_service.db import DB
from users_service.models.blacklist_token import BlacklistToken

class User(DB.Model, UserMixin):
    """Implementation of Users entity."""
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False)
    first_name = Column(String(255), nullable=False)
    last_name = Column(String(255), nullable=False)
    google_id = Column(String(255), unique=True, nullable=True, default=None)
    password = Column(String(255), nullable=True, default=None)
    admin = Column(SmallInteger, nullable=False, default=0)
    create_date = Column(DateTime, nullable=False, default=datetime.datetime.now())
    update_date = Column(DateTime, nullable=False, default=datetime.datetime.now())

    def __init__(self, email, first_name, last_name, password=None, google_id=None):
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.google_id = google_id
        self.password = BCRYPT.generate_password_hash(
            password, APP.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()

    def __repr__(self):
        return f"id = {self.user_id}, email = {self.email}," \
            f" first_name = {self.first_name}, last_name = {self.last_name}," \
            f" create_date = {self.create_date}"

    @staticmethod
    def encode_auth_token(user_id):
        """
        Generates the Auth Token
        :return: bytes
        """
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=5000),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            APP.config.get('SECRET_KEY'),
            algorithm='HS256'
        )

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, APP.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'
