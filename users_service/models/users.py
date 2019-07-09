"""Model for users service."""
import datetime
from flask_security import UserMixin
from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy_utils import EmailType
from users_service import APP, BCRYPT
from users_service.db import DB


class User(DB.Model, UserMixin): # pylint: disable=too-few-public-methods
    """Implementation of Users entity."""
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True)
    email = Column(EmailType, unique=True, nullable=False)
    first_name = Column(String(255), nullable=False)
    last_name = Column(String(255), nullable=False)
    google_id = Column(String(255), unique=True, nullable=True, default=None)
    password = Column(String(255), nullable=True, default=None)
    create_date = Column(DateTime, nullable=False, default=datetime.datetime.now())
    update_date = Column(DateTime, nullable=False, default=datetime.datetime.now())

    def __init__(self, email, first_name, last_name, password=None, google_id=None):
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.google_id = google_id
        if password:
            self.password = BCRYPT.generate_password_hash(
                password, APP.config.get('BCRYPT_LOG_ROUNDS')
            ).decode()
