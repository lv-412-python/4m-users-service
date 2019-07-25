"""Configuration for development."""
import os
from users_service.config.base_config import Configuration

BASEDIR = os.path.abspath(os.path.dirname(__file__))
POSTGRES_LOCAL_BASE = 'postgresql://postgres:mysecretpassword@db:5432/'
DATABASE_NAME = '4m_users_db'


class DevConfiguration(Configuration):
    """Development configuration."""
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = '{}{}'.format(POSTGRES_LOCAL_BASE, DATABASE_NAME)

    SESSION_COOKIE_SECURE=False
    SESSION_COOKIE_HTTPONLY=False
