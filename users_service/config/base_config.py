"""Base configuration for users service"""

import os
BASEDIR = os.path.abspath(os.path.dirname(__file__))

class Configuration:
    """Base configuration."""
    DEBUG = False
    TESTING = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = True    
    JWT_TOKEN_LOCATION = 'cookies'
    JWT_ACCESS_COOKIE_PATH = '/auth'
    JWT_REFRESH_COOKIE_PATH = ''
    JWT_SECRET_KEY = 'very_secret'
