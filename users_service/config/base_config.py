"""Base configuration for users service"""

import os
BASEDIR = os.path.abspath(os.path.dirname(__file__))

class Configuration:
    """Base configuration."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'my_precious')
    DEBUG = False
    TESTING = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = True
