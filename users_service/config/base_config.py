"""Base configuration for users service"""

import os
BASEDIR = os.path.abspath(os.path.dirname(__file__))

class Configuration:
    """Base configuration."""
    DEBUG = False
    TESTING = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = True
