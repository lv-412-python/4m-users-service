"""Configuration for production."""
from users_service.config.base_config import Configuration

class ProdConfiguration(Configuration):
    """Production configuration."""
    SECRET_KEY = 'my_precious'
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'postgresql:///example'
