"""Configuration for testing."""
from users_service.config.base_config import Configuration

POSTGRES_LOCAL_BASE = 'postgresql://postgres:postgres@localhost:5432/'
DATABASE_NAME = '4m_users_db'

class TestConfiguration(Configuration):
    """Testing configuration."""
    DEBUG = True
    TESTING = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = '{}{}_test'.format(POSTGRES_LOCAL_BASE, DATABASE_NAME)
    PRESERVE_CONTEXT_ON_EXCEPTION = False
