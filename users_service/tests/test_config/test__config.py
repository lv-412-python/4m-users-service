"""Test configs"""
import unittest

from flask import current_app
from flask_testing import TestCase

from users_service import APP

POSTGRES_DATABASE_NAME = 'postgresql://postgres:admin@localhost:5432/4m_users_db'

class TestDevelopmentConfig(TestCase):
    """Test development configuration"""
    def create_app(self): #pylint: disable=no-self-use
        """create app with development configuration"""
        APP.config.from_object('users_service.config.dev_config.DevConfiguration')
        return APP

    def test_app_is_development(self):
        """test app has development configuration"""
        self.assertTrue(APP.config['DEBUG'] is True)
        self.assertFalse(current_app is None)
        self.assertTrue(
            APP.config['SQLALCHEMY_DATABASE_URI'] == '{}'.format(POSTGRES_DATABASE_NAME)
        )


class TestTestingConfig(TestCase):
    """Test testing configuration"""
    def create_app(self): #pylint: disable=no-self-use
        """create app with testing configuration"""
        APP.config.from_object('users_service.config.test_config.TestConfiguration')
        return APP

    def test_app_is_testing(self):
        """test app has testing configuration"""
        self.assertTrue(APP.config['DEBUG'])
        self.assertTrue(
            APP.config['SQLALCHEMY_DATABASE_URI'] == '{}_test'.format(POSTGRES_DATABASE_NAME)
        )

class TestProductionConfig(TestCase):
    """Test production configuration"""
    def create_app(self): #pylint: disable=no-self-use
        """create app with production configuration"""
        APP.config.from_object('users_service.config.prod_config.ProdConfiguration')
        return APP

    def test_app_is_production(self):
        """test app has production configuration"""
        self.assertTrue(APP.config['DEBUG'] is False)


if __name__ == '__main__':
    unittest.main()
