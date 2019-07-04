"""Base test case"""
from flask_testing import TestCase

from users_service.db import APP, DB


class BaseTestCase(TestCase):
    """ Base Tests """

    def create_app(self): #pylint: disable=no-self-use
        """Create app and configure"""
        APP.config.from_object('users_service.config.test_config.TestConfiguration')
        return APP

    def setUp(self): #pylint: disable=no-self-use
        """Create tables"""
        DB.create_all()
        DB.session.commit()

    def tearDown(self): #pylint: disable=no-self-use
        """Drop tables"""
        DB.session.remove()
        DB.drop_all()
