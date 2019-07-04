"""Test user model"""
import unittest

from users_service.db import DB
from users_service.models.users import User
from users_service.tests.base import BaseTestCase


class TestUserModel(BaseTestCase):
    """Test user model"""
    def test_encode_auth_token(self):
        """test encoding token"""
        user = User(
            email='test@test.com',
            password='test',
            first_name='test',
            last_name='test'
        )
        DB.session.add(user)
        DB.session.commit()
        auth_token = user.encode_auth_token(user.user_id)
        self.assertTrue(isinstance(auth_token, bytes))

    def test_decode_auth_token(self):
        """test decoding token"""
        user = User(
            email='test@test.com',
            password='test',
            first_name='test',
            last_name='test'
        )
        DB.session.add(user)
        DB.session.commit()
        auth_token = user.encode_auth_token(user.user_id)
        self.assertTrue(isinstance(auth_token, bytes))

        self.assertTrue(User.decode_auth_token(
            auth_token.decode("utf-8")) == 1)


if __name__ == '__main__':
    unittest.main()
