"""Model for token blacklist."""
import datetime
from sqlalchemy import Column, Integer, String, DateTime
from users_service.db import DB

class BlacklistToken(DB.Model): #pylint: disable=too-few-public-methods
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    token_id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String(500), unique=True, nullable=False)
    blacklisted_on = Column(DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    @staticmethod
    def check_blacklist(auth_token):
        """check whether auth token has been blacklisted"""
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        return bool(res)
