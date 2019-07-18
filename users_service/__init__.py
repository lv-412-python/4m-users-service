#pylint: disable=cyclic-import
"""Init users service"""
import unittest
import coverage
from flask import Flask
from flask_restful import Api
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager

COV = coverage.coverage(
    branch=True,
    include='users_service/*',
    omit=[
        'users_service/tests/*',
        'users_service/config/*',
        'users_service/*/__init__.py'
    ]
)
COV.start()

APP = Flask(__name__)
APP.secret_key = 'very_secret'
API = Api(APP)
JWT = JWTManager(APP)
MA = Marshmallow(APP)
BCRYPT = Bcrypt(APP)

from users_service.views.auth_view import AUTH_BLUEPRINT # pylint: disable=wrong-import-position
APP.register_blueprint(AUTH_BLUEPRINT)
