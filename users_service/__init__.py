#pylint: disable=cyclic-import
"""Init users service"""
import unittest
import coverage
from flask import Flask
from flask_restful import Api
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_mail import Mail

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
CORS(APP, supports_credentials=True)

API = Api(APP)
JWT = JWTManager(APP)

MA = Marshmallow(APP)
BCRYPT = Bcrypt(APP)

APP.config['MAIL_SERVER'] = 'smtp.gmail.com'
APP.config['MAIL_PORT'] = 465
APP.config['MAIL_USE_SSL'] = True
APP.config['MAIL_USERNAME'] = '4m.users.service@gmail.com'
APP.config['MAIL_PASSWORD'] = "qwe123rty456"

MAIL = Mail(APP)

from users_service.views.auth_view import AUTH_BLUEPRINT # pylint: disable=wrong-import-position
APP.register_blueprint(AUTH_BLUEPRINT)
from users_service.views.google_auth import G_BLUEPRINT # pylint: disable=wrong-import-position
APP.register_blueprint(G_BLUEPRINT)
from users_service.views.reset_passwd import RESET_PASSWD_BLUEPRINT # pylint: disable=wrong-import-position
APP.register_blueprint(RESET_PASSWD_BLUEPRINT)
