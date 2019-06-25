#pylint: disable=cyclic-import
"""Init users service"""
from flask import Flask
from flask_restful import Api
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow


APP = Flask(__name__)

API = Api(APP)

MA = Marshmallow(APP)
BCRYPT = Bcrypt(APP)

from users_service.views.auth_view import AUTH_BLUEPRINT # pylint: disable=wrong-import-position
APP.register_blueprint(AUTH_BLUEPRINT)
