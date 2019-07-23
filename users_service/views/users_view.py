"""Users view"""
from flask import Blueprint, jsonify, make_response
from flask_restful import Resource
from marshmallow import ValidationError
from flask_api import status
from users_service import API, APP
from users_service.models.users import User
from users_service.serializers.user_schema import UserSchema

USERS_BLUEPRINT = Blueprint('user', __name__)
USER_SCHEMA = UserSchema(strict=True)
USERS_SCHEMA = UserSchema(strict=True, many=True)

AUTH_TOKEN_KEY = 'auth_token'

class UsersResource(Resource):
    """
    Users Resource.
    """
    def get(self):
        """Get method"""
        try:
            users = User.query.all()
            response_obj = USERS_SCHEMA.dump(users).data
            return make_response(jsonify(response_obj), status.HTTP_200_OK)
        except ValidationError as err:
            APP.logger.error(err.args)
            return jsonify(err.messages), status.HTTP_400_BAD_REQUEST

API.add_resource(UsersResource, '/user')
