"""Authentication view"""
from flask import Blueprint, jsonify, make_response, request, session
from flask_restful import Resource
from jwt.exceptions import ExpiredSignatureError
from marshmallow import ValidationError
from sqlalchemy.exc import DataError, IntegrityError
from flask_api import status
from flask_jwt_extended import (
    create_access_token,
    decode_token
)
from users_service import API, APP, BCRYPT
from users_service.db import DB
from users_service.models.users import User
from users_service.serializers.user_schema import UserSchema

AUTH_BLUEPRINT = Blueprint('users', __name__)
USER_SCHEMA = UserSchema(strict=True)
USER_SCHEMA_NO_PASSWD = UserSchema(strict=True, exclude=['password'])
USERS_SCHEMA = UserSchema(strict=True, many=True, exclude=['password'])

AUTH_TOKEN_KEY = 'auth_token'
IS_ADMIN = 'admin'

class RegisterResource(Resource):
    """
    User Registration Resource.
    """
    def post(self):
        """Post method"""
        try:
            new_user = USER_SCHEMA.load(request.json).data
        except ValidationError as err:
            APP.logger.error(err.args)
            return jsonify(err.messages), status.HTTP_400_BAD_REQUEST
        user = User(
            email=new_user['email'],
            password=new_user['password'],
            first_name=new_user['first_name'],
            last_name=new_user['last_name'],
            role_id=1
        )
        DB.session.add(user)
        try:
            DB.session.commit()
        except IntegrityError as err:
            APP.logger.error(err.args)
            DB.session.rollback()
            response = {
                'error': 'Already exists.'
            }
            return response, status.HTTP_400_BAD_REQUEST
        session.permanent = True
        access_token = create_access_token(identity=user.email)
        session[AUTH_TOKEN_KEY] = access_token
        session[IS_ADMIN] = False
        response_obj = jsonify({
            'message': 'Successfully registered.'
        })
        return make_response(response_obj, status.HTTP_201_CREATED)


class LoginResource(Resource):
    """
    User Login Resource.
    """
    def post(self):
        """Post method"""
        try:
            user_data = USER_SCHEMA.load(request.json).data
        except ValidationError as err:
            APP.logger.error(err.args)
            return jsonify(err.messages), status.HTTP_400_BAD_REQUEST
        try:
            user = User.query.filter_by(
                email=user_data['email']
            ).first()
        except (KeyError, DataError) as err:
            APP.logger.error(err.args)
            response_obj = {
                'error': 'Invalid url.'
            }
            return response_obj, status.HTTP_404_NOT_FOUND
        if user:
            if BCRYPT.check_password_hash(
                    user.password, user_data['password']
            ):
                session.permanent = True
                access_token = create_access_token(identity=user.email)
                session[AUTH_TOKEN_KEY] = access_token
                session[IS_ADMIN] = bool(user.role_id == 2)
                response_obj = jsonify({
                    'message': 'Successfully logged in.'
                })
                return make_response(response_obj, status.HTTP_201_CREATED)
            response_obj = {
                'error': 'Wrong password.'
            }
            return response_obj, status.HTTP_400_BAD_REQUEST
        response_obj = {
            'error': 'No user with this email.'
        }
        return response_obj, status.HTTP_400_BAD_REQUEST


class StatusResource(Resource):
    """
    Status Resource.
    """
    def get(self):
        """Get method"""
        try:
            access_token = session[AUTH_TOKEN_KEY]
        except KeyError as err:
            APP.logger.error(err.args)
            response_obj = {
                'error': 'Provide a valid auth token.'
            }
            return response_obj, status.HTTP_401_UNAUTHORIZED
        try:
            user_info = decode_token(access_token)
            user_email = user_info['identity']
        except ExpiredSignatureError as err:
            APP.logger.error(err.args)
            response_obj = {
                'error': 'Signature expired. Please, log in again.'
            }
            return response_obj, status.HTTP_401_UNAUTHORIZED
        user = User.query.filter_by(email=user_email).first()
        response_obj = USER_SCHEMA_NO_PASSWD.dump(user).data
        return make_response(jsonify(response_obj), status.HTTP_200_OK)


class LogoutResource(Resource):
    """
    Logout Resource
    """
    def post(self):
        """Post method"""
        session.clear()
        response_obj = jsonify({
            'message': 'Successfully logged out.'
        })
        return make_response(response_obj, status.HTTP_200_OK)

class UsersResource(Resource):
    """
    Users Resource.
    """
    def get(self):
        """Get method"""
        users = User.query.all()
        response_obj = USERS_SCHEMA.dump(users).data
        return make_response(jsonify(response_obj), status.HTTP_200_OK)


API.add_resource(UsersResource, '/users')
API.add_resource(RegisterResource, '/users/register')
API.add_resource(LoginResource, '/users/login')
API.add_resource(StatusResource, '/users/status')
API.add_resource(LogoutResource, '/users/logout')
