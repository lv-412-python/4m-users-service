"""Authentification view"""
from flask import Blueprint, jsonify, make_response, request
from flask_restful import Resource
from jwt.exceptions import ExpiredSignatureError
from marshmallow import ValidationError
from sqlalchemy.exc import DataError, IntegrityError
from flask_api import status
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    jwt_optional,
    set_access_cookies,
    unset_jwt_cookies
)
from users_service import API
from users_service import BCRYPT
from users_service.db import DB
from users_service.models.users import User
from users_service.serializers.user_schema import UserSchema

AUTH_BLUEPRINT = Blueprint('auth', __name__)
USER_SCHEMA = UserSchema(strict=True)

class RegisterResource(Resource):
    """
    User Registration Resource.
    """
    def post(self):
        """Post method"""
        try:
            new_user = USER_SCHEMA.load(request.json).data
        except ValidationError as error:
            return jsonify(error.messages), status.HTTP_400_BAD_REQUEST
        user = User(
            email=new_user['email'],
            password=new_user['password'],
            first_name=new_user['first_name'],
            last_name=new_user['last_name']
        )
        DB.session.add(user)
        try:
            DB.session.commit()
        except IntegrityError:
            DB.session.rollback()
            response = {
                'error': 'Already exists.'
            }
            return response, status.HTTP_400_BAD_REQUEST
        access_token = create_access_token(identity=user.email)
        response_obj = jsonify({
            'message': 'Successfully registered.'
        })
        set_access_cookies(response_obj, access_token)
        return make_response(response_obj, status.HTTP_201_CREATED)


class LoginResource(Resource):
    """
    User Login Resource.
    """
    def post(self):
        """Post method"""
        try:
            user_data = USER_SCHEMA.load(request.json).data
        except ValidationError as error:
            return jsonify(error.messages), status.HTTP_400_BAD_REQUEST
        try:
            user = User.query.filter_by(
                email=user_data['email']
            ).first()
        except DataError:
            response_obj = {
                'error': 'Invalid url.'
            }
            return response_obj, status.HTTP_404_NOT_FOUND
        if BCRYPT.check_password_hash(
                user.password, user_data['password']
            ):
            access_token = create_access_token(identity=user.email)
            response_obj = jsonify({
                'message': 'Successfully logged in.'
            })
            set_access_cookies(response_obj, access_token)
            return make_response(response_obj, status.HTTP_201_CREATED)
        response_obj = {
            'error': 'Wrong password.'
        }
        return response_obj, status.HTTP_400_BAD_REQUEST


class UserResource(Resource):
    """
    User Resource.
    """
    @jwt_optional
    def get(self):
        """Get method"""
        try:
            user_email = get_jwt_identity()
        except ExpiredSignatureError:
            response_obj = {
                'error': 'Signature expired. Please, log in again.'
            }
            return response_obj, status.HTTP_401_UNAUTHORIZED
        if user_email:
            user = User.query.filter_by(email=user_email).first()
            response_obj = USER_SCHEMA.dump(user).data
            del response_obj['password']
            return make_response(jsonify(response_obj), status.HTTP_200_OK)
        response_obj = {
            'error': 'Provide a valid auth token.'
        }
        return response_obj, status.HTTP_401_UNAUTHORIZED


class LogoutResource(Resource):
    """
    Logout Resource
    """
    def post(self):
        """Post method"""
        response_obj = jsonify({
            'message': 'Successfully logged out.'
        })
        unset_jwt_cookies(response_obj)
        return make_response(response_obj, status.HTTP_200_OK)


API.add_resource(RegisterResource, '/auth/register')
API.add_resource(LoginResource, '/auth/login')
API.add_resource(UserResource, '/auth/status')
API.add_resource(LogoutResource, '/auth/logout')
