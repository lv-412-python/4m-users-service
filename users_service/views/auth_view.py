"""Authentification view"""
import datetime
from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from sqlalchemy import exc
from users_service.db import DB
from users_service import BCRYPT
from users_service.models.users import User
from users_service.models.blacklist_token import BlacklistToken

AUTH_BLUEPRINT = Blueprint('auth', __name__)


class RegisterAPI(MethodView):
    """
    User Registration Resource
    """
    def post(self): #pylint: disable=no-self-use
        """Post method"""
        post_data = request.get_json()
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            try:
                user = User(
                    email=post_data.get('email'),
                    password=post_data.get('password'),
                    first_name=post_data.get('first_name'),
                    last_name=post_data.get('last_name')
                )
            except exc.SQLAlchemyError as error:
                response_object = {
                    'status': 'fail',
                    'message': str(error)
                }
                return make_response(jsonify(response_object)), 401
            DB.session.add(user)
            DB.session.commit()
            auth_token = user.encode_auth_token(user.user_id)
            response_object = {
                'status': 'success',
                'message': 'Successfully registered.',
                'auth_token': auth_token.decode()
            }
            return make_response(jsonify(response_object)), 201
        if user.google_id:
            user.password = post_data.get('password')
            user.update_date = datetime.datetime.now()
            DB.session.commit()
            auth_token = user.encode_auth_token(user.user_id)
            response_object = {
                'status': 'success',
                'message': 'Successfully updated.',
                'auth_token': auth_token.decode()
            }
            return make_response(jsonify(response_object)), 201
        response_object = {
            'status': 'fail',
            'message': 'User already exists. Please Log in.',
        }
        return make_response(jsonify(response_object)), 202


class LoginAPI(MethodView):
    """
    User Login Resource
    """
    def post(self): #pylint: disable=no-self-use
        """Post method"""
        post_data = request.get_json()
        try:
            user = User.query.filter_by(
                email=post_data.get('email')
            ).first()
        except exc.SQLAlchemyError as error:
            response_object = {
                'status': 'fail',
                'message': str(error)
            }
            return make_response(jsonify(response_object)), 500
        if user and BCRYPT.check_password_hash(
                user.password, post_data.get('password')
            ):
            auth_token = user.encode_auth_token(user.user_id)
            response_object = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'auth_token': auth_token.decode()
            }
            return make_response(jsonify(response_object)), 201
        response_object = {
            'status': 'fail',
            'message': 'User does not exist.'
        }
        return make_response(jsonify(response_object)), 404



class UserAPI(MethodView):
    """
    User Resource
    """
    def get(self): #pylint: disable=no-self-use
        """Get method"""
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                response_object = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(response_object)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(user_id=resp).first()
                response_object = {
                    'status': 'success',
                    'data': {
                        'user_id': user.user_id,
                        'email': user.email,
                        'admin': user.admin
                    }
                }
                return make_response(jsonify(response_object)), 200
            response_object = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(response_object)), 401
        response_object = {
            'status': 'fail',
            'message': 'Provide a valid auth token.'
        }
        return make_response(jsonify(response_object)), 401


class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    def post(self): #pylint: disable=no-self-use
        """Post method"""
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    DB.session.add(blacklist_token)
                    DB.session.commit()
                    response_object = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(response_object)), 200
                except exc.SQLAlchemyError as error:
                    response_object = {
                        'status': 'fail',
                        'message': str(error)
                    }
                    return make_response(jsonify(response_object)), 200
            else:
                response_object = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(response_object)), 401
        else:
            response_object = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(response_object)), 403

REGISTRATION_VIEW = RegisterAPI.as_view('register_api')
LOGIN_VIEW = LoginAPI.as_view('login_api')
USER_VIEW = UserAPI.as_view('user_api')
LOGOUT_VIEW = LogoutAPI.as_view('logout_api')

AUTH_BLUEPRINT.add_url_rule(
    '/auth/register',
    view_func=REGISTRATION_VIEW,
    methods=['POST']
)
AUTH_BLUEPRINT.add_url_rule(
    '/auth/login',
    view_func=LOGIN_VIEW,
    methods=['POST']
)
AUTH_BLUEPRINT.add_url_rule(
    '/auth/status',
    view_func=USER_VIEW,
    methods=['GET']
)
AUTH_BLUEPRINT.add_url_rule(
    '/auth/logout',
    view_func=LOGOUT_VIEW,
    methods=['POST']
)
