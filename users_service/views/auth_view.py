"""Authentication view"""
from flask import Blueprint, jsonify, make_response, request, session
from flask_restful import HTTPException, Resource
from marshmallow import fields, ValidationError
from sqlalchemy.exc import DataError, IntegrityError
from flask_api import status
from flask_jwt_extended import create_access_token, decode_token
from webargs.flaskparser import parser
from users_service import API, APP, BCRYPT
from users_service.db import DB
from users_service.models.users import User
from users_service.serializers.user_schema import UserSchema

AUTH_BLUEPRINT = Blueprint('users', __name__)
USER_SCHEMA = UserSchema(strict=True)
USER_SCHEMA_NO_PASSWD = UserSchema(strict=True, exclude=['password'])
USERS_SCHEMA = UserSchema(strict=True, many=True, exclude=['password'])

AUTH_TOKEN_KEY = 'auth_token'

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
        try:
            user = User(
                email=new_user['email'],
                password=new_user['password'],
                first_name=new_user['first_name'],
                last_name=new_user['last_name'],
                role_id=1
            )
        except KeyError:
            user = User(
                email=new_user['email'],
                google_id=new_user['google_id'],
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
        access_token = create_access_token(identity=user.user_id, expires_delta=False)
        session[AUTH_TOKEN_KEY] = access_token

        response_obj = jsonify({
            'message': 'Successfully registered.'
        })
        response_obj.set_cookie("admin", str(False))
        return make_response(response_obj, status.HTTP_200_OK)


class LoginResource(Resource):
    """
    User Login Resource.
    """
    def post(self):
        """Post method"""
        try:
            user_data = USER_SCHEMA.load(request.json).data
        except ValidationError as err:
            APP.logger.exception(err.args)
            return jsonify(err.messages), status.HTTP_400_BAD_REQUEST
        try:
            user = User.query.filter_by(
                email=user_data['email']
            ).first()
        except (KeyError, DataError) as err:
            APP.logger.exception(err.args)
            response_obj = {
                'error': 'Invalid url.'
            }
            return response_obj, status.HTTP_404_NOT_FOUND
        if user:
            try:
                check_user = BCRYPT.check_password_hash(
                    user.password, user_data['password']
                )
            except KeyError:
                check_user = user.google_id
            if check_user:
                session.permanent = True
                access_token = create_access_token(identity=user.user_id, expires_delta=False)
                session[AUTH_TOKEN_KEY] = access_token
                response_obj = jsonify({
                    'message': 'Successfully logged in.'
                })
                response_obj.set_cookie("admin", str(bool(user.role_id == 2)))
                return make_response(response_obj, status.HTTP_200_OK)
            response_obj = {
                'error': 'Wrong password.'
            }
            return response_obj, status.HTTP_400_BAD_REQUEST
        response_obj = {
            'error': 'No user with this email.'
        }
        return response_obj, status.HTTP_400_BAD_REQUEST


class ProfileResource(Resource):
    """
    Profile Resource.
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
        user_info = decode_token(access_token)
        user_id = user_info['identity']
        user = User.query.get(user_id)
        response_obj = USER_SCHEMA_NO_PASSWD.dump(user).data
        return make_response(jsonify(response_obj), status.HTTP_200_OK)

    def put(self):
        """Put method"""
        try:
            access_token = session[AUTH_TOKEN_KEY]
        except KeyError as err:
            APP.logger.error(err.args)
            response_obj = {
                'error': 'Provide a valid auth token.'
            }
            return response_obj, status.HTTP_401_UNAUTHORIZED
        user_info = decode_token(access_token)
        user_id = user_info['identity']
        user = User.query.get(user_id)
        if user.google_id:
            password = request.json.get('password')
            user.password = BCRYPT.generate_password_hash(
                password, APP.config.get('BCRYPT_LOG_ROUNDS')
            ).decode()
        else:
            user.google_id = request.json.get('google_id')
        try:
            DB.session.commit()
        except IntegrityError as err:
            APP.logger.error(err.args)
            DB.session.rollback()
            response = {
                'error': 'Database error.'
            }
            return response, status.HTTP_400_BAD_REQUEST
        response_obj = {
            'message': 'Successfully updated.'
        }
        return response_obj, status.HTTP_200_OK



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
        response_obj.delete_cookie('admin')
        return make_response(response_obj, status.HTTP_200_OK)


class UsersResource(Resource):
    """
    Users Resource.
    """
    def get(self):
        """Get method"""
        admin = request.cookies.get('admin')
        if admin:
            url_args = {
                'user_id': fields.List(fields.Int(validate=lambda val: val > 0)),
                'email': fields.String(),
                'first_name': fields.String(),
                'last_name': fields.String(),
                'from_date': fields.Date(),
                'end_date': fields.Date()
            }
            try:
                args = parser.parse(url_args, request)
            except HTTPException:
                APP.logger.error('%s not correct URL', request.url)
                return {"error": "Invalid URL."}, status.HTTP_400_BAD_REQUEST
            users = User.query.filter().order_by(User.user_id)

            if 'user_id' in args:
                users = users.filter(User.user_id.in_(args['user_id']))
            if 'from_date' in args:
                users = users.filter(User.create_date >= args['from_date'])
            if 'end_date' in args:
                users = users.filter(User.create_date <= args['end_date'])
            if 'first_name' in args:
                users = users.filter(User.first_name.like('%' + args['first_name'] + '%'))
            if 'last_name' in args:
                users = users.filter(User.last_name.like('%' + args['last_name'] + '%'))
            if 'email' in args:
                users = users.filter(User.email.like('%' + args['email'] + '%'))
            response_obj = USERS_SCHEMA.dump(users).data
            if not response_obj:
                response_obj = {
                    'error': 'No user fitting criteria.'
                }
            return response_obj, status.HTTP_200_OK
        response_obj = {
            'error': 'Not allowed.'
        }
        return response_obj, status.HTTP_403_FORBIDDEN


    def put(self):
        """Put method"""
        admin = request.cookies.get('admin')
        if admin:
            user_email = request.json.get("email")
            print(user_email)
            user = User.query.filter_by(email=user_email).first()
            if user:
                user.role_id = 2
                try:
                    DB.session.commit()
                except IntegrityError as err:
                    APP.logger.error(err.args)
                    DB.session.rollback()
                    response = {
                        'error': 'Database error.'
                    }
                    return response, status.HTTP_400_BAD_REQUEST
                response_obj = {
                    'message': 'Successfully updated.'
                }
                return response_obj, status.HTTP_200_OK
            response_obj = {
                'error': 'No user with this email.'
            }
            return response_obj, status.HTTP_400_BAD_REQUEST
        response_obj = {
            'error': 'Not allowed.'
        }
        return response_obj, status.HTTP_403_FORBIDDEN


class GetIdResource(Resource):
    """
    Get user id Resource.
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
        user_info = decode_token(access_token)
        user_id = user_info['identity']
        response_obj = {
            'id': user_id
        }
        return make_response(jsonify(response_obj), status.HTTP_200_OK)

API.add_resource(UsersResource, '/users')
API.add_resource(RegisterResource, '/users/register')
API.add_resource(LoginResource, '/users/login')
API.add_resource(ProfileResource, '/users/profile')
API.add_resource(LogoutResource, '/users/logout')
API.add_resource(GetIdResource, '/users/id')
