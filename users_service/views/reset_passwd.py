"""Reset password view"""
import datetime
from flask import Blueprint, request
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from flask_api import status
from flask_mail import Message
from users_service import API, APP, BCRYPT, MAIL
from users_service.db import DB
from users_service.models.users import User

RESET_PASSWD_BLUEPRINT = Blueprint('reset_password', __name__)

def send_reset_email(user):
    """Send email with reset password token."""
    token = user.get_reset_token()
    message = Message('Password Reset Request',
                      sender='noreply@4m.com',
                      recipients=[user.email])
    url_to = 'http://127.0.0.1:3000/set_new_password?token={}'.format(token)
    message.body = f'''To reset your password visit the following link:
{url_to}

If you did not make this request just ignore this email and no changes will be done.
'''
    MAIL.send(message)

class ResetPasswordResource(Resource):
    """
    Reset password Resource.
    """
    def post(self):
        """Post method"""
        curr_session = request.cookies.get('session')
        if curr_session:
            response_obj = {
                'error': 'Already signed in.'
            }
            return response_obj, status.HTTP_400_BAD_REQUEST

        user_email = request.json.get("email")
        user = User.query.filter_by(email=user_email).first()
        if not user:
            response_obj = {
                'error': 'No user with this email.'
            }
            return response_obj, status.HTTP_400_BAD_REQUEST
        send_reset_email(user)
        response_obj = {
            'message': 'Email with reset link has been sent.'
        }
        return response_obj, status.HTTP_200_OK

    def put(self):
        """Put method"""
        curr_session = request.cookies.get('session')
        if curr_session:
            response_obj = {
                'error': 'Already signed in.'
            }
            return response_obj, status.HTTP_400_BAD_REQUEST
        token = request.args.get('token')
        user = User.verify_reset_token(token)
        password = request.json.get('password')
        if not user:
            response_obj = {
                'error': 'Invalid or expired token.'
            }
            return response_obj, status.HTTP_400_BAD_REQUEST
        user.password = BCRYPT.generate_password_hash(
            password, APP.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        user.update_date = datetime.datetime.now()
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


API.add_resource(ResetPasswordResource, '/reset_password')
