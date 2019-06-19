"""Google Autentification"""
import functools
import os

from flask import Blueprint, jsonify, make_response, redirect, request, session
from flask_restful import Resource
from marshmallow import ValidationError
from sqlalchemy.exc import DataError, IntegrityError
from flask_api import status
from users_service import API
from users_service import BCRYPT
from users_service.db import DB
from users_service.models.users import User
from users_service.serializers.user_schema import UserSchema

from authlib.client import OAuth2Session
import google.oauth2.credentials
import googleapiclient.discovery

ACCESS_TOKEN_URI = 'https://www.googleapis.com/oauth2/v4/token'
AUTHORIZATION_URL = 'https://accounts.google.com/o/oauth2/v2/auth' + \
    '?access_type=offline&prompt=consent'

AUTHORIZATION_SCOPE = 'openid email profile'

AUTH_REDIRECT_URI = os.environ.get("FN_AUTH_REDIRECT_URI", default=False)
BASE_URI = os.environ.get("FN_BASE_URI", default=False)
CLIENT_ID = os.environ.get("FN_CLIENT_ID", default=False)
CLIENT_SECRET = os.environ.get("FN_CLIENT_SECRET", default=False)

AUTH_TOKEN_KEY = 'auth_token'
AUTH_STATE_KEY = 'auth_state'

GOOGLE_AUTH_BLUEPRINT = Blueprint('google_auth', __name__)
USER_SCHEMA = UserSchema(strict=True)

class GRegisterResource(Resource):
    """docstring for ."""

    def post(self):
        """Post method."""


class GLoginResource(Resource):
    """docstring for ."""

    def post(self):
        """Post method."""
        session_g = OAuth2Session(CLIENT_ID, CLIENT_SECRET,
                                scope=AUTHORIZATION_SCOPE,
                                redirect_uri=AUTH_REDIRECT_URI)

        uri, state = session_g.authorization_url(AUTHORIZATION_URL)

        session[AUTH_STATE_KEY] = state
        session.permanent = True

        return redirect(uri, status.HTTP_302_FOUND)


class GUserResource(Resource):
    """docstring for ."""

    def get(self):
        """Post method."""


class GLogoutResource(Resource):
    """docstring for ."""

    def post(self):
        """Post method."""
        session.pop(AUTH_TOKEN_KEY, None)
        session.pop(AUTH_STATE_KEY, None)
        response_obj = jsonify({
            'message': 'Successfully logged out.'
        })
        return make_response(response_obj, status.HTTP_200_OK)


API.add_resource(GRegisterResource, '/google_auth/register')
API.add_resource(GLoginResource, '/google_auth/login')
API.add_resource(GUserResource, '/google_auth/status')
API.add_resource(GLogoutResource, '/google_auth/logout')

def is_logged_in():
    """Check user is logged in"""
    return bool(AUTH_TOKEN_KEY in flask.session)

def build_credentials():
    """Build credentials"""
    if not is_logged_in():
        raise Exception('User must be logged in')

    oauth2_tokens = session[AUTH_TOKEN_KEY]

    return google.oauth2.credentials.Credentials(
                oauth2_tokens['access_token'],
                refresh_token=oauth2_tokens['refresh_token'],
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                token_uri=ACCESS_TOKEN_URI)

def get_user_info():
    """Get dict with user info"""
    credentials = build_credentials()

    oauth2_client = googleapiclient.discovery.build(
        'oauth2', 'v2',
        credentials=credentials)

    return oauth2_client.userinfo().get().execute() #pylint: disable=no-member

def no_cache(view):
    """Implement no-caching of logger data"""
    @functools.wraps(view)
    def no_cache_impl(*args, **kwargs):
        response = flask.make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response

    return functools.update_wrapper(no_cache_impl, view)

@APP.route('/google/login')
@no_cache
def login():
    """Login view"""
    session = OAuth2Session(CLIENT_ID, CLIENT_SECRET,
                            scope=AUTHORIZATION_SCOPE,
                            redirect_uri=AUTH_REDIRECT_URI)

    uri, state = session.authorization_url(AUTHORIZATION_URL)

    flask.session[AUTH_STATE_KEY] = state
    flask.session.permanent = True

    return flask.redirect(uri, status.HTTP_302_FOUND)

@APP.route('/google/auth')
@no_cache
def google_auth_redirect():
    """This mitigates Cross-Site Request Forgery (CSRF) attacks"""
    req_state = flask.request.args.get('state', default=None, type=None)

    if req_state != flask.session[AUTH_STATE_KEY]:
        response = flask.make_response('Invalid state parameter', 401)
        return response

    session = OAuth2Session(CLIENT_ID, CLIENT_SECRET,
                            scope=AUTHORIZATION_SCOPE,
                            state=flask.session[AUTH_STATE_KEY],
                            redirect_uri=AUTH_REDIRECT_URI)

    oauth2_tokens = session.fetch_access_token(
        ACCESS_TOKEN_URI,
        authorization_response=flask.request.url)

    flask.session[AUTH_TOKEN_KEY] = oauth2_tokens

    return flask.redirect(BASE_URI, code=302)

@APP.route('/google/logout')
@no_cache
def logout():
    """Logout view"""
    flask.session.pop(AUTH_TOKEN_KEY, None)
    flask.session.pop(AUTH_STATE_KEY, None)

    return flask.redirect(BASE_URI, code=302)
