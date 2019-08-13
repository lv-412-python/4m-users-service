"""Google authentication view"""
import json
import urllib.parse
import requests
from flask import (
    Blueprint,
    jsonify,
    make_response,
    redirect,
    request
)
from flask_restful import Resource
from httplib2 import Http
from flask_jwt_extended import create_access_token, decode_token
from users_service import API
from users_service.models.users import User
from users_service.serializers.user_schema import UserSchema

USER_SCHEMA = UserSchema(strict=True, exclude=['password', 'role_id', 'user_id',
                                               'create_date', 'update_date'])

G_BLUEPRINT = Blueprint('g', __name__)

AUTH_TOKEN_KEY = 'auth_token'

REDIRECT_URL = 'http://127.0.0.1/g/redir'
REDIRECT_LOGIN = 'http://127.0.0.1/users/login'
REDIRECT_REGISTER = 'http://127.0.0.1/users/register'
REDIRECT_PROFILE = 'http://127.0.0.1/users/profile'


class GLoginResource(Resource):
    """
    User Login Resource.
    """
    def get(self):
        """Get method"""
        token_request_uri = "https://accounts.google.com/o/oauth2/auth"
        response_type = "code"
        client_id = "736262570105-js691v4obo9k4nad2mftejcfq6lbhnse.apps.googleusercontent.com"
        scope = "profile+email"
        url = "{token_request_uri}?response_type={response_type}&" \
            "client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}".format(
                token_request_uri=token_request_uri,
                response_type=response_type,
                client_id=client_id,
                redirect_uri=REDIRECT_URL,
                scope=scope)
        response_obj = make_response(jsonify({'url':url}))
        if request.args.get('method') == 'login':
            url_to = REDIRECT_LOGIN
        elif request.args.get('method') == 'expand':
            url_to = REDIRECT_PROFILE
            email = create_access_token(request.args.get('email'))
            response_obj.set_cookie('email', email)
        else:
            url_to = REDIRECT_REGISTER
        response_obj.set_cookie("url_to", url_to)
        return response_obj


class GRedirResource(Resource):
    """
    User Login Resource.
    """
    def get(self):
        """Get method"""
        http_parser = Http()
        if request.cookies.get('url_to') == REDIRECT_LOGIN:
            login_failed_url = 'http://127.0.0.1:3000/signin'
        elif request.cookies.get('url_to') == REDIRECT_PROFILE:
            login_failed_url = 'http://127.0.0.1:3000/profile'
        else:
            login_failed_url = 'http://127.0.0.1:3000/registration'
        if request.args.get('error') or not request.args.get('code'):
            response_obj = redirect(login_failed_url)
            response_obj = make_response(response_obj)
            response_obj.set_cookie('error', 'Failed google authentication.')
            return response_obj

        redirect_to = request.cookies.get('url_to')


        access_token_uri = 'https://accounts.google.com/o/oauth2/token'

        params = urllib.parse.urlencode({
            'code':request.args['code'],
            'redirect_uri':REDIRECT_URL,
            'client_id':'736262570105-js691v4obo9k4nad2mftejcfq6lbhnse.apps.googleusercontent.com',
            'client_secret':'rXhproETgZ59M43quk2aOKcm',
            'grant_type':'authorization_code'
        })
        headers = {'content-type':'application/x-www-form-urlencoded'}
        content = http_parser.request(
            access_token_uri,
            method='POST',
            body=params,
            headers=headers
        )[1]
        token_data = json.loads(content)
        content = http_parser.request("https://www.googleapis.com/oauth2/v1/" \
            "userinfo?access_token={accessToken}" \
            .format(accessToken=token_data['access_token']))[1]
        google_profile = json.loads(content)
        user = User(
            email=google_profile["email"],
            first_name=google_profile["given_name"],
            last_name=google_profile["family_name"],
            role_id=1,
            google_id=google_profile["id"]
        )
        response_obj = USER_SCHEMA.dump(user).data
        if redirect_to in (REDIRECT_LOGIN, REDIRECT_REGISTER):
            resp = requests.post(
                url=redirect_to,
                json=response_obj
            )
            if resp.status_code != 200:
                response_obj = make_response(redirect(login_failed_url))
                response_obj.set_cookie("error", "Error happened. Try again")
                return response_obj
            cookies_to_set = resp.cookies.get_dict()
            response_obj = make_response(redirect('http://127.0.0.1:3000/'))
            response_obj.set_cookie("session", cookies_to_set['session'])
            response_obj.set_cookie("admin", cookies_to_set['admin'])
        else:
            encoded_email = request.cookies.get('email')
            email = decode_token(encoded_email)['identity']
            if email != google_profile["email"]:
                response_obj = redirect(login_failed_url)
                response_obj = make_response(response_obj)
                response_obj.set_cookie('error', 'Expected same email.')
                return response_obj
            resp = requests.put(
                url=redirect_to,
                json=response_obj,
                cookies={'session' :request.cookies.get('session')}
            )
            if resp.status_code != 200:
                response_obj = make_response(redirect(login_failed_url))
                response_obj.set_cookie("error", "Error happened. Try again")
                return response_obj
            response_obj = make_response(redirect('http://127.0.0.1:3000/profile'))
            response_obj.delete_cookie('email')
        return response_obj

API.add_resource(GLoginResource, '/g/login')
API.add_resource(GRedirResource, '/g/redir')
