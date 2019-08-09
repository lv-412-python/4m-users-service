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
from flask_api import status
from users_service import API
from users_service.models.users import User
from users_service.serializers.user_schema import UserSchema

USER_SCHEMA = UserSchema(strict=True, exclude=['password', 'role_id', 'user_id',
                                               'create_date', 'update_date'])

G_BLUEPRINT = Blueprint('g', __name__)

AUTH_TOKEN_KEY = 'auth_token'

REDIRECT_URL = 'http://127.0.0.1/g/redir'


class GLoginResource(Resource):
    """
    User Login Resource.
    """
    def get(self):
        """Get method"""
        token_request_uri = "https://accounts.google.com/o/oauth2/auth"
        response_type = "code"
        client_id = "736262570105-js691v4obo9k4nad2mftejcfq6lbhnse.apps.googleusercontent.com"
        redirect_uri = REDIRECT_URL
        scope = "profile+email"
        url = "{token_request_uri}?response_type={response_type}&" \
            "client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}".format(
                token_request_uri=token_request_uri,
                response_type=response_type,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope)
        response_obj = make_response(jsonify({'url':url}))
        if request.args.get('method') == 'login':
            url_to = "http://127.0.0.1/users/login"
        elif request.args.get('method') == 'expand':
            url_to = "http://127.0.0.1/users/profile"
        else:
            url_to = "http://127.0.0.1/users/register"
        response_obj.set_cookie("url_to", url_to)
        return response_obj


class GRedirResource(Resource):
    """
    User Login Resource.
    """
    def get(self):
        """Get method"""
        http_parser = Http()
        if request.cookies.get('url_to') == 'http://127.0.0.1/users/login':
            login_failed_url = 'http://127.0.0.1:3000/login'
        elif request.cookies.get('url_to') == 'http://127.0.0.1/users/profile':
            login_failed_url = 'http://127.0.0.1:3000/profile'
        else:
            login_failed_url = 'http://127.0.0.1:3000/register'
        if request.args.get('error') or not request.args.get('code'):
            response_obj = {
                'error': 'Failed google authentication.'
            }
            return response_obj, status.HTTP_401_UNAUTHORIZED

        redirect_to = request.cookies.get('url_to')


        access_token_uri = 'https://accounts.google.com/o/oauth2/token'
        redirect_uri = REDIRECT_URL

        params = urllib.parse.urlencode({
            'code':request.args['code'],
            'redirect_uri':redirect_uri,
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
        if redirect_to == 'http://127.0.0.1/users/login' \
            or 'http://127.0.0.1/users/register':
            resp = requests.post(
                url=redirect_to,
                json=response_obj
            )
        else:
            resp = requests.put(
                url=redirect_to,
                json=response_obj
            )
        if resp.status_code != 200:
            return redirect(login_failed_url)
        cookies_to_set = resp.cookies.get_dict()
        response_obj = make_response(redirect('http://127.0.0.1:3000/'))
        response_obj.delete_cookie('url_to')
        response_obj.set_cookie("session", cookies_to_set['session'])
        response_obj.set_cookie("admin", cookies_to_set['admin'])
        return response_obj

API.add_resource(GLoginResource, '/g/login')
API.add_resource(GRedirResource, '/g/redir')
