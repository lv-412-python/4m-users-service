"""App entry point"""
import json
import os

import flask

import users_service.google_auth as google_auth

APP = flask.Flask(__name__)
APP.secret_key = os.environ.get("FN_FLASK_SECRET_KEY", default=False)

APP.register_blueprint(google_auth.APP)

@APP.route('/')
def index():
    """Show autentification state"""
    if google_auth.is_logged_in():
        user_info = google_auth.get_user_info()
        return '<div>You are currently logged in as ' + user_info['given_name'] + \
        '<div><pre>' + json.dumps(user_info, indent=4) + "</pre>"

    return 'You are not currently logged in.'
