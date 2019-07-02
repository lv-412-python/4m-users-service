set FN_BASE_URI=http://localhost:5230/auth/status

set FLASK_APP=setup.py
set APP_SETTINGS=users_service.config.dev_config.DevConfiguration

python -m flask run -p 5230
