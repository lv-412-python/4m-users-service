export FN_BASE_URI=http://localhost:5230

export FLASK_APP=run.py
export APP_SETTINGS=users_service.config.dev_config.DevConfiguration

python -m flask run -p 5230
