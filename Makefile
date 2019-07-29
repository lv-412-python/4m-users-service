.PHONY: help install lint run-dev run-prod run-test
PYTHON_PATH_ANSWERS_SERVICE := users-service-repo
.DEFAULT: help
help:
	@echo "make install"
	@echo "       installs requirements"
	@echo "make run-dev"
	@echo "       run project in dev mode"
	@echo "make run-prod"
	@echo "       run project in production mode"
	@echo "make run-test"
	@echo "       run project in testing mode"
	@echo "make lint"
	@echo "       run pylint"

install:
	 pip3 install -r requirements.txt;

run-dev:
	 export PYTHONPATH=$(PYTHON_PATH_USERS_SERVICE);\
	 export FLASK_ENV="development"; \
	 export FLASK_APP="setup.py"; \
	 python3 -m flask run -p 5050;


run-prod:
	 export PYTHONPATH=$(PYTHON_PATH_USERS_SERVICE); \
	 export FLASK_ENV="production"; \
	 export FLASK_APP="setup.py"; \
	 python3 -m flask run -p 5050;


run-test:
	 export PYTHONPATH=$(PYTHON_PATH_USERS_SERVICE); \
	 export FLASK_ENV="testing"; \
	 export FLASK_APP="setup.py"; \
	 python3 -m flask run -p 5050;

lint:
	 pylint setup.py users_service/
