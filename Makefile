.PHONY: help install clear lint dev-env prod-env test-env
PYTHON_PATH_ANSWERS_SERVICE := /home/lev/project/4m/4m-users-service/users_service
.DEFAULT: help
help:
	@echo "make install"
	@echo "       creates venv and installs requirements"
	@echo "make dev-env"
	@echo "       run project in dev mode"
	@echo "make prod-env"
	@echo "       run project in production mode"
	@echo "make test-env"
	@echo "       run project in testing mode"
	@echo "make lint"
	@echo "       run pylint"
	@echo "make clear"
	@echo "       deletes venv and .pyc files"

install:
	python3 -m venv venv
	~/projects/4m-users-service/venv/bin/activate; \
	pip install setuptools --upgrade --ignore-installed --user
	pip install pip --upgrade --ignore-installed --user
	pip install -r requirements.txt --user;

clear:
	rm -rf venv
	find -iname "*.pyc" -delete

dev-env:
	 make install; \
	 export PYTHONPATH=$(PYTHON_PATH_USERS_SERVICE);\
	 export FLASK_APP="setup.py"; \
	 export FLASK_ENV="development"; \
	 flask run --port=5230;


prod-env:
	 make install; \
	 export PYTHONPATH=$(PYTHON_PATH_USERS_SERVICE); \
	 export FLASK_APP="setup.py"; \
	 export FLASK_ENV="production"; \
	 flask run --port=5230;


test-env:
	 make install; \
	 export PYTHONPATH=$(PYTHON_PATH_USERS_SERVICE); \
	 export FLASK_APP="setup.py"; \
	 export FLASK_ENV="testing"; \
	 flask run --port=5230;

lint:
	pylint setup.py users_service/
