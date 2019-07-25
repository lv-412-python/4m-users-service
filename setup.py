""" app runner """
from users_service import APP
from logging.config import fileConfig

if __name__ == '__main__':
    fileConfig('logging.config')

    APP.run(host='0.0.0.0', port=5050)
