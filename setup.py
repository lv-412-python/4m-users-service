""" app runner """
from users_service import APP

if __name__ == '__main__':
    if not APP.debug:
        from logging.config import fileConfig
        fileConfig('logging.config')

    APP.run(host='0.0.0.0', port=5000)
