import os

basedir = os.path.abspath(os.path.dirname(__file__))
FLASK_DB = os.environ['SQLALCHEMY_DATABASE_URI']


class BaseConfig:
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.getenv('SECRET_KEY', 'flask_secret')
    CSRF_ENABLED = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BCRYPT_LOG_ROUNDS = 4


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = FLASK_DB


class TestingConfig(BaseConfig):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = FLASK_DB + '_test'
    PRESERVE_CONTEXT_ON_EXCEPTION = False
