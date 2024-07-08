import os
import string

class Config(object):
    SECRET_KEY = os.urandom(50)
    AES_KEY = os.urandom(16)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    FLAG = open("/flag.txt","r").read()
    UPLOAD_FOLDER = "/app/uploads"
    ALLOWED_EXTENSIONS = {'txt'}
    ALLOWED_USER_CHARS = string.ascii_lowercase+string.digits+"_-"

class ProductionConfig(Config):
    pass


class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True