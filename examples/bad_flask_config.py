# Flask configuration - INSECURE example

from flask import Flask

app = Flask(__name__)

DEBUG = True
SECRET_KEY = 'dev'
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False

DATABASE_PASSWORD = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890'
API_SECRET_KEY = 'test'
