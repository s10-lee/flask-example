import os
import jwt
import datetime
from flask import Flask, request, make_response, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy


application = Flask(__name__)
application.config.from_object(os.getenv('APP_SETTINGS', 'config.DevelopmentConfig'))


CORS(application)
bcrypt = Bcrypt(application)
db = SQLAlchemy(application)


# Models
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, email, password, admin=False):
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, application.config.get('BCRYPT_LOG_ROUNDS', 4)
        ).decode()
        self.registered_on = datetime.datetime.now()
        self.admin = admin

    @staticmethod
    def encode_auth_token(user_id):

        print('encode_auth_token() !!!')

        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=10),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                application.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            raise e


    @staticmethod
    def decode_auth_token(auth_token):
        print('DECODE !')
        print(auth_token)
        print(application.config.get('SECRET_KEY'))
        try:
            payload = jwt.decode(auth_token, application.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'


class BlacklistToken(db.Model):
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return f'<id: token: {self.token}>'

    @staticmethod
    def check_blacklist(auth_token):
        return BlacklistToken.query.filter_by(token=str(auth_token)).first()




@application.route('/register', methods=['POST'])
def auth_register():
    post_data = request.get_json()
    user = User.query.filter_by(email=post_data.get('email')).first()
    if not user:
        try:
            user = User(
                email=post_data.get('email'),
                password=post_data.get('password')
            )
            db.session.add(user)
            db.session.commit()

            auth_token = user.encode_auth_token(user.id)
            response = {
                'status': 'success',
                'message': 'Successfully registered.',
                'auth_token': auth_token.decode()
            }
            return make_response(jsonify(response)), 201
        except Exception as e:
            print(e)
            response = {
                'status': 'fail',
                'message': 'Some error occurred. Please try again.'
            }
            return make_response(jsonify(response)), 401
    else:
        response = {
            'status': 'fail',
            'message': 'User already exists. Please Log in.',
        }
        return make_response(jsonify(response)), 202



@application.route('/login', methods=['POST'])
def auth_login():
    post_data = request.get_json()
    try:
        user = User.query.filter_by(email=post_data.get('email')).first()
        if user and bcrypt.check_password_hash(
                user.password, post_data.get('password')
        ):
            auth_token = user.encode_auth_token(user.id)
            if auth_token:
                response = {
                    'status': 'success',
                    'message': 'Successfully logged in.',
                    'auth_token': auth_token.decode()
                }
                return make_response(jsonify(response)), 200
        else:
            response = {
                'status': 'fail',
                'message': 'User does not exist.'
            }
            return make_response(jsonify(response)), 404
    except Exception as e:
        print('Exception - auth_login()', e)
        response = {
            'status': 'fail',
            'message': 'Try again'
        }
        return make_response(jsonify(response)), 500



@application.route('/status', methods=['GET'])
def auth_status():
    auth_header = request.headers.get('Authorization')
    if auth_header:
        try:
            auth_token = auth_header.split(" ")[1]
        except IndexError:
            response = {
                'status': 'fail',
                'message': 'Bearer token malformed.'
            }
            return make_response(jsonify(response)), 401
    else:
        auth_token = ''
    if auth_token:
        resp = User.decode_auth_token(auth_token)
        if not isinstance(resp, str):
            user = User.query.filter_by(id=resp).first()
            response = {
                'status': 'success',
                'data': {
                    'user_id': user.id,
                    'email': user.email,
                    'admin': user.admin,
                    'registered_on': user.registered_on
                }
            }
            return make_response(jsonify(response)), 200
        response = {
            'status': 'fail',
            'message': resp
        }
        return make_response(jsonify(response)), 401
    else:
        response = {
            'status': 'fail',
            'message': 'Provide a valid auth token.'
        }
        return make_response(jsonify(response)), 401



@application.route('/')
def index():
    return "<html>\n<head> <title>.index</title> </head>\n<body><h1>application</h1></body>\n</html>", 200


if __name__ == '__main__':
    application.run(host='0.0.0.0')
