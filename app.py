from flask import Flask

application = Flask(__name__)


@application.route('/')
def index():
    return 'Test Amazon pipeline.'


if __name__ == '__main__':
    application.run()