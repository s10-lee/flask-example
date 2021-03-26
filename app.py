from flask import Flask

app = Flask(__name__)


@app.route('/')
def index():
    return 'Test Amazon pipeline.'


if __name__ == '__main__':
    app.run()
