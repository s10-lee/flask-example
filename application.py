from flask import Flask
application = Flask(__name__)

html = '''
    <html>\n
    <head> <title>EB Flask Test</title> </head>\n
    <body><h1>AWS pipeline finally !</h1></body>\n
    </html>
    '''


@application.route('/')
def index():
    return html


if __name__ == '__main__':
    application.debug = True
    application.run(host='0.0.0.0')
