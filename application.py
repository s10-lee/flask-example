from flask import Flask
app = Flask(__name__)

html = '''
    <html>\n
    <head> <title>EB Flask Test</title> </head>\n
    <body><h1>application app</h1></body>\n
    </html>
    '''


@app.route('/')
def index():
    return html


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0')
