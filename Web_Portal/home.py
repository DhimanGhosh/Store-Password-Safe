from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return "<h1>Welcome to Store Password Safe</h1>"

@app.route('/user')
def users():
    return "<h2>Welcome User!</h2>"

if __name__ == "__main__":
    app.run(debug=True)