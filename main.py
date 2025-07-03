from flask import Flask, render_template, request, jsonify

app = Flask(__name__, static_folder='static')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/authenticate', methods=['POST'])
def authenticate():
    username = request.form.get('username')
    password = request.form.get('password')

    # Simulate authentication logic based on your topic
    if username == 'byoduser' and password == 'securepass':
        message = "Authentication successful! Your BYOD device is compliant; proceeding with multi-factor authentication for cloud resource access."
        status = "success"
    elif username == 'admin' and password == 'cloudadmin':
        message = "Cloud administrator login detected. Initiating federated identity verification for enterprise cloud access."
        status = "success"
    elif username == 'guest' and password == 'byodguest':
        message = "Guest access detected. Limited cloud resources available after identity federation with external provider."
        status = "success"
    else:
        message = "Authentication failed. Please check your credentials and ensure your BYOD device meets security policies for cloud access."
        status = "error"

    return jsonify({"message": message, "status": status})

if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App Engine,
    # a webserver process (like Gunicorn) is used to serve the application.
    app.run(host='127.0.0.1', port=8080, debug=True)