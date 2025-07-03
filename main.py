from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__, static_folder='static')
app.secret_key = 'your_secret_key_here'  # Needed for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ---------------------------
# Models
# ---------------------------

# Mock user database (for testing)
users = {
    'byoduser': {'password': 'securepass', 'role': 'BYOD User'},
    'admin': {'password': 'cloudadmin', 'role': 'Administrator'},
    'guest': {'password': 'byodguest', 'role': 'Guest'}
}

class UserLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class RegisteredUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)

# ---------------------------
# Initialize DB
# ---------------------------

with app.app_context():
    db.create_all()

# ---------------------------
# Routes
# ---------------------------

@app.route('/')
def index():
    if 'authenticated' in session and session['authenticated']:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Check if username already exists
        existing_user = RegisteredUser.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists. Try a different one."

        # Hash the password before saving
        hashed_password = generate_password_hash(password)

        # Save to database
        new_user = RegisteredUser(username=username, password_hash=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('index'))  # Redirect to login after success

    return render_template('register.html')

@app.route('/authenticate', methods=['POST'])
def authenticate():
    username = request.form.get('username')
    password = request.form.get('password')

    # 1. Check mock users
    if username in users and password == users[username]['password']:
        session['authenticated'] = True
        session['username'] = username
        session['role'] = users[username]['role']

        # Save login log
        log = UserLog(username=username, role=users[username]['role'])
        db.session.add(log)
        db.session.commit()

        # Role messages
        if username == 'byoduser':
            message = "Authentication successful! Your BYOD device is compliant; proceeding with multi-factor authentication for cloud resource access."
        elif username == 'admin':
            message = "Cloud administrator login detected. Initiating federated identity verification for enterprise cloud access."
        elif username == 'guest':
            message = "Guest access detected. Limited cloud resources available after identity federation with external provider."
        else:
            message = "Authentication successful!"

        return jsonify({
            "message": message,
            "status": "success",
            "redirect": url_for('dashboard')
        })

    # 2. Check registered users
    registered_user = RegisteredUser.query.filter_by(username=username).first()
    if registered_user and check_password_hash(registered_user.password_hash, password):
        session['authenticated'] = True
        session['username'] = registered_user.username
        session['role'] = registered_user.role

        # Save login log
        log = UserLog(username=registered_user.username, role=registered_user.role)
        db.session.add(log)
        db.session.commit()

        return jsonify({
            "message": f"Welcome back, {registered_user.username}!",
            "status": "success",
            "redirect": url_for('dashboard')
        })

    # Failed login
    return jsonify({
        "message": "Authentication failed. Please check your credentials and ensure your BYOD device meets security policies for cloud access.",
        "status": "error"
    })

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect(url_for('index'))

    username = session.get('username')
    role = session.get('role')

    logs = UserLog.query.filter_by(username=username).order_by(UserLog.login_time.desc()).all()

    return render_template('dashboard.html',
                           username=username,
                           role=role,
                           logs=logs)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/show-users')
def show_users():
    users = RegisteredUser.query.all()
    output = ''
    for user in users:
        output += f"Username: {user.username}, Role: {user.role}<br>"
    return output


# ---------------------------
# Run
# ---------------------------
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
