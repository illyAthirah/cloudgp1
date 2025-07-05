import os

from flask import flash

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
import datetime
import pyotp  # Added for TOTP
import qrcode # Added for QR code generation
from io import BytesIO # Added to handle image data in memory
import base64 # Added to encode image for HTML display

app = Flask(__name__, static_folder='static')
app.secret_key = 'your_secret_key_here'  # Needed for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Google SSO Blueprint
google_bp = make_google_blueprint(
    client_id="344509022009-rf4vjmv3267iknkrm2e734dklmbjegl3.apps.googleusercontent.com",
    client_secret="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",
    scope=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ],
    redirect_url="/"
)
app.register_blueprint(google_bp, url_prefix="/login")

# ---------------------------
# Models
# ---------------------------

# This is a mock user dictionary for initial testing.
# MFA will not be applied to these users.
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
    # --- ADDED: Column to store the TOTP secret key for MFA ---
    totp_secret = db.Column(db.String(32), nullable=True)

# ---------------------------
# Initialize DB
# ---------------------------

with app.app_context():
    db.create_all()

# ---------------------------
# Routes
# ---------------------------

@app.route("/")
def index():
    # Google SSO
    if google.authorized:
        resp = google.get("/oauth2/v2/userinfo")
        if resp.ok:
            user_info = resp.json()
            email = user_info['email']

            registered_user = RegisteredUser.query.filter_by(username=email).first()
            if not registered_user:
                # For Google users, we don't set a password or TOTP secret initially
                new_user = RegisteredUser(
                    username=email,
                    password_hash=generate_password_hash(pyotp.random_base32()), # Generate a random password hash
                    role='Google User'
                )
                db.session.add(new_user)
                db.session.commit()

            session['authenticated'] = True
            session['username'] = email
            session['role'] = 'Google User'
            return redirect(url_for('dashboard'))

    # If already logged in, redirect to dashboard
    if session.get('authenticated'):
        return redirect(url_for('dashboard'))

    # Otherwise, show the login page
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        existing_user = RegisteredUser.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists. Try a different one."

        hashed_password = generate_password_hash(password)

        # --- ADDED: Generate a TOTP secret for the new user ---
        secret = pyotp.random_base32()

        new_user = RegisteredUser(
            username=username,
            password_hash=hashed_password,
            role=role,
            totp_secret=secret # Save the secret to the user's record
        )
        db.session.add(new_user)
        db.session.commit()

        # --- MODIFIED: Redirect to MFA setup instead of login ---
        # Store username in session to retrieve it on the setup page
        session['username_for_mfa_setup'] = username
        return redirect(url_for('mfa_setup'))

    return render_template('register.html')

# --- NEW ROUTE: To show QR code for MFA setup ---
@app.route('/mfa-setup')
def mfa_setup():
    # Retrieve the username stored in the session after registration
    username = session.get('username_for_mfa_setup')
    if not username:
        return redirect(url_for('index'))

    user = RegisteredUser.query.filter_by(username=username).first()
    if not user or not user.totp_secret:
        # If user or secret doesn't exist, something went wrong.
        return redirect(url_for('register'))

    # Generate the provisioning URI for the authenticator app
    totp = pyotp.TOTP(user.totp_secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name="YourCloudApp")

    # Generate the QR code image
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)

    # Encode the image to a base64 string to embed in the HTML
    img_b64 = base64.b64encode(buf.read()).decode('utf-8')

    # Clear the temporary session variable
    session.pop('username_for_mfa_setup', None)

    # You will need to create an 'mfa_setup.html' template
    # This template should display the QR code and instruct the user to scan it.
    return render_template('mfa_setup.html', qr_code=img_b64)

@app.route('/authenticate', methods=['POST'])
def authenticate():
    username = request.form.get('username')
    password = request.form.get('password')

    # 1. Check mock users (no MFA)
    if username in users and password == users[username]['password']:
        session['authenticated'] = True
        session['username'] = username
        session['role'] = users[username]['role']
        log = UserLog(username=username, role=users[username]['role'])
        db.session.add(log)
        db.session.commit()
        # ... role messages ...
        return jsonify({
            "message": "Authentication successful!",
            "status": "success",
            "redirect": url_for('dashboard')
        })

    # 2. Check registered users
    registered_user = RegisteredUser.query.filter_by(username=username).first()
    if registered_user and check_password_hash(registered_user.password_hash, password):
        # --- MODIFIED: Check if MFA is enabled for this user ---
        if registered_user.totp_secret:
            # Password is correct, but MFA is required.
            # Don't log them in yet. Store username and set a flag.
            session['mfa_required'] = True
            session['username'] = registered_user.username
            return jsonify({
                "status": "mfa_required",
                "redirect": url_for('mfa_verify') # Redirect to the MFA verification page
            })
        else:
            # No MFA secret, log in directly
            session['authenticated'] = True
            session['username'] = registered_user.username
            session['role'] = registered_user.role
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
        "message": "Authentication failed. Please check your credentials.",
        "status": "error"
    })

# --- NEW ROUTE: To verify the TOTP code from the user ---
@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    if not session.get('mfa_required'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        otp_input = request.form.get('otp')
        username = session.get('username')
        user = RegisteredUser.query.filter_by(username=username).first()

        if not user:
            session.clear()
            return redirect(url_for('index'))

        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(otp_input):
            # OTP is correct. Finalize login.
            session.pop('mfa_required', None)
            session['authenticated'] = True
            session['role'] = user.role

            # Save login log
            log = UserLog(username=user.username, role=user.role)
            db.session.add(log)
            db.session.commit()

            return redirect(url_for('dashboard'))
        else:
            # Invalid OTP
            # You need an 'mfa_verify.html' template
            return render_template('mfa_verify.html', error="Invalid OTP. Please try again.")

    # For GET request, just show the verification form
    return render_template('mfa_verify.html')


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
    # Remove Google OAuth token if present
    session.pop('google_oauth_token', None)
    # Clear app session data
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

@app.route('/show-users')
def show_users():
    if not session.get('authenticated') or session.get('role') != 'Administrator':
        return "Access Denied", 403
    users = RegisteredUser.query.all()
    output = '<h3>Registered Users:</h3>'
    for user in users:
        has_mfa = "Yes" if user.totp_secret else "No"
        output += f"Username: {user.username}, Role: {user.role}, MFA Enabled: {has_mfa}<br>"
    return output

# ---------------------------
# Run
# ---------------------------
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)