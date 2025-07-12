import os
import datetime
import pyotp
import qrcode
from io import BytesIO
import base64

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
from oauthlib.oauth2.rfc6749.errors import TokenExpiredError

# Set this environment variable for OAUTHLIB_INSECURE_TRANSPORT if running locally over HTTP
# Remove or set to '0' for production with HTTPS
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__, static_folder='static')
app.secret_key = 'your_secret_key_here' # IMPORTANT: Change this to a strong, random secret key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Google OAuth Blueprint
google_bp = make_google_blueprint(
    client_id="344509022009-rf4vjmv3267iknkrm2e734dklmbjegl3.apps.googleusercontent.com",
    client_secret="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",
    scope=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ],
    redirect_url="/" # This should ideally be a dedicated callback URL, but for simple demo, '/' can work
)
app.register_blueprint(google_bp, url_prefix="/login")

# Database Models
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
    totp_secret = db.Column(db.String(32), nullable=True) # Stores the TOTP secret for MFA

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

# --- Routes ---


@app.route("/")
def index():
    if google.authorized:
        try:
            resp = google.get("/oauth2/v2/userinfo")
        except TokenExpiredError:
            session.clear()
            flash("Your session has expired. Please log in again.", "warning")
            return redirect(url_for("index"))
        if resp.ok:
            user_info = resp.json()
            email = user_info['email']

            registered_user = RegisteredUser.query.filter_by(username=email).first()
            if not registered_user:
                # If Google user not in DB, register them and generate MFA secret
                # Note: For Google SSO users, we are auto-generating a password_hash and totp_secret.
                # The password_hash here is just a placeholder as they won't use it for direct login.
                new_user = RegisteredUser(
                    username=email,
                    password_hash=generate_password_hash(pyotp.random_base32()), # Placeholder password
                    role='Google User', # Default role for Google SSO users
                    totp_secret=pyotp.random_base32() # Generate MFA secret
                )
                db.session.add(new_user)
                db.session.commit()
                # Redirect to MFA setup for new Google users
                session['username_for_mfa_setup'] = email
                return redirect(url_for('mfa_setup'))

            # For existing Google users, proceed to MFA verification if they have a secret
            if registered_user.totp_secret:
                session['mfa_required'] = True
                session['username'] = registered_user.username
                session['role'] = registered_user.role # Set role for dashboard
                return redirect(url_for('mfa_verify'))
            else:
                # This case should ideally not happen if a secret is always generated on registration.
                # But as a fallback, if an existing Google user somehow doesn't have a secret,
                # you might want to redirect them to setup or handle it.
                # For this demo, let's assume all Google users will have a secret after their first login.
                session['authenticated'] = True
                session['username'] = email
                session['role'] = registered_user.role
                return redirect(url_for('dashboard'))

    # If already authenticated (after MFA verification for local or Google login)
    if session.get('authenticated'):
        return redirect(url_for('dashboard'))

    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if not username or not password or not role:
            return render_template('register.html', error="All fields are required.")

        existing_user = RegisteredUser.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error="Username already exists. Try a different one.")

        hashed_password = generate_password_hash(password)
        secret = pyotp.random_base32() # Generate TOTP secret during registration

        new_user = RegisteredUser(
            username=username,
            password_hash=hashed_password,
            role=role,
            totp_secret=secret
        )
        db.session.add(new_user)
        db.session.commit()

        # Store username in session to retrieve it in mfa_setup route
        session['username_for_mfa_setup'] = username
        return redirect(url_for('mfa_setup'))

    return render_template('register.html')

@app.route('/mfa-setup')
def mfa_setup():
    username = session.get('username_for_mfa_setup')
    if not username:
        # If no username in session, redirect to index or register
        return redirect(url_for('index'))

    user = RegisteredUser.query.filter_by(username=username).first()
    if not user or not user.totp_secret:
        # Should not happen if secret is generated on registration/Google SSO first login
        return redirect(url_for('register'))

    # Generate TOTP provisioning URI and QR code
    totp = pyotp.TOTP(user.totp_secret)
    # Use the application name as issuer_name for clarity in authenticator app
    uri = totp.provisioning_uri(name=user.username, issuer_name="YourCloudApp")

    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)
    img_b64 = base64.b64encode(buf.read()).decode('utf-8')

    # Remove the temporary session variable after use
    session.pop('username_for_mfa_setup', None)

    return render_template('mfa_setup.html', qr_code=img_b64)

@app.route('/authenticate', methods=['POST'])
def authenticate():
    username = request.form.get('username')
    password = request.form.get('password')

    registered_user = RegisteredUser.query.filter_by(username=username).first()

    if registered_user and check_password_hash(registered_user.password_hash, password):
        if registered_user.totp_secret:
            # If user has MFA enabled, require MFA verification
            session['mfa_required'] = True
            session['username'] = registered_user.username
            session['role'] = registered_user.role # Store role for dashboard
            return jsonify({
                "status": "mfa_required",
                "redirect": url_for('mfa_verify')
            })
        else:
            # This case should be rare if all users get a secret on registration.
            # But if a user somehow exists without a secret, they cannot proceed.
            return jsonify({
                "message": "MFA is not set up for this user. Please contact admin or re-register.",
                "status": "error"
            })

    # If standard username/password authentication fails
    return jsonify({
        "message": "Authentication failed. Please check your credentials.",
        "status": "error"
    })

@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    # Ensure MFA is required and username is in session
    if not session.get('mfa_required') or not session.get('username'):
        return redirect(url_for('index'))

    username = session.get('username')
    user = RegisteredUser.query.filter_by(username=username).first()

    if not user:
        session.clear() # Clear session if user not found (shouldn't happen)
        return redirect(url_for('index'))

    if request.method == 'POST':
        otp_input = request.form.get('otp')

        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(otp_input):
            # MFA successful! Clear MFA flags, set authenticated, and log activity.
            session.pop('mfa_required', None)
            session['authenticated'] = True
            # User role is already set from /authenticate or / in case of Google SSO
            log = UserLog(username=user.username, role=session.get('role', 'Unknown'))
            db.session.add(log)
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            # Invalid OTP
            return render_template('mfa_verify.html', error="Invalid OTP. Please try again.")

    return render_template('mfa_verify.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect(url_for('index'))

    username = session.get('username')
    role = session.get('role') # Retrieve role from session
    logs = UserLog.query.filter_by(username=username).order_by(UserLog.login_time.desc()).all()

    return render_template('dashboard.html',
                           username=username,
                           role=role, # Pass role to template
                           logs=logs)

@app.route('/logout')
def logout():
    session.pop('google_oauth_token', None) # Clear Google OAuth token
    session.clear() # Clear all session variables
    flash("You have been logged out.", "success") # Optional: Use Flask-Flash for messages
    return redirect(url_for("index"))

@app.route('/show-users')
def show_users():
    # Example admin route to view registered users and their MFA status
    if not session.get('authenticated') or session.get('role') != 'Administrator':
        return "Access Denied", 403
    users = RegisteredUser.query.all()
    output = '<h3>Registered Users:</h3>'
    for user in users:
        has_mfa = "Yes" if user.totp_secret else "No"
        output += f"Username: {user.username}, Role: {user.role}, MFA Enabled: {has_mfa}<br>"
    return output

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)