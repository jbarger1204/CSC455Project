import os
import random
from datetime import datetime, timedelta, UTC
from email.message import EmailMessage
import smtplib

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from dotenv import load_dotenv

load_dotenv()


def make_aware(dt):
    """Return a timezone-aware datetime in UTC.
    If dt is None return None. If dt is naive, assume it's UTC and attach UTC tzinfo.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///db.sqlite3')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(32), unique=False, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    otp_hash = db.Column(db.String(128), nullable=True)
    otp_expiration = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    otp_sent_count = db.Column(db.Integer, default=0)
    last_otp_sent = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode()

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def set_otp(self, otp, expires_minutes=5):
        self.otp_hash = bcrypt.generate_password_hash(otp).decode()
        self.otp_expiration = datetime.now(UTC) + timedelta(minutes=expires_minutes)

    def check_otp(self, otp):
        if not self.otp_hash or not self.otp_expiration:
            return False
        exp = self.otp_expiration
        if exp is None:
            return False
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        if datetime.now(UTC) > exp:
            return False
        return bcrypt.check_password_hash(self.otp_hash, otp)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def send_email(recipient, subject, body):
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT', '465'))
    smtp_user = os.getenv('SMTP_USERNAME')
    smtp_pass = os.getenv('SMTP_PASSWORD')
    sender = os.getenv('SENDER_EMAIL', smtp_user)

    if not smtp_server or not smtp_user or not smtp_pass:
        # For demo environments where SMTP not configured, print the code to console
        print(f"[DEMO MODE] Email to {recipient}: {subject}\n{body}")
        return True

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient
    msg.set_content(body)

    try:
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        # Print the error and the message body to help in demo/debug environments
        print('Failed to send email:', e)
        try:
            print('[EMAIL BODY]')
            print(body)
            print('[/EMAIL BODY]')
        except Exception:
            pass
        return False


def send_sms(to_number, body):
    #Twilio integration. Provide TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM in .env
    sid = os.getenv('TWILIO_ACCOUNT_SID')
    token = os.getenv('TWILIO_AUTH_TOKEN')
    twilio_from = os.getenv('TWILIO_FROM')
    if not sid or not token or not twilio_from:
        print(f"[DEMO MODE] SMS to {to_number}: {body}")
        return True
    try:
        from twilio.rest import Client
        client = Client(sid, token)
        msg = client.messages.create(body=body, from_=twilio_from, to=to_number)
        print('Twilio SID:', msg.sid)
        return True
    except Exception as e:
        print('Failed to send SMS:', e)
        return False


def generate_otp():
    return f"{random.randint(100000, 999999)}"


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'warning')
            return redirect(url_for('register'))
        user = User(email=email)
        if phone:
            user.phone = phone
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        method = request.form.get('method', 'email')
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))

        # Check lockout
        lockout = make_aware(user.lockout_until)
        if lockout and datetime.now(UTC) < lockout:
            flash('Account is temporarily locked due to multiple failed attempts. Try later.', 'danger')
            return redirect(url_for('login'))

        # Rate-limit OTP sends: require 30s between sends
        now = datetime.now(UTC)
        last_sent = make_aware(user.last_otp_sent)
        if last_sent and (now - last_sent).total_seconds() < 30:
            flash('OTP recently sent. Please wait before requesting a new code.', 'warning')
            return redirect(url_for('login'))

        # Generate OTP and send
        otp = generate_otp()
        user.set_otp(otp, expires_minutes=5)
        user.otp_sent_count = (user.otp_sent_count or 0) + 1
        user.last_otp_sent = now
        db.session.commit()
        # Delivery: email by default, or sms if requested and phone present
        if method == 'sms' and user.phone:
            send_sms(user.phone, f'Your one-time code is: {otp}')
            flash('✓ OTP sent via SMS to ' + user.phone, 'info')
        else:
            send_email(user.email, 'Your 2FA Code', f'Your one-time code is: {otp}')
            flash('✓ OTP sent via email to ' + user.email, 'info')

        session['pre_2fa_user_id'] = user.id
        flash('A one-time code was sent to your email.', 'info')
        return redirect(url_for('verify'))
    return render_template('login.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        flash('No authentication in progress', 'warning')
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if request.method == 'POST':
        code = request.form['code'].strip()
        if user and user.check_otp(code):
            # Clear OTP and log in
            user.otp_hash = None
            user.otp_expiration = None
            user.failed_login_attempts = 0
            user.lockout_until = None
            db.session.commit()
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            flash('✓ Authentication successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            # increment failed attempts and lockout if necessary
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= 5:
                user.lockout_until = datetime.now(UTC) + timedelta(minutes=15)
                flash('Too many failed attempts. Account locked for 15 minutes.', 'danger')
            else:
                flash('Invalid or expired code', 'danger')
            db.session.commit()
            return redirect(url_for('verify'))
    return render_template('verify.html', email=user.email if user else '')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Ensure DB exists
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=os.getenv('FLASK_DEBUG', '1') == '1')
