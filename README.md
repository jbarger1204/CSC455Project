# CSC455Project

Two-Factor Authentication (2FA) demo using Flask (password + one-time code via email).

Features
- User registration and password authentication (bcrypt hashed)
- One-time code generation (6-digit), emailed via SMTP or printed to console in demo mode
- OTP verification with expiration (default 5 minutes)
- Secure session management via Flask-Login

Quick start
1. Create a virtualenv and install dependencies:

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt
```

2. Copy environment example and configure SMTP (optional):

```powershell
copy .env.example .env
# Edit .env to set SMTP_SERVER, SMTP_USERNAME, SMTP_PASSWORD, SENDER_EMAIL, and SECRET_KEY
```

3. Run the app:

```powershell
python app.py
```

4. Open `http://127.0.0.1:5000` in your browser. If SMTP settings are not provided, the OTP will be printed to the console for demo purposes.

Notes and extensions
- To enable SMS delivery, integrate Twilio in `send_email` or add a `send_sms` helper. Add `twilio` to `requirements.txt` if you plan to use it.
- You can increase OTP strength, add rate-limiting, lockout on repeated failures, or use TOTP (RFC 6238) for authenticator app support.

Security considerations
- Passwords and OTP hashes use bcrypt. OTPs are ephemeral and stored hashed with expiration.
- For production: use TLS/SSL for the app, secure SECRET_KEY, a production DB, and real email/SMS providers.

