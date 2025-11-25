"""Reset a user's password.
Usage:
  .\.venv\Scripts\Activate.ps1
  python reset_password.py user@example.com NewP@ssw0rd

This updates the user's password (bcrypt-hashed) in the app database.
"""
import sys
from app import app, db, User

if len(sys.argv) < 3:
    print('Usage: python reset_password.py user_email new_password')
    sys.exit(1)

email = sys.argv[1].strip().lower()
new_password = sys.argv[2]

with app.app_context():
    user = User.query.filter_by(email=email).first()
    if not user:
        print('User not found:', email)
        sys.exit(2)
    user.set_password(new_password)
    db.session.commit()
    print('Password updated for', email)
