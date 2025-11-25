"""List registered users from the app database.
Usage: run in the project root with the virtualenv active:

  .\.venv\Scripts\Activate.ps1
  python list_users.py

This prints: id, email, phone, created info (where available).
"""
from app import app, db, User

with app.app_context():
    users = User.query.all()
    if not users:
        print('No users found in the database.')
    for u in users:
        print(f'id={u.id}\temail={u.email}\tphone={u.phone}\tfailed_login_attempts={u.failed_login_attempts}')
