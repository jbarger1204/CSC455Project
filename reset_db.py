"""Reset the test database safely.

This script will remove the local `instance/db.sqlite3` file (if present) and recreate the DB schema
by calling SQLAlchemy's `create_all()`.

Usage (PowerShell):
  .\.venv\Scripts\Activate.ps1
  python reset_db.py

Be careful: this deletes local test data. Do NOT run on production DBs.
"""
import os
import shutil
from app import app, db

DB_PATH = os.path.join('instance', 'db.sqlite3')

def main():
    if os.path.exists(DB_PATH):
        print('Removing existing DB file if possible:', DB_PATH)
        try:
            os.remove(DB_PATH)
            print('File removed')
        except PermissionError:
            # file is in use by another process (web server). we fall back to drop_all below
            print('Could not remove file (in use). Falling back to dropping tables via SQLAlchemy')
    else:
        print('No existing DB file found at', DB_PATH)

    # Ensure instance folder exists
    os.makedirs('instance', exist_ok=True)

    with app.app_context():
        # Clear the schema then recreate tables. This works even if the sqlite file couldn't be removed
        try:
            db.drop_all()
        except Exception as e:
            print('Warning: db.drop_all() failed:', e)
        db.create_all()
    print('Database recreated (empty).')

if __name__ == '__main__':
    confirm = input('This will DELETE the local instance DB. Type YES to continue: ')
    if confirm.strip().upper() == 'YES':
        main()
    else:
        print('Aborted.')
