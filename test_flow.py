# Simple integration test using Flask test_client to demonstrate registration + OTP verify flow
from app import app, db, User, generate_otp
from datetime import datetime

with app.app_context():
    # recreate DB for test
    db.drop_all()
    db.create_all()

    # create user directly
    user = User(email='tester@example.com')
    user.set_password('password123')
    db.session.add(user)
    db.session.commit()

    # Generate OTP manually and attach to user (simulate login step)
    otp = generate_otp()
    user.set_otp(otp, expires_minutes=5)
    db.session.commit()

    # Use test client to simulate verifying the OTP
    client = app.test_client()
    # Set session pre_2fa_user_id so /verify can find the user
    with client.session_transaction() as sess:
        sess['pre_2fa_user_id'] = user.id

    resp = client.post('/verify', data={'code': otp}, follow_redirects=True)
    text = resp.get_data(as_text=True)
    print('Verify response status:', resp.status_code)
    if 'Authentication successful' in text:
        print('2FA flow succeeded')
    else:
        print('2FA flow failed; response body:\n', text)
