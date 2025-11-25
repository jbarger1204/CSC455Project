import tkinter as tk
from tkinter import messagebox
import requests
import re

# Simple Tkinter client to call the Flask 2FA endpoints for demo purposes.
# Usage: run the Flask app locally, then run this client and point to the base URL.

# Map common HTTP codes to human-friendly phrases
HTTP_MEANINGS = {
    200: '200 OK — Success',
    201: '201 Created',
    302: '302 Redirect',
    400: '400 Bad Request',
    401: '401 Unauthorized',
    403: '403 Forbidden',
    404: '404 Not Found',
    429: '429 Too Many Requests',
    500: '500 Server Error'
}


def extract_flash_messages(html_text):
    """Extract messages from the simple Flask template flash divs.
    Looks for <div class="flash ...">message</div> and returns plain messages list.
    """
    if not html_text:
        return []
    # This is a lightweight parser using regex to avoid extra dependencies.
    pattern = re.compile(r'<div class="flash(?: [^\"]*)?">(.*?)</div>', re.S)
    msgs = []
    for m in pattern.findall(html_text):
        # Strip HTML tags inside the flash if any
        text = re.sub(r'<[^>]+>', '', m).strip()
        if text:
            msgs.append(text)
    return msgs


class ClientApp:
    def __init__(self, master):
        self.master = master
        master.title('2FA Demo Client')

        tk.Label(master, text='Server base URL').grid(row=0, column=0)
        self.url_entry = tk.Entry(master, width=40)
        self.url_entry.insert(0, 'http://127.0.0.1:5000')
        self.url_entry.grid(row=0, column=1)

        tk.Label(master, text='Email').grid(row=1, column=0)
        self.email_entry = tk.Entry(master)
        self.email_entry.grid(row=1, column=1)

        tk.Label(master, text='Password').grid(row=2, column=0)
        self.password_entry = tk.Entry(master, show='*')
        self.password_entry.grid(row=2, column=1)

        tk.Label(master, text='Phone (optional)').grid(row=3, column=0)
        self.phone_entry = tk.Entry(master)
        self.phone_entry.grid(row=3, column=1)

        self.register_btn = tk.Button(master, text='Register', command=self.register)
        self.register_btn.grid(row=4, column=0)

        self.login_btn = tk.Button(master, text='Login (request OTP)', command=self.login)
        self.login_btn.grid(row=4, column=1)

        tk.Label(master, text='OTP').grid(row=5, column=0)
        self.otp_entry = tk.Entry(master)
        self.otp_entry.grid(row=5, column=1)

        self.verify_btn = tk.Button(master, text='Verify OTP', command=self.verify)
        self.verify_btn.grid(row=6, column=0, columnspan=2)

        self.session = requests.Session()

    def base(self):
        return self.url_entry.get().rstrip('/')

    def show_response(self, resp):
        code = resp.status_code
        meaning = HTTP_MEANINGS.get(code, f'{code} (see response)')
        # Try to extract flashed messages from HTML
        flashes = extract_flash_messages(resp.text)
        # Show all flashes, not just the first one
        if flashes:
            message = '\n'.join(flashes)
        else:
            message = meaning
        # Show as info for 2xx, warning for 3xx/4xx, error for 5xx
        if 200 <= code < 300:
            messagebox.showinfo('Response', message)
        elif 300 <= code < 500:
            messagebox.showwarning('Response', message)
        else:
            messagebox.showerror('Response', message)

    def register(self):
        data = {'email': self.email_entry.get(), 'password': self.password_entry.get(), 'phone': self.phone_entry.get()}
        resp = self.session.post(self.base() + '/register', data=data)
        self.show_response(resp)

    def login(self):
        # Auto-select SMS if phone is filled, otherwise email
        phone = self.phone_entry.get().strip()
        method = 'sms' if phone else 'email'
        data = {'email': self.email_entry.get(), 'password': self.password_entry.get(), 'method': method}
        resp = self.session.post(self.base() + '/login', data=data)
        self.show_response(resp)

    def verify(self):
        data = {'code': self.otp_entry.get()}
        resp = self.session.post(self.base() + '/verify', data=data)
        self.show_response(resp)


if __name__ == '__main__':
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
