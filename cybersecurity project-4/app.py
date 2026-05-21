import os
import re
import time
import sqlite3
import base64
from io import BytesIO
from functools import wraps
from flask import Flask, request, jsonify, session, redirect, send_from_directory
import bcrypt
import pyotp
import qrcode
from dotenv import load_dotenv

# Load configurations
load_dotenv()

app = Flask(__name__, static_folder='public', static_url_path='')

# Secure Session configuration
app.secret_key = os.getenv('SESSION_SECRET', 'e7d3b2f90a18c642b55f891d4e0e64c39b8c0a9d0a1b2c3d4e5f6a7b8c9d0e1f')
app.config.update(
    SESSION_COOKIE_NAME='secure_session_id',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=(os.getenv('FLASK_ENV', 'development') == 'production')
)

DATABASE = os.path.join(os.path.dirname(__file__), 'data', 'database.db')

# Custom in-memory rate limiter to avoid requiring external Redis/Memcached configurations
rate_limit_store = {}

def limit_rate(limit, period_seconds):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            
            # Filter timestamps to keep only those within the rate window
            if ip in rate_limit_store:
                rate_limit_store[ip] = [t for t in rate_limit_store[ip] if now - t < period_seconds]
            else:
                rate_limit_store[ip] = []
                
            if len(rate_limit_store[ip]) >= limit:
                return jsonify({
                    'success': False,
                    'message': 'Too many authentication attempts from this IP. Please try again later.'
                }), 429
                
            rate_limit_store[ip].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Database Utilities
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            two_factor_secret TEXT,
            two_factor_enabled INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    conn.commit()
    conn.close()

# Initialize DB structure on load
init_db()

# Middleware Check Decorators
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or not session.get('authenticated'):
            # Return JSON for API/XHR calls, redirect for standard browser requests
            if request.path.startswith('/api/') or request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', ''):
                return jsonify({'success': False, 'message': 'Unauthorized. Please login.'}), 401
            return redirect('/login.html')
        return f(*args, **kwargs)
    return decorated

def require_2fa_pending(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'temp_user_id' not in session:
            if request.path.startswith('/api/') or request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', ''):
                return jsonify({'success': False, 'message': 'Unauthorized session state.'}), 401
            return redirect('/login.html')
        return f(*args, **kwargs)
    return decorated

# Password validator check
def validate_password_strength(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[^A-Za-z0-9]', password):
        return False
    return True

# ----------------- SECURITY HEADERS MIDDLEWARE -----------------
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ----------------- PAGE ROUTING ROUTES -----------------
@app.route('/')
def index():
    if 'user_id' in session and session.get('authenticated'):
        return redirect('/dashboard.html')
    return redirect('/login.html')

@app.route('/login.html')
def serve_login():
    if 'user_id' in session and session.get('authenticated'):
        return redirect('/dashboard.html')
    return send_from_directory(app.static_folder, 'login.html')

@app.route('/register.html')
def serve_register():
    if 'user_id' in session and session.get('authenticated'):
        return redirect('/dashboard.html')
    return send_from_directory(app.static_folder, 'register.html')

@app.route('/verify-2fa.html')
def serve_verify_2fa():
    if 'user_id' in session and session.get('authenticated'):
        return redirect('/dashboard.html')
    if 'temp_user_id' not in session:
        return redirect('/login.html')
    return send_from_directory(app.static_folder, 'verify-2fa.html')

@app.route('/dashboard.html')
def serve_dashboard():
    if 'user_id' not in session or not session.get('authenticated'):
        return redirect('/login.html')
    return send_from_directory(app.static_folder, 'dashboard.html')

# ----------------- AUTHENTICATION API ROUTES -----------------
@app.route('/api/auth/register', methods=['POST'])
@limit_rate(15, 900)  # max 15 requests per 15 mins
def register():
    try:
        data = request.get_json() or {}
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required.'}), 400

        # Validate Username Format
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            return jsonify({
                'success': False,
                'message': 'Username must be between 3 and 20 characters and contain only letters, numbers, and underscores.'
            }), 400

        # Validate Email Format
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            return jsonify({'success': False, 'message': 'Please enter a valid email address.'}), 400

        # Validate Password Strength
        if not validate_password_strength(password):
            return jsonify({
                'success': False,
                'message': 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
            }), 400

        conn = get_db()
        cursor = conn.cursor()
        
        # Check for duplication (parameterized select prevents injection)
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Username or email already registered.'}), 409

        # Hash credentials using bcrypt (12 cost factor)
        salt = bcrypt.gensalt(rounds=12)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        # Insert user record
        cursor.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, password_hash)
        )
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'Registration successful. You can now login.'}), 201

    except Exception as e:
        print("Registration error:", e)
        return jsonify({'success': False, 'message': 'An internal server error occurred.'}), 500

@app.route('/api/auth/login', methods=['POST'])
@limit_rate(15, 900)
def login():
    try:
        data = request.get_json() or {}
        username_or_email = data.get('usernameOrEmail', '').strip().lower()
        password = data.get('password', '')

        if not username_or_email or not password:
            return jsonify({'success': False, 'message': 'All fields are required.'}), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?',
            (username_or_email, username_or_email)
        )
        user = cursor.fetchone()
        conn.close()

        # Timing attack countermeasure: verify dummy hash if username not found
        dummy_hash = '$2b$12$LRY8N7Q0mE7fFvV3uC7fEeU3t3S8Z3Yn/Z6X5R3.xY7i/6P3V0T6q'
        hash_to_verify = user['password_hash'] if user else dummy_hash
        is_password_valid = bcrypt.checkpw(password.encode('utf-8'), hash_to_verify.encode('utf-8'))

        if not user or not is_password_valid:
            # Generic error to prevent enumeration
            return jsonify({'success': False, 'message': 'Invalid username/email or password.'}), 401

        # Check if 2FA is active
        if user['two_factor_enabled'] == 1 and user['two_factor_secret']:
            session['temp_user_id'] = user['id']
            return jsonify({
                'success': True,
                'requires2FA': True,
                'message': 'Password verified. Two-Factor Authentication required.'
            }), 200

        # Create session
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['authenticated'] = True

        return jsonify({
            'success': True,
            'requires2FA': False,
            'message': 'Login successful.'
        }), 200

    except Exception as e:
        print("Login error:", e)
        return jsonify({'success': False, 'message': 'An internal server error occurred.'}), 500

@app.route('/api/auth/verify-2fa', methods=['POST'])
@limit_rate(15, 900)
@require_2fa_pending
def verify_2fa():
    try:
        data = request.get_json() or {}
        token = data.get('token', '').strip()
        temp_user_id = session.get('temp_user_id')

        if not token:
            return jsonify({'success': False, 'message': '2FA Token is required.'}), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (temp_user_id,))
        user = cursor.fetchone()
        conn.close()

        if not user or user['two_factor_enabled'] != 1 or not user['two_factor_secret']:
            return jsonify({'success': False, 'message': '2FA is not set up for this user.'}), 400

        # Verify TOTP Token
        totp = pyotp.TOTP(user['two_factor_secret'])
        if not totp.verify(token):
            return jsonify({'success': False, 'message': 'Invalid 2FA code. Please try again.'}), 401

        # Complete Authentication
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['authenticated'] = True

        return jsonify({
            'success': True,
            'message': 'Two-Factor Verification successful. Login completed.'
        }), 200

    except Exception as e:
        print("2FA login verification error:", e)
        return jsonify({'success': False, 'message': 'An internal server error occurred.'}), 500

@app.route('/api/auth/setup-2fa', methods=['POST'])
@require_auth
def setup_2fa():
    try:
        user_id = session.get('user_id')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT username, two_factor_enabled FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return jsonify({'success': False, 'message': 'User not found.'}), 404

        if user['two_factor_enabled'] == 1:
            return jsonify({'success': False, 'message': '2FA is already enabled.'}), 400

        # Generate TOTP Configuration
        secret = pyotp.random_base32()
        app_name = os.getenv('TFA_APP_NAME', 'SecureAuthSystem')
        
        totp = pyotp.TOTP(secret)
        otpauth_uri = totp.provisioning_uri(name=user['username'], issuer_name=app_name)

        # Generate QR code image
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(otpauth_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Buffer image to base64 string
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
        qr_data_url = f"data:image/png;base64,{qr_base64}"

        # Store secret temporarily in session state
        session['temp_2fa_secret'] = secret

        return jsonify({
            'success': True,
            'secret': secret,
            'qrCode': qr_data_url
        }), 200

    except Exception as e:
        print("2FA Setup initialization error:", e)
        return jsonify({'success': False, 'message': 'An error occurred during 2FA setup.'}), 500

@app.route('/api/auth/enable-2fa', methods=['POST'])
@require_auth
def enable_2fa():
    try:
        data = request.get_json() or {}
        token = data.get('token', '').strip()
        user_id = session.get('user_id')
        temp_secret = session.get('temp_2fa_secret')

        if not token:
            return jsonify({'success': False, 'message': 'Verification code is required.'}), 400

        if not temp_secret:
            return jsonify({'success': False, 'message': '2FA setup was not initialized. Please request a new QR code.'}), 400

        # Verify Code
        totp = pyotp.TOTP(temp_secret)
        if not totp.verify(token):
            return jsonify({'success': False, 'message': 'Invalid verification code. Please try again.'}), 400

        # Save to DB
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1 WHERE id = ?',
            (temp_secret, user_id)
        )
        conn.commit()
        conn.close()

        # Remove temporary secret
        session.pop('temp_2fa_secret', None)

        return jsonify({
            'success': True,
            'message': 'Two-Factor Authentication has been successfully enabled on your account!'
        }), 200

    except Exception as e:
        print("Enable 2FA error:", e)
        return jsonify({'success': False, 'message': 'An error occurred while enabling 2FA.'}), 500

@app.route('/api/auth/disable-2fa', methods=['POST'])
@require_auth
def disable_2fa():
    try:
        data = request.get_json() or {}
        token = data.get('token', '').strip()
        user_id = session.get('user_id')

        if not token:
            return jsonify({'success': False, 'message': 'Verification code is required to disable 2FA.'}), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()

        if not user or user['two_factor_enabled'] != 1 or not user['two_factor_secret']:
            conn.close()
            return jsonify({'success': False, 'message': '2FA is not enabled on this account.'}), 400

        # Verify Code
        totp = pyotp.TOTP(user['two_factor_secret'])
        if not totp.verify(token):
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid verification code. Disable action rejected.'}), 400

        # Update columns
        cursor.execute('UPDATE users SET two_factor_secret = NULL, two_factor_enabled = 0 WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Two-Factor Authentication has been disabled successfully.'
        }), 200

    except Exception as e:
        print("Disable 2FA error:", e)
        return jsonify({'success': False, 'message': 'An error occurred while disabling 2FA.'}), 500

@app.route('/api/auth/user', methods=['GET'])
@require_auth
def get_user():
    try:
        user_id = session.get('user_id')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email, two_factor_enabled, created_at FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return jsonify({'success': False, 'message': 'User not found.'}), 404

        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'twoFactorEnabled': user['two_factor_enabled'] == 1,
                'createdAt': user['created_at']
            }
        }), 200

    except Exception as e:
        print("Get profile error:", e)
        return jsonify({'success': False, 'message': 'An error occurred fetching account details.'}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully.'}), 200

# Catch-all rule to serve static styling or asset files
@app.route('/<path:path>')
def serve_fallback_static(path):
    return send_from_directory(app.static_folder, path)

if __name__ == '__main__':
    port = int(os.getenv('PORT', 3000))
    flask_env = os.getenv('FLASK_ENV', 'development')
    debug_mode = (flask_env == 'development')
    
    print(f"====================================================")
    print(f"SECURE LOGIN SYSTEM (Python) running on port {port}")
    print(f"Environment: {flask_env}")
    print(f"Local Access: http://localhost:{port}")
    print(f"====================================================")
    
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
