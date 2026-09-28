#services/gateway/app.py
"""Zitified Gateway Service - Only binds to localhost, receives traffic via Edge Router"""
import os
import ssl
import sys
import yaml
import jwt
import hashlib
import sqlite3
import secrets
import uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS

# Add parent to path BEFORE importing shared
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE_DIR)

# ─── Structured logging ─────────────────────────────────────────────
from shared.logging_config import setup_logger, set_trace_id, emit_event, get_trace_id
from shared.events import (
    AUTH_LOGIN_SUCCESS, AUTH_LOGIN_FAILURE, AUTH_LOGOUT,
    AUTH_TOKEN_ISSUED, AUTH_TOKEN_REFRESHED, AUTH_TOKEN_INVALID,
    AUTH_TOKEN_EXPIRED, AUTH_TOKEN_MISSING, AUTH_TOKEN_REVOKED,
    ADMIN_USER_CREATED, ADMIN_USER_LISTED, ADMIN_ACCESS_DENIED,
    SERVICE_STARTUP,
)

logger = setup_logger("gateway")

# Load config - NO HARDCODES
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.yaml')
with open(CONFIG_PATH, 'r') as f:
    SERVICE_CONFIG = yaml.safe_load(f)

# Load clearance levels
CLEARANCE_PATH = os.path.join(BASE_DIR, 'config', 'policies', 'clearance_levels.yaml')
with open(CLEARANCE_PATH, 'r') as f:
    CLEARANCE_LEVELS = yaml.safe_load(f)

# Load departments
DEPT_PATH = os.path.join(BASE_DIR, 'config', 'policies', 'departments.yaml')
with open(DEPT_PATH, 'r') as f:
    DEPARTMENTS = yaml.safe_load(f)

app = Flask(__name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static')
)

# JWT Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_EXPIRY_HOURS'] = SERVICE_CONFIG.get('jwt', {}).get('expiry_hours', 8)
app.config['JWT_ALGORITHM'] = SERVICE_CONFIG.get('jwt', {}).get('algorithm', 'HS256')
app.config['JWT_REFRESH_EXPIRY_DAYS'] = SERVICE_CONFIG.get('jwt', {}).get('refresh_expiry_days', 7)

# Database setup
DB_PATH = os.path.join(BASE_DIR, 'database', 'gateway.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def init_db():
    """Initialize database tables"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  full_name TEXT NOT NULL,
                  department TEXT NOT NULL,
                  clearance_level TEXT NOT NULL,
                  mfa_secret TEXT,
                  is_active BOOLEAN DEFAULT 1,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    c.execute('''CREATE TABLE IF NOT EXISTS user_sessions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  jwt_token TEXT NOT NULL,
                  refresh_token TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  expires_at TIMESTAMP NOT NULL,
                  last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users(id))''')

    c.execute('''CREATE TABLE IF NOT EXISTS token_blacklist
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  token TEXT NOT NULL,
                  blacklisted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    conn.commit()
    conn.close()


init_db()


def generate_tokens(user_id, username, full_name, department, clearance_level):
    """Generate access and refresh JWT tokens"""
    access_expiry = datetime.utcnow() + timedelta(hours=app.config['JWT_EXPIRY_HOURS'])
    access_token = jwt.encode({
        'user_id': user_id,
        'username': username,
        'full_name': full_name,
        'department': department,
        'clearance_level': clearance_level,
        'type': 'access',
        'exp': access_expiry,
        'iat': datetime.utcnow()
    }, app.config['SECRET_KEY'], algorithm=app.config['JWT_ALGORITHM'])

    refresh_expiry = datetime.utcnow() + timedelta(days=app.config['JWT_REFRESH_EXPIRY_DAYS'])
    refresh_token = jwt.encode({
        'user_id': user_id,
        'username': username,
        'type': 'refresh',
        'exp': refresh_expiry,
        'iat': datetime.utcnow()
    }, app.config['SECRET_KEY'], algorithm=app.config['JWT_ALGORITHM'])

    return access_token, refresh_token, access_expiry


def token_required(f):
    """Decorator to verify JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            emit_event(
                logger, AUTH_TOKEN_MISSING,
                message="Request with no Authorization header",
                http={"method": request.method, "path": request.path},
                source={"ip": request.remote_addr},
            )
            return jsonify({'error': 'Token is missing'}), 401

        if token.startswith('Bearer '):
            token = token[7:]

        try:
            # Check if token is blacklisted
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('SELECT id FROM token_blacklist WHERE token = ?', (token,))
            is_blacklisted = c.fetchone() is not None
            conn.close()

            if is_blacklisted:
                emit_event(
                    logger, AUTH_TOKEN_REVOKED,
                    message="Blacklisted token used",
                    http={"method": request.method, "path": request.path},
                    source={"ip": request.remote_addr},
                )
                return jsonify({'error': 'Token has been revoked'}), 401

            # Decode and verify token
            data = jwt.decode(
                token,
                app.config['SECRET_KEY'],
                algorithms=[app.config['JWT_ALGORITHM']]
            )

            if data.get('type') != 'access':
                emit_event(
                    logger, AUTH_TOKEN_INVALID,
                    message="Token is not an access token",
                    http={"method": request.method, "path": request.path},
                    source={"ip": request.remote_addr},
                )
                return jsonify({'error': 'Invalid token type'}), 401

            request.user = data

            # Update last activity
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''UPDATE user_sessions
                         SET last_activity = CURRENT_TIMESTAMP
                         WHERE jwt_token = ?''', (token,))
            conn.commit()
            conn.close()

        except jwt.ExpiredSignatureError:
            emit_event(
                logger, AUTH_TOKEN_EXPIRED,
                message="Expired token presented",
                http={"method": request.method, "path": request.path},
                source={"ip": request.remote_addr},
            )
            return jsonify({'error': 'Token has expired'}), 401

        except jwt.InvalidTokenError as e:
            emit_event(
                logger, AUTH_TOKEN_INVALID,
                message=f"Invalid token: {e}",
                http={"method": request.method, "path": request.path},
                source={"ip": request.remote_addr},
            )
            return jsonify({'error': f'Invalid token: {str(e)}'}), 401

        return f(*args, **kwargs)
    return decorated


# ─── Trace ID propagation ───────────────────────────────────────────
@app.before_request
def _assign_trace_id():
    """Assign a trace_id to every request, honor inbound X-Trace-Id."""
    incoming = request.headers.get("X-Trace-Id")
    trace_id = incoming or str(uuid.uuid4())
    set_trace_id(trace_id)


@app.after_request
def _echo_trace_id(response):
    """Expose trace_id for correlation across the overlay."""
    tid = get_trace_id()
    if tid:
        response.headers["X-Trace-Id"] = tid
    return response


# Simple CORS - single handler
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin', '')
    if 'localhost' in origin or '127.0.0.1' in origin:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        response.headers['Access-Control-Allow-Origin'] = 'https://localhost:5000'

    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Trace-Id'
    return response


@app.route('/')
def index():
    return render_template('overlay_dashboard.html')


@app.route('/login')
def login_page():
    return render_template('overlay_login.html')


@app.route('/health', methods=['GET'])
@token_required
def gateway_health():
    return jsonify({'status': 'healthy', 'service': 'gateway', 'port': 5000, 'protocol': 'https'})


@app.route('/api/v1/auth/health', methods=['GET'])
def auth_health():
    return jsonify({'status': 'healthy', 'service': 'gateway'})


@app.route('/dashboard')
def dashboard_page():
    token = request.args.get('token')
    if token:
        return render_template('overlay_user_dashboard.html',
                               user=request.user if hasattr(request, 'user') else None,
                               token=token)
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header[7:]
        return render_template('overlay_user_dashboard.html',
                               user=request.user if hasattr(request, 'user') else None,
                               token=token)
    return render_template('overlay_user_dashboard.html', user=None, token=None)


@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """Authenticate user and issue JWT tokens"""
    data = request.json
    username = data.get('username')
    password = data.get('password')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT id, username, password_hash, full_name, department, clearance_level
                 FROM users WHERE username = ? AND is_active = 1''', (username,))
    user = c.fetchone()

    if not user:
        conn.close()
        emit_event(
            logger, AUTH_LOGIN_FAILURE,
            message=f"Login failed: unknown user '{username}'",
            user={"name": username},
            source={"ip": request.remote_addr},
            http={"method": "POST", "path": "/api/v1/auth/login"},
        )
        return jsonify({'error': 'Invalid credentials'}), 401

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if password_hash != user[2]:
        conn.close()
        emit_event(
            logger, AUTH_LOGIN_FAILURE,
            message=f"Login failed: bad password for '{username}'",
            user={"name": username},
            source={"ip": request.remote_addr},
            http={"method": "POST", "path": "/api/v1/auth/login"},
        )
        return jsonify({'error': 'Invalid credentials'}), 401

    access_token, refresh_token, expiry = generate_tokens(
        user_id=user[0],
        username=user[1],
        full_name=user[3],
        department=user[4],
        clearance_level=user[5]
    )

    c.execute('''INSERT INTO user_sessions (user_id, jwt_token, refresh_token, expires_at)
                 VALUES (?, ?, ?, ?)''', (user[0], access_token, refresh_token, expiry))
    conn.commit()
    conn.close()

    # Emit both events — order matters for readability in logs
    emit_event(
        logger, AUTH_LOGIN_SUCCESS,
        message=f"Login success: '{username}'",
        user={"id": user[0], "name": username,
              "department": user[4], "clearance": user[5]},
        source={"ip": request.remote_addr},
    )
    emit_event(
        logger, AUTH_TOKEN_ISSUED,
        message=f"Access token issued for '{username}'",
        user={"id": user[0], "name": username},
        source={"ip": request.remote_addr},
        token={"type": "access", "expires_in_hours": app.config['JWT_EXPIRY_HOURS']},
    )

    return jsonify({
        'status': 'success',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
        'expires_in': app.config['JWT_EXPIRY_HOURS'] * 3600,
        'user': {
            'id': user[0],
            'username': user[1],
            'full_name': user[3],
            'department': user[4],
            'clearance_level': user[5]
        }
    })


@app.route('/api/v1/auth/refresh', methods=['POST'])
def refresh_token():
    """Refresh an expired access token using refresh token"""
    data = request.json
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        return jsonify({'error': 'Refresh token is missing'}), 401

    try:
        data = jwt.decode(
            refresh_token,
            app.config['SECRET_KEY'],
            algorithms=[app.config['JWT_ALGORITHM']]
        )

        if data.get('type') != 'refresh':
            emit_event(
                logger, AUTH_TOKEN_INVALID,
                message="Token is not a refresh token",
                http={"method": request.method, "path": request.path},
                source={"ip": request.remote_addr},
            )
            return jsonify({'error': 'Invalid token type'}), 401

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''SELECT id, username, full_name, department, clearance_level
                     FROM users WHERE id = ? AND is_active = 1''', (data['user_id'],))
        user = c.fetchone()
        conn.close()

        if not user:
            return jsonify({'error': 'User not found'}), 401

        new_access_token, _, new_expiry = generate_tokens(
            user_id=user[0],
            username=user[1],
            full_name=user[2],
            department=user[3],
            clearance_level=user[4]
        )

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''UPDATE user_sessions
                     SET jwt_token = ?, expires_at = ?, last_activity = CURRENT_TIMESTAMP
                     WHERE refresh_token = ?''', (new_access_token, new_expiry, refresh_token))
        conn.commit()
        conn.close()

        emit_event(
            logger, AUTH_TOKEN_REFRESHED,
            message=f"Token refreshed for '{user[1]}'",
            user={"id": user[0], "name": user[1]},
            source={"ip": request.remote_addr},
        )

        return jsonify({
            'access_token': new_access_token,
            'token_type': 'Bearer',
            'expires_in': app.config['JWT_EXPIRY_HOURS'] * 3600
        })

    except jwt.ExpiredSignatureError:
        emit_event(
            logger, AUTH_TOKEN_EXPIRED,
            message="Expired refresh token presented",
            http={"method": request.method, "path": request.path},
            source={"ip": request.remote_addr},
        )
        return jsonify({'error': 'Refresh token has expired, please login again'}), 401
    except jwt.InvalidTokenError as e:
        emit_event(
            logger, AUTH_TOKEN_INVALID,
            message=f"Invalid refresh token: {e}",
            http={"method": request.method, "path": request.path},
            source={"ip": request.remote_addr},
        )
        return jsonify({'error': 'Invalid refresh token'}), 401


@app.route('/api/v1/auth/logout', methods=['POST'])
@token_required
def logout():
    """Logout user - blacklist the token"""
    token = request.headers.get('Authorization')
    if token and token.startswith('Bearer '):
        token = token[7:]

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO token_blacklist (token) VALUES (?)', (token,))
    c.execute('DELETE FROM user_sessions WHERE jwt_token = ?', (token,))
    conn.commit()
    conn.close()

    emit_event(
        logger, AUTH_LOGOUT,
        message=f"User logged out: '{request.user.get('username')}'",
        user={"id": request.user.get("user_id"), "name": request.user.get("username")},
        source={"ip": request.remote_addr},
    )

    return jsonify({'status': 'success', 'message': 'Logged out successfully'})


@app.route('/api/v1/auth/me', methods=['GET'])
@token_required
def get_current_user():
    return jsonify(request.user)


@app.route('/api/v1/auth/verify', methods=['GET'])
@token_required
def verify_token():
    return jsonify({
        'valid': True,
        'user': request.user,
        'expires_at': request.user.get('exp')
    })


@app.route('/api/v1/admin/users', methods=['GET'])
@token_required
def list_users():
    if request.user.get('clearance_level') != 'TOP_SECRET':
        emit_event(
            logger, ADMIN_ACCESS_DENIED,
            message=f"Non-admin attempted to list users: '{request.user.get('username')}'",
            user={"id": request.user.get('user_id'), "name": request.user.get('username'),
                  "clearance": request.user.get('clearance_level')},
            source={"ip": request.remote_addr},
            http={"method": "GET", "path": "/api/v1/admin/users"},
        )
        return jsonify({'error': 'Admin access required'}), 403

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, full_name, department, clearance_level, is_active, created_at FROM users')
    users = c.fetchall()
    conn.close()

    emit_event(
        logger, ADMIN_USER_LISTED,
        message=f"Admin listed all users ({len(users)} records)",
        user={"id": request.user.get('user_id'), "name": request.user.get('username')},
        source={"ip": request.remote_addr},
    )

    return jsonify({
        'users': [
            {
                'id': u[0],
                'username': u[1],
                'full_name': u[2],
                'department': u[3],
                'clearance_level': u[4],
                'is_active': bool(u[5]),
                'created_at': u[6]
            } for u in users
        ]
    })


@app.route('/api/v1/admin/users', methods=['POST'])
@token_required
def create_user():
    if request.user.get('clearance_level') != 'TOP_SECRET':
        emit_event(
            logger, ADMIN_ACCESS_DENIED,
            message=f"Non-admin attempted to create user: '{request.user.get('username')}'",
            user={"id": request.user.get('user_id'), "name": request.user.get('username'),
                  "clearance": request.user.get('clearance_level')},
            source={"ip": request.remote_addr},
            http={"method": "POST", "path": "/api/v1/admin/users"},
        )
        return jsonify({'error': 'Admin access required'}), 403

    data = request.json
    username = data.get('username')
    password = data.get('password')
    full_name = data.get('full_name')
    department = data.get('department')
    clearance_level = data.get('clearance_level', 'BASIC')

    valid_levels = [c['name'] for c in CLEARANCE_LEVELS['clearance_hierarchy']]
    if clearance_level not in valid_levels:
        return jsonify({'error': f'Invalid clearance level. Must be one of: {valid_levels}'}), 400

    valid_depts = [d['id'] for d in DEPARTMENTS['bangladesh_government_departments']]
    if department not in valid_depts:
        return jsonify({'error': f'Invalid department. Must be one of: {valid_depts}'}), 400

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''INSERT INTO users (username, password_hash, full_name, department, clearance_level)
                     VALUES (?, ?, ?, ?, ?)''',
                  (username, password_hash, full_name, department, clearance_level))
        conn.commit()
        user_id = c.lastrowid
        conn.close()

        emit_event(
            logger, ADMIN_USER_CREATED,
            message=f"Admin created user '{username}' ({clearance_level} / {department})",
            user={"id": request.user.get('user_id'), "name": request.user.get('username')},
            source={"ip": request.remote_addr},
            new_user={"name": username, "department": department, "clearance": clearance_level},
        )

        return jsonify({
            'status': 'success',
            'user_id': user_id,
            'message': 'User created successfully'
        })
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Username already exists'}), 400


if __name__ == '__main__':
    host = SERVICE_CONFIG['service']['bind_host']
    port = SERVICE_CONFIG['service']['port']

    cert_path = os.path.join(BASE_DIR, 'certs', 'identities', 'gateway', 'gateway.crt')
    key_path = os.path.join(BASE_DIR, 'certs', 'identities', 'gateway', 'gateway.key')

    if os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_context = (cert_path, key_path)

        emit_event(
            logger, SERVICE_STARTUP,
            message=f"Gateway starting on https://{host}:{port}",
            service={"name": "gateway", "port": port},
        )

        print(f"=" * 60)
        print(f"Gateway Service - HTTPS")
        print(f"=" * 60)
        print(f"  • Binding to: https://{host}:{port}")
        print(f"  • mTLS: Client certificates NOT required (Edge Router handles auth)")
        print(f"=" * 60)
        app.run(host=host, port=port, debug=False, use_reloader=False, ssl_context=ssl_context)
    else:
        print(f"ERROR: Certificates not found at {cert_path}")
        sys.exit(1)