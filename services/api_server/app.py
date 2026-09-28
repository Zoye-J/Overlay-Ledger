#!/usr/bin/env python
"""Zitified API Server - Handles business logic and database operations"""
import os
import sys
import ssl
import yaml
import sqlite3
import json
import uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
import jwt
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE_DIR)

# ─── Structured logging ─────────────────────────────────────────────
from shared.logging_config import setup_logger, set_trace_id, emit_event, get_trace_id
from shared.events import (
    AUTH_TOKEN_INVALID, AUTH_TOKEN_EXPIRED, AUTH_TOKEN_MISSING,
    AUTHZ_POLICY_ALLOWED, AUTHZ_POLICY_DENIED,
    AUTHZ_CLEARANCE_DENIED, AUTHZ_DEPARTMENT_DENIED, AUTHZ_BUSINESS_HOURS_DENIED,
    SERVICE_STARTUP,
)

logger = setup_logger("api_server")

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.yaml')
with open(CONFIG_PATH, 'r') as f:
    SERVICE_CONFIG = yaml.safe_load(f)

# Load clearance levels
CLEARANCE_PATH = os.path.join(BASE_DIR, 'config', 'policies', 'clearance_levels.yaml')
with open(CLEARANCE_PATH, 'r') as f:
    CLEARANCE_LEVELS = yaml.safe_load(f)

# Create hierarchy map
CLEARANCE_HIERARCHY = {c['name']: c['level'] for c in CLEARANCE_LEVELS['clearance_hierarchy']}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Database
DB_PATH = os.path.join(BASE_DIR, 'database', 'api.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS documents
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  content TEXT NOT NULL,
                  classification TEXT NOT NULL,
                  department TEXT NOT NULL,
                  author_id INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS access_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  document_id INTEGER NOT NULL,
                  action TEXT NOT NULL,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()


init_db()


# ─── Trace ID propagation ───────────────────────────────────────────
@app.before_request
def _assign_trace_id():
    incoming = request.headers.get("X-Trace-Id")
    trace_id = incoming or str(uuid.uuid4())
    set_trace_id(trace_id)


@app.after_request
def _echo_trace_id(response):
    tid = get_trace_id()
    if tid:
        response.headers["X-Trace-Id"] = tid
    return response


def verify_token(token):
    """Verify JWT token - Accept user JWTs"""
    if not token:
        return None
    try:
        if token.startswith('Bearer '):
            token = token[7:]

        payload = jwt.decode(
            token,
            app.config['SECRET_KEY'],
            algorithms=['HS256'],
            options={'verify_exp': True}
        )

        if payload.get('type') != 'access':
            emit_event(
                logger, AUTH_TOKEN_INVALID,
                message=f"Token type '{payload.get('type')}' is not 'access'",
                http={"method": request.method, "path": request.path},
                source={"ip": request.remote_addr},
                user={"name": payload.get("username")},
            )
            return None

        return payload

    except jwt.ExpiredSignatureError:
        emit_event(
            logger, AUTH_TOKEN_EXPIRED,
            message="Expired token presented to API server",
            http={"method": request.method, "path": request.path},
            source={"ip": request.remote_addr},
        )
        return None
    except jwt.InvalidTokenError as e:
        emit_event(
            logger, AUTH_TOKEN_INVALID,
            message=f"Invalid JWT: {e}",
            http={"method": request.method, "path": request.path},
            source={"ip": request.remote_addr},
        )
        return None


def token_required(f):
    """Decorator to verify JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '')

        if not token:
            emit_event(
                logger, AUTH_TOKEN_MISSING,
                message="Request with no Authorization header",
                http={"method": request.method, "path": request.path},
                source={"ip": request.remote_addr},
            )
            return jsonify({'error': 'Invalid or expired token'}), 401

        user = verify_token(token)
        if not user:
            return jsonify({'error': 'Invalid or expired token'}), 401

        request.user = user
        return f(*args, **kwargs)
    return decorated


@app.route('/api/v1/auth/me', methods=['GET'])
@token_required
def get_current_user():
    return jsonify({
        'user_id': request.user.get('user_id'),
        'username': request.user.get('username'),
        'full_name': request.user.get('full_name'),
        'department': request.user.get('department'),
        'clearance_level': request.user.get('clearance_level')
    })


@app.route('/api/v1/auth/verify', methods=['GET'])
@token_required
def verify_token_endpoint():
    return jsonify({
        'valid': True,
        'user': request.user,
        'expires_at': request.user.get('exp')
    })


@app.route('/api/v1/documents', methods=['GET'])
@token_required
def get_documents():
    """Get documents accessible to user (list endpoint — summary view)"""
    user = request.user
    user_clearance = user.get('clearance_level', 'BASIC')
    user_dept = user.get('department', 'General')
    username = user.get('username')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, title, classification, department, created_at FROM documents')
    all_docs = c.fetchall()
    conn.close()

    docs = []
    denied_clearance = 0
    denied_department = 0

    for doc in all_docs:
        doc_id, title, doc_clearance, doc_dept, created_at = doc

        if CLEARANCE_HIERARCHY.get(user_clearance, 0) < CLEARANCE_HIERARCHY.get(doc_clearance, 0):
            denied_clearance += 1
            continue

        if doc_dept == 'General' or doc_dept == user_dept:
            docs.append({
                'id': doc_id,
                'title': title,
                'classification': doc_clearance,
                'department': doc_dept,
                'created_at': created_at
            })
        else:
            denied_department += 1

    emit_event(
        logger, AUTHZ_POLICY_ALLOWED,
        message=f"Listed documents for '{username}': {len(docs)} returned, "
                f"{denied_clearance} filtered by clearance, {denied_department} by department",
        user={"id": user.get("user_id"), "name": username,
              "clearance": user_clearance, "department": user_dept},
        source={"ip": request.remote_addr},
        http={"method": "GET", "path": request.path},
        result={"returned": len(docs),
                "filtered_clearance": denied_clearance,
                "filtered_department": denied_department},
    )

    return jsonify({'documents': docs})


@app.route('/api/v1/documents/<int:doc_id>', methods=['GET'])
@token_required
def get_document(doc_id):
    """Get specific document — full access control enforcement"""
    user = request.user
    user_clearance = user.get('clearance_level', 'BASIC')
    user_dept = user.get('department', 'General')
    username = user.get('username')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, title, content, classification, department, created_at FROM documents WHERE id = ?', (doc_id,))
    doc = c.fetchone()
    conn.close()

    if not doc:
        emit_event(
            logger, AUTHZ_POLICY_DENIED,
            message=f"Document {doc_id} not found (requested by '{username}')",
            user={"id": user.get("user_id"), "name": username,
                  "clearance": user_clearance, "department": user_dept},
            source={"ip": request.remote_addr},
            http={"method": "GET", "path": request.path},
            target={"document_id": doc_id},
            reason="not_found",
        )
        return jsonify({'error': 'Document not found'}), 404

    doc_id, title, content, doc_clearance, doc_dept, created_at = doc

    # ─── Clearance check ─────────────────────────────────────────
    if CLEARANCE_HIERARCHY.get(user_clearance, 0) < CLEARANCE_HIERARCHY.get(doc_clearance, 0):
        emit_event(
            logger, AUTHZ_CLEARANCE_DENIED,
            message=f"Clearance denied: '{username}' ({user_clearance}) "
                    f"attempted document {doc_id} ({doc_clearance})",
            user={"id": user.get("user_id"), "name": username,
                  "clearance": user_clearance, "department": user_dept},
            source={"ip": request.remote_addr},
            http={"method": "GET", "path": request.path},
            target={"document_id": doc_id, "classification": doc_clearance,
                    "department": doc_dept, "title": title},
            reason="insufficient_clearance",
        )
        return jsonify({'error': 'Insufficient clearance'}), 403

    # ─── Department check ────────────────────────────────────────
    if doc_dept != 'General' and doc_dept != user_dept:
        emit_event(
            logger, AUTHZ_DEPARTMENT_DENIED,
            message=f"Department denied: '{username}' ({user_dept}) "
                    f"attempted document {doc_id} ({doc_dept})",
            user={"id": user.get("user_id"), "name": username,
                  "clearance": user_clearance, "department": user_dept},
            source={"ip": request.remote_addr},
            http={"method": "GET", "path": request.path},
            target={"document_id": doc_id, "classification": doc_clearance,
                    "department": doc_dept, "title": title},
            reason="department_mismatch",
        )
        return jsonify({'error': f'Access denied. Restricted to {doc_dept} department.'}), 403

    # ─── Business hours check (TOP_SECRET only) ──────────────────
    if doc_clearance == 'TOP_SECRET':
        current_hour = datetime.now().hour
        business_start = int(os.environ.get('BUSINESS_HOURS_START', 8))
        business_end = int(os.environ.get('BUSINESS_HOURS_END', 16))
        if current_hour < business_start or current_hour >= business_end:
            emit_event(
                logger, AUTHZ_BUSINESS_HOURS_DENIED,
                message=f"Business hours denied: '{username}' attempted TOP_SECRET "
                        f"document {doc_id} at {current_hour:02d}:00 (window {business_start}-{business_end})",
                user={"id": user.get("user_id"), "name": username,
                      "clearance": user_clearance, "department": user_dept},
                source={"ip": request.remote_addr},
                http={"method": "GET", "path": request.path},
                target={"document_id": doc_id, "classification": doc_clearance,
                        "department": doc_dept, "title": title},
                reason="outside_business_hours",
                time={"current_hour": current_hour,
                      "window_start": business_start,
                      "window_end": business_end},
            )
            return jsonify({'error': 'TOP_SECRET documents only accessible during business hours (8 AM - 4 PM)'}), 403

    # ─── Access granted ──────────────────────────────────────────
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO access_logs (user_id, document_id, action) VALUES (?, ?, ?)',
              (user.get('user_id'), doc_id, 'read'))
    conn.commit()
    conn.close()

    emit_event(
        logger, AUTHZ_POLICY_ALLOWED,
        message=f"Document access granted: '{username}' read document {doc_id}",
        user={"id": user.get("user_id"), "name": username,
              "clearance": user_clearance, "department": user_dept},
        source={"ip": request.remote_addr},
        http={"method": "GET", "path": request.path},
        target={"document_id": doc_id, "classification": doc_clearance,
                "department": doc_dept, "title": title},
    )

    return jsonify({
        'id': doc_id,
        'title': title,
        'content': content,
        'classification': doc_clearance,
        'department': doc_dept,
        'created_at': created_at,
        'encrypted': False
    })


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'api_server'})


if __name__ == '__main__':
    host = SERVICE_CONFIG['service']['bind_host']
    port = SERVICE_CONFIG['service']['port']

    cert_path = os.path.join(BASE_DIR, 'certs', 'identities', 'api-server', 'api-server.crt')
    key_path = os.path.join(BASE_DIR, 'certs', 'identities', 'api-server', 'api-server.key')

    emit_event(
        logger, SERVICE_STARTUP,
        message=f"API Server starting on https://{host}:{port}",
        service={"name": "api_server", "port": port},
    )

    if os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_context = (cert_path, key_path)
        print(f"API Server starting on https://{host}:{port}")
        app.run(host=host, port=port, debug=False, use_reloader=False, ssl_context=ssl_context)
    else:
        print(f"API Server starting on http://{host}:{port}")
        app.run(host=host, port=port, debug=False, use_reloader=False)