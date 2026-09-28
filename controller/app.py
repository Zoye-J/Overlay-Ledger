import os
import sys
import yaml
import uuid
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import ssl

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# ─── Structured logging ─────────────────────────────────────────────
from shared.logging_config import setup_logger, set_trace_id, emit_event, get_trace_id
from shared.events import (
    AUTHZ_POLICY_ALLOWED, AUTHZ_POLICY_DENIED,
    SERVICE_STARTUP, SERVICE_HEALTH_OK,
)

logger = setup_logger("controller")

load_dotenv()

CONFIG_PATH = os.path.join(BASE_DIR, 'config', 'controller_config.yaml')
with open(CONFIG_PATH, 'r') as f:
    CONFIG = yaml.safe_load(f)

NETWORK_CONFIG_PATH = os.path.join(BASE_DIR, 'config', 'network_config.yaml')
with open(NETWORK_CONFIG_PATH, 'r') as f:
    NETWORK_CONFIG = yaml.safe_load(f)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

database_path = os.path.join(BASE_DIR, CONFIG['controller']['database']['path'])
os.makedirs(os.path.dirname(database_path), exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{database_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# ─── Models ─────────────────────────────────────────────────────────

class Identity(db.Model):
    __tablename__ = 'identities'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    identity_type = db.Column(db.String(20), nullable=False)
    certificate_serial = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    last_seen = db.Column(db.DateTime)


class ServicePolicy(db.Model):
    __tablename__ = 'service_policies'
    id = db.Column(db.Integer, primary_key=True)
    identity_id = db.Column(db.Integer, db.ForeignKey('identities.id'))
    target_service = db.Column(db.String(100))
    action = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    conditions = db.Column(db.JSON)


with app.app_context():
    db.create_all()


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


# ─── Routes ─────────────────────────────────────────────────────────

@app.route('/api/v1/health', methods=['GET'])
def health():
    emit_event(
        logger, SERVICE_HEALTH_OK,
        message="Controller health check OK",
        source={"ip": request.remote_addr},
        http={"method": "GET", "path": request.path},
    )
    return jsonify({
        'status': 'healthy',
        'controller': CONFIG['controller']['name'],
        'environment': CONFIG['controller']['environment'],
        'protocol': 'https'
    })


@app.route('/api/v1/enroll', methods=['POST'])
def enroll_identity():
    """Enroll a new identity (service or client) with the overlay."""
    data = request.json or {}
    identity_type = data.get('type')
    name = data.get('name')
    enrollment_token = data.get('enrollment_token')

    master_secret = os.environ.get('MASTER_ENROLLMENT_SECRET', 'dev_token_123')

    if enrollment_token != master_secret:
        emit_event(
            logger, AUTHZ_POLICY_DENIED,
            message=f"Enrollment denied: bad token for identity '{name}' (type={identity_type})",
            source={"ip": request.remote_addr},
            http={"method": "POST", "path": request.path},
            identity={"name": name, "type": identity_type},
            reason="invalid_enrollment_token",
        )
        return jsonify({'error': 'Invalid enrollment token'}), 401

    identity = Identity(name=name, identity_type=identity_type, status='active')
    db.session.add(identity)
    db.session.commit()

    emit_event(
        logger, AUTHZ_POLICY_ALLOWED,
        message=f"Identity enrolled: '{name}' (type={identity_type}, id={identity.id})",
        source={"ip": request.remote_addr},
        http={"method": "POST", "path": request.path},
        identity={"id": identity.id, "name": name, "type": identity_type,
                  "status": "active"},
    )

    return jsonify({
        'identity_id': identity.id,
        'controller_url': CONFIG['controller']['control_plane']['public_address'],
        'overlay_config': NETWORK_CONFIG,
        'status': 'enrolled'
    })


@app.route('/api/v1/policies/check', methods=['POST'])
def check_policy():
    """Policy Decision Point — called by Edge Router on every request."""
    data = request.json or {}
    source_identity = data.get('source')
    target_service = data.get('target')
    action = data.get('action')

    policies_path = os.path.join(BASE_DIR, 'config', 'policies', 'access_policies.yaml')

    try:
        with open(policies_path, 'r') as f:
            policies = yaml.safe_load(f)
    except FileNotFoundError:
        # FAIL CLOSED — a missing policy file means we cannot make a decision,
        # so we deny. This is the only correct behavior for a PDP.
        emit_event(
            logger, AUTHZ_POLICY_DENIED,
            message=f"Policy file missing at '{policies_path}'; denying request "
                    f"{source_identity} -> {target_service} ({action})",
            source={"ip": request.remote_addr},
            http={"method": "POST", "path": request.path},
            policy={"source": source_identity, "target": target_service,
                    "action": action, "matched": None,
                    "reason": "policy_file_missing"},
            severity="high",
        )
        return jsonify({
            'allowed': False,
            'source': source_identity,
            'target': target_service,
            'error': 'Policy engine unavailable'
        }), 503

    except yaml.YAMLError as e:
        # Policy file exists but is malformed — also fail closed.
        emit_event(
            logger, AUTHZ_POLICY_DENIED,
            message=f"Policy file at '{policies_path}' is malformed: {e}; denying request",
            source={"ip": request.remote_addr},
            http={"method": "POST", "path": request.path},
            policy={"source": source_identity, "target": target_service,
                    "action": action, "matched": None,
                    "reason": "policy_file_malformed"},
            severity="high",
        )
        return jsonify({
            'allowed': False,
            'source': source_identity,
            'target': target_service,
            'error': 'Policy engine unavailable'
        }), 503

    matched_policy = None
    for policy in policies.get('policies', []):
        if (policy.get('action') == action
                and policy.get('source_identity') == source_identity
                and policy.get('target_service') == target_service):
            matched_policy = policy
            break

    allowed = matched_policy is not None

    if allowed:
        emit_event(
            logger, AUTHZ_POLICY_ALLOWED,
            message=f"Policy ALLOW: {source_identity} -> {target_service} ({action}) "
                    f"[{matched_policy.get('name')}]",
            source={"ip": request.remote_addr},
            http={"method": "POST", "path": request.path},
            policy={"source": source_identity, "target": target_service,
                    "action": action, "matched": matched_policy.get('name'),
                    "policy_id": matched_policy.get('policy_id')},
        )
    else:
        emit_event(
            logger, AUTHZ_POLICY_DENIED,
            message=f"Policy DENY: {source_identity} -> {target_service} ({action})",
            source={"ip": request.remote_addr},
            http={"method": "POST", "path": request.path},
            policy={"source": source_identity, "target": target_service,
                    "action": action, "matched": None},
            reason="no_matching_policy",
        )

    return jsonify({'allowed': allowed, 'source': source_identity, 'target': target_service})


if __name__ == '__main__':
    port = int(os.environ.get('CONTROLLER_PORT', CONFIG['controller']['control_plane']['bind_port']))
    host = os.environ.get('CONTROLLER_HOST', 'localhost')

    cert_path = os.path.join(BASE_DIR, 'certs', 'identities', 'controller', 'controller.crt')
    key_path = os.path.join(BASE_DIR, 'certs', 'identities', 'controller', 'controller.key')

    emit_event(
        logger, SERVICE_STARTUP,
        message=f"Controller starting on https://{host}:{port}",
        service={"name": "controller", "port": port,
                 "environment": CONFIG['controller']['environment']},
    )

    if os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_context = (cert_path, key_path)

        print("=" * 60)
        print("ZTA Controller - HTTPS with mTLS")
        print("=" * 60)
        print(f"Running on: https://{host}:{port}")
        print(f"mTLS: ENABLED")
        print("=" * 60)

        app.run(host=host, port=port, debug=False, use_reloader=False, ssl_context=ssl_context)
    else:
        print(f"ERROR: Certificates not found at {cert_path}")
        sys.exit(1)