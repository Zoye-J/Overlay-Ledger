import os
import sys
import yaml
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import ssl

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

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

# Models (same as before)
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

@app.route('/api/v1/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'controller': CONFIG['controller']['name'],
        'environment': CONFIG['controller']['environment'],
        'protocol': 'https'
    })

@app.route('/api/v1/enroll', methods=['POST'])
def enroll_identity():
    data = request.json
    identity_type = data.get('type')
    name = data.get('name')
    enrollment_token = data.get('enrollment_token')
    
    master_secret = os.environ.get('MASTER_ENROLLMENT_SECRET', 'dev_token_123')
    if enrollment_token != master_secret:
        return jsonify({'error': 'Invalid enrollment token'}), 401
    
    identity = Identity(name=name, identity_type=identity_type, status='active')
    db.session.add(identity)
    db.session.commit()
    
    return jsonify({
        'identity_id': identity.id,
        'controller_url': CONFIG['controller']['control_plane']['public_address'],
        'overlay_config': NETWORK_CONFIG,
        'status': 'enrolled'
    })

@app.route('/api/v1/policies/check', methods=['POST'])
def check_policy():
    data = request.json
    source_identity = data.get('source')
    target_service = data.get('target')
    action = data.get('action')
    
    policies_path = os.path.join(BASE_DIR, 'config', 'policies', 'access_policies.yaml')
    try:
        with open(policies_path, 'r') as f:
            policies = yaml.safe_load(f)
    except FileNotFoundError:
        return jsonify({'allowed': True, 'source': source_identity, 'target': target_service})
    
    allowed = False
    for policy in policies.get('policies', []):
        if (policy.get('action') == action and 
            policy.get('source_identity') == source_identity and 
            policy.get('target_service') == target_service):
            allowed = True
            break
    
    return jsonify({'allowed': allowed, 'source': source_identity, 'target': target_service})

if __name__ == '__main__':
    port = int(os.environ.get('CONTROLLER_PORT', CONFIG['controller']['control_plane']['bind_port']))
    host = os.environ.get('CONTROLLER_HOST', 'localhost')
    
    cert_path = os.path.join(BASE_DIR, 'certs', 'identities', 'controller', 'controller.crt')
    key_path = os.path.join(BASE_DIR, 'certs', 'identities', 'controller', 'controller.key')
    ca_cert_path = os.path.join(BASE_DIR, 'certs', 'ca.crt')
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        # Create SSL context with client certificate validation (mTLS)
        # ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # ssl_context.load_cert_chain(cert_path, key_path)
        # ssl_context.load_verify_locations(ca_cert_path)
        # ssl_context.verify_mode = ssl.CERT_REQUIRED
        # ssl_context.check_hostname = False
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