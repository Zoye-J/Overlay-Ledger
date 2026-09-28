"""Simplified Edge Router - HTTPS proxy for ZTA Overlay Network"""
import os
import sys
import yaml
import json
import requests
from flask import Flask, request, Response
from flask_cors import CORS
import ssl

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.yaml')
if not os.path.exists(CONFIG_PATH):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    default_config = {
        'identity': {'name': 'edge-router-01', 'type': 'router'},
        'controller': {'url': 'https://localhost:8080', 'host': 'localhost', 'port': 8080, 'heartbeat_interval': 30},
        'local': {'proxy_port': 9999, 'default_service': 'gateway'}
    }
    with open(CONFIG_PATH, 'w') as f:
        yaml.dump(default_config, f, default_flow_style=False)

with open(CONFIG_PATH, 'r') as f:
    CONFIG = yaml.safe_load(f)

SERVICE_REGISTRY = {
    'gateway': 'https://127.0.0.1:5000',
    'api_server': 'https://127.0.0.1:5001',
    'opa_agent': 'https://127.0.0.1:8282',
    'dashboard': 'https://127.0.0.1:5002'
}

CA_CERT_PATH = os.path.join(BASE_DIR, 'certs', 'ca.crt')

app = Flask(__name__)

CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        "allow_headers": ["Content-Type", "Authorization", "X-Target-Service"],
        "supports_credentials": True,
    }
})

# Create session with client certificate for mTLS to backend services
def create_mtls_session():
    """Create a session with client certificate for service-to-service communication"""
    session = requests.Session()
    
    client_cert_path = os.path.join(BASE_DIR, 'certs', 'identities', 'gateway', 'gateway.crt')
    client_key_path = os.path.join(BASE_DIR, 'certs', 'identities', 'gateway', 'gateway.key')
    
    if os.path.exists(client_cert_path) and os.path.exists(client_key_path):
        session.cert = (client_cert_path, client_key_path)
    
    session.verify = False  # Allow self-signed certs for internal services
    return session

mtls_session = create_mtls_session()

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy_all(path):
    """Forward all requests to the appropriate service"""
    
    if request.method == "OPTIONS":
        response = Response(status=200)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Target-Service'
        return response
    
    target_service = request.headers.get('X-Target-Service')
    if not target_service:
        target_service = CONFIG['local']['default_service']
    
    print(f"[Edge Router] Proxying {request.method} /{path} -> {target_service}")
    
    service_url = SERVICE_REGISTRY.get(target_service)
    if not service_url:
        return Response(
            response=json.dumps({'error': f'Unknown service: {target_service}'}),
            status=404,
            mimetype='application/json'
        )
    
    full_url = f"{service_url}/{path}" if path else service_url
    
    try:
        forward_headers = {}
        for k, v in request.headers.items():
            if k.lower() not in ['x-target-service', 'host', 'content-length']:
                forward_headers[k] = v
        
        # Use mTLS session for outgoing requests to services
        resp = mtls_session.request(
            method=request.method,
            url=full_url,
            headers=forward_headers,
            data=request.get_data(),
            timeout=30
        )
        
        response = Response(resp.content, status=resp.status_code)
        if 'Content-Type' in resp.headers:
            response.headers['Content-Type'] = resp.headers['Content-Type']
        response.headers['Access-Control-Allow-Origin'] = '*'
        
        return response
        
    except Exception as e:
        print(f"[Edge Router] Proxy error: {e}")
        return Response(
            response=json.dumps({'error': str(e)}),
            status=500,
            mimetype='application/json'
        )

@app.route('/health', methods=['GET'])
def health():
    return Response(
        response=json.dumps({
            'status': 'healthy',
            'services': list(SERVICE_REGISTRY.keys())
        }),
        status=200,
        mimetype='application/json'
    )

if __name__ == '__main__':
    print("=" * 60)
    print("ZTA Edge Router - HTTPS Proxy")
    print("=" * 60)
    print(f"Listening on: https://0.0.0.0:{CONFIG['local']['proxy_port']}")
    print("  • Browser connections: HTTPS (no client certificate required)")
    print("  • Backend connections: mTLS (client certificate sent)")
    print("=" * 60)
    
    cert_path = os.path.join(BASE_DIR, 'certs', 'identities', 'gateway', 'gateway.crt')
    key_path = os.path.join(BASE_DIR, 'certs', 'identities', 'gateway', 'gateway.key')
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        # Simple SSL context - NO client certificate required from browsers
        ssl_context = (cert_path, key_path)
        
        app.run(host='0.0.0.0', port=CONFIG['local']['proxy_port'], 
                debug=False, use_reloader=False, ssl_context=ssl_context)
    else:
        print("ERROR: Certificates not found")
        sys.exit(1)