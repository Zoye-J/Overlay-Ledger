"""Simplified Edge Router - HTTPS proxy for ZTA Overlay Network"""
import os
import sys
import yaml
import json
import uuid
import time
import requests
from flask import Flask, request, Response
from flask_cors import CORS
import ssl

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# ─── Structured logging ─────────────────────────────────────────────
from shared.logging_config import setup_logger, set_trace_id, emit_event, get_trace_id
from shared.events import (
    ROUTER_REQUEST_RECEIVED, ROUTER_ROUTE_FORWARDED, ROUTER_ROUTE_BLOCKED,
    ROUTER_TARGET_UNKNOWN, SERVICE_STARTUP,
)

logger = setup_logger("edge_router")

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.yaml')
if not os.path.exists(CONFIG_PATH):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    default_config = {
        'identity': {'name': 'edge-router-01', 'type': 'router'},
        'controller': {'url': 'https://localhost:8080', 'host': 'localhost',
                       'port': 8080, 'heartbeat_interval': 30},
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
        "allow_headers": ["Content-Type", "Authorization", "X-Target-Service", "X-Trace-Id"],
        "supports_credentials": True,
    }
})


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


def _client_ip() -> str:
    """Best-effort client IP extraction (honor XFF from upstream proxies)."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy_all(path):
    """Forward all requests to the appropriate service"""

    if request.method == "OPTIONS":
        response = Response(status=200)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Target-Service, X-Trace-Id'
        return response

    # ─── Resolve target service ──────────────────────────────────
    target_service = request.headers.get('X-Target-Service')
    if not target_service:
        target_service = CONFIG['local']['default_service']

    src_ip = _client_ip()
    start_ts = time.time()

    # ─── Emit request-received (every non-OPTIONS request) ───────
    emit_event(
        logger, ROUTER_REQUEST_RECEIVED,
        message=f"Received {request.method} /{path} -> {target_service}",
        source={"ip": src_ip},
        http={
            "method": request.method,
            "path": f"/{path}" if path else "/",
            "user_agent": request.headers.get("User-Agent", ""),
        },
        target={"service": target_service},
    )

    # ─── Resolve backend URL ─────────────────────────────────────
    service_url = SERVICE_REGISTRY.get(target_service)
    if not service_url:
        emit_event(
            logger, ROUTER_TARGET_UNKNOWN,
            message=f"Unknown target service '{target_service}' requested",
            source={"ip": src_ip},
            http={"method": request.method, "path": f"/{path}" if path else "/"},
            target={"service": target_service, "resolved": False},
        )
        return Response(
            response=json.dumps({'error': f'Unknown service: {target_service}'}),
            status=404,
            mimetype='application/json'
        )

    full_url = f"{service_url}/{path}" if path else service_url

    # ─── Forward request ─────────────────────────────────────────
    try:
        forward_headers = {}
        for k, v in request.headers.items():
            if k.lower() not in ['x-target-service', 'host', 'content-length']:
                forward_headers[k] = v

        # Forward client attribution and trace ID to backend
        forward_headers['X-Forwarded-For'] = src_ip
        forward_headers['X-Trace-Id'] = get_trace_id()

        resp = mtls_session.request(
            method=request.method,
            url=full_url,
            headers=forward_headers,
            data=request.get_data(),
            timeout=30
        )

        latency_ms = round((time.time() - start_ts) * 1000, 2)

        emit_event(
            logger, ROUTER_ROUTE_FORWARDED,
            message=f"Forwarded {request.method} /{path} -> {target_service} "
                    f"[{resp.status_code}, {latency_ms}ms]",
            source={"ip": src_ip},
            http={
                "method": request.method,
                "path": f"/{path}" if path else "/",
                "status_code": resp.status_code,
                "response_time_ms": latency_ms,
            },
            target={"service": target_service, "url": full_url},
        )

        response = Response(resp.content, status=resp.status_code)
        if 'Content-Type' in resp.headers:
            response.headers['Content-Type'] = resp.headers['Content-Type']
        response.headers['Access-Control-Allow-Origin'] = '*'

        return response

    except Exception as e:
        latency_ms = round((time.time() - start_ts) * 1000, 2)
        emit_event(
            logger, ROUTER_ROUTE_BLOCKED,
            message=f"Proxy error forwarding to '{target_service}': {e}",
            source={"ip": src_ip},
            http={
                "method": request.method,
                "path": f"/{path}" if path else "/",
                "response_time_ms": latency_ms,
            },
            target={"service": target_service, "url": full_url},
            error={"type": type(e).__name__, "message": str(e)},
        )
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

    emit_event(
        logger, SERVICE_STARTUP,
        message=f"Edge Router starting on https://0.0.0.0:{CONFIG['local']['proxy_port']}",
        service={"name": "edge_router", "port": CONFIG['local']['proxy_port']},
    )

    if os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_context = (cert_path, key_path)

        app.run(host='0.0.0.0', port=CONFIG['local']['proxy_port'],
                debug=False, use_reloader=False, ssl_context=ssl_context)
    else:
        print("ERROR: Certificates not found")
        sys.exit(1)