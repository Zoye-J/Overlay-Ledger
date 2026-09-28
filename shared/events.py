"""
Canonical event taxonomy for the ZTA Overlay Network.

Every log event emitted by any service must use one of these constants
as its `event.action` field. This gives the SIEM a stable, enumerable set
of event types to write detection rules against.

Naming convention:
    <domain>.<subject>.<outcome>

ATT&CK hints are advisory — used later when mapping detections to techniques
in the ATT&CK Navigator layer. They are NOT enforced at emission time.
"""

# ─── Authentication events ────────────────────────────────────────────────
AUTH_LOGIN_SUCCESS      = "auth.login.success"        # ATT&CK: none (normal)
AUTH_LOGIN_FAILURE      = "auth.login.failure"        # ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts)
AUTH_LOGOUT             = "auth.logout"               # ATT&CK: none (normal)

# ─── Token lifecycle ──────────────────────────────────────────────────────
AUTH_TOKEN_ISSUED       = "auth.token.issued"         # ATT&CK: T1550.001 (Use Alternate Auth Material)
AUTH_TOKEN_REFRESHED    = "auth.token.refreshed"      # ATT&CK: none (normal)
AUTH_TOKEN_REVOKED      = "auth.token.revoked"        # ATT&CK: none (normal)
AUTH_TOKEN_INVALID      = "auth.token.invalid"        # ATT&CK: T1078 (Valid Accounts), T1550 (Alt Auth Material)
AUTH_TOKEN_EXPIRED      = "auth.token.expired"        # ATT&CK: none (normal)
AUTH_TOKEN_MISSING      = "auth.token.missing"        # ATT&CK: none (client error)

# ─── Authorization / policy decisions ─────────────────────────────────────
AUTHZ_POLICY_ALLOWED       = "authz.policy.allowed"        # ATT&CK: none (normal)
AUTHZ_POLICY_DENIED        = "authz.policy.denied"         # ATT&CK: T1078, T1134 (Access Token Manipulation)
AUTHZ_CLEARANCE_DENIED     = "authz.clearance.denied"      # ATT&CK: T1078, T1548 (Abuse Elevation Control)
AUTHZ_DEPARTMENT_DENIED    = "authz.department.denied"     # ATT&CK: T1078
AUTHZ_BUSINESS_HOURS_DENIED = "authz.business_hours.denied" # ATT&CK: none (policy enforcement)

# ─── Edge Router / overlay traffic ────────────────────────────────────────
ROUTER_REQUEST_RECEIVED = "router.request.received"   # ATT&CK: T1190 (Exploit Public-Facing App)
ROUTER_ROUTE_FORWARDED  = "router.route.forwarded"    # ATT&CK: none (normal)
ROUTER_ROUTE_BLOCKED    = "router.route.blocked"      # ATT&CK: T1190, T1090 (Proxy)
ROUTER_TARGET_UNKNOWN   = "router.target.unknown"     # ATT&CK: T1190, T1046 (Network Service Discovery)

# ─── Service health ───────────────────────────────────────────────────────
SERVICE_HEALTH_OK       = "service.health.ok"         # ATT&CK: none
SERVICE_STARTUP         = "service.startup"           # ATT&CK: none

# ─── Admin actions ────────────────────────────────────────────────────────
ADMIN_USER_CREATED      = "admin.user.created"        # ATT&CK: T1136 (Create Account)
ADMIN_USER_LISTED       = "admin.user.listed"         # ATT&CK: T1087 (Account Discovery)
ADMIN_ACCESS_DENIED     = "admin.access.denied"       # ATT&CK: T1078, T1548