"""
Atomic attack harness for the ZTA Overlay Network.

Runs controlled, safe attack simulations against the running ZTA and
generates the log patterns our Sigma rules are designed to detect.

Attacks implemented:
    T1110.003   Password Spraying    -> 6 bad logins for one user (rule: t1110)
    T1078       Valid Accounts       -> 3 invalid tokens + 3 clearance attempts (rule: t1078)
    T1190/T1046 Edge Probing         -> 6 unknown-target requests + suspicious paths (rule: t1190)

Usage:
    python -m detections.atomic.run               # run all attacks
    python -m detections.atomic.run --attack t1110
    python -m detections.atomic.run --dry-run     # print actions, no HTTP

Design notes:
- Uses `requests` with verify=False (self-signed CA on the Edge Router)
- All HTTP goes through the Edge Router on https://localhost:9999
- Each attack runs at maximum speed to generate events within a tight
  window, which is what the Sigma aggregation is designed to catch
- Does NOT modify any ZTA state beyond log entries (login attempts fail,
  token abuse never gets past JWT verification, edge probes are 404s)
"""

import argparse
import sys
import time
from datetime import datetime

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROUTER = "https://localhost:9999"


# ─── Helpers ─────────────────────────────────────────────────────────

def post(path: str, service: str, json_body: dict | None = None,
         headers: dict | None = None, dry_run: bool = False) -> requests.Response | None:
    """POST through the Edge Router."""
    h = {"X-Target-Service": service, "Content-Type": "application/json"}
    if headers:
        h.update(headers)

    if dry_run:
        print(f"    [dry-run] POST {path} via {service} body={json_body}")
        return None

    try:
        return requests.post(f"{ROUTER}{path}", json=json_body, headers=h,
                             verify=False, timeout=5)
    except requests.RequestException as e:
        print(f"    [!] Request failed: {e}")
        return None


def get(path: str, service: str, headers: dict | None = None,
        dry_run: bool = False) -> requests.Response | None:
    """GET through the Edge Router."""
    h = {"X-Target-Service": service}
    if headers:
        h.update(headers)

    if dry_run:
        print(f"    [dry-run] GET {path} via {service}")
        return None

    try:
        return requests.get(f"{ROUTER}{path}", headers=h,
                            verify=False, timeout=5)
    except requests.RequestException as e:
        print(f"    [!] Request failed: {e}")
        return None


# ─── Attacks ─────────────────────────────────────────────────────────

def attack_t1110_password_spray(dry_run: bool = False) -> None:
    """
    T1110.003 — Password Spraying.
    Sends 6 bad-password login attempts for a single user.
    Sigma rule t1110 (5 in 60s) will fire.
    """
    print("  [T1110.003] Password spray — 6 bad logins for 'intelligence_officer'")
    for i in range(1, 7):
        post("/api/v1/auth/login", "gateway",
             json_body={"username": "intelligence_officer",
                        "password": f"guess-{i}"},
             dry_run=dry_run)
        # Small jitter — real attackers don't hammer; they pace
        if not dry_run:
            time.sleep(0.5)


def attack_t1078_token_abuse(dry_run: bool = False) -> None:
    """
    T1078 — Valid Accounts.
    Sends 3 invalid tokens, then 3 requests that will trigger clearances denials.
    Sigma rule t1078 (3 in 120s) will fire.
    """
    print("  [T1078] Token abuse — 3 invalid JWTs + 3 unauthorized doc requests")

    # Pattern 1: invalid tokens
    for i in range(1, 4):
        get("/api/v1/auth/me", "gateway",
            headers={"Authorization": f"Bearer not-a-real-token-{i}"},
            dry_run=dry_run)
        if not dry_run:
            time.sleep(0.3)

    # Pattern 2: valid login then immediate clearance-denied access attempt
    # (a real attack pattern: stolen token + escalation attempt)
    if not dry_run:
        r = post("/api/v1/auth/login", "gateway",
                 json_body={"username": "intelligence_officer",
                            "password": "password123"})
        if r and r.status_code == 200:
            token = r.json().get("access_token")
            # Try to access a document ID that doesn't belong to this user
            # For our data, doc 4 is TOP_SECRET/Intelligence (allowed),
            # so we probe doc IDs that likely don't exist or aren't visible.
            for doc_id in (999, 998, 997):
                get(f"/api/v1/documents/{doc_id}", "api_server",
                    headers={"Authorization": f"Bearer {token}"})
                time.sleep(0.3)
    else:
        print("    [dry-run] POST /api/v1/auth/login (valid creds)")
        for doc_id in (999, 998, 997):
            print(f"    [dry-run] GET /api/v1/documents/{doc_id} with valid token")


def attack_t1190_edge_probing(dry_run: bool = False) -> None:
    """
    T1190 / T1046 — Exploit Public-Facing App / Network Service Discovery.
    Sends 6 probe requests: 3 unknown targets + 3 suspicious paths.
    Sigma rule t1190 (3 in 60s) will fire.
    """
    print("  [T1190/T1046] Edge probing — 6 probes (unknown targets + suspicious paths)")

    # Pattern 1: unknown target services
    for svc in ("admin_portal", "internal_api", "backup_db"):
        get("/api/v1/health", svc, dry_run=dry_run)
        if not dry_run:
            time.sleep(0.3)

    # Pattern 2: suspicious paths on the default (gateway) target
    for path in ("/.env", "/admin", "/phpmyadmin"):
        get(path, "gateway", dry_run=dry_run)
        if not dry_run:
            time.sleep(0.3)


# ─── Main ────────────────────────────────────────────────────────────

ATTACKS = {
    "t1110": attack_t1110_password_spray,
    "t1078": attack_t1078_token_abuse,
    "t1190": attack_t1190_edge_probing,
}


def main():
    parser = argparse.ArgumentParser(description="ZTA Atomic attack harness")
    parser.add_argument("--attack", choices=list(ATTACKS.keys()),
                        help="Run only this attack")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print actions without sending HTTP")
    args = parser.parse_args()

    print("=" * 60)
    print("ZTA Atomic Attack Harness")
    print("=" * 60)
    print(f"Target: {ROUTER}")
    print(f"Started: {datetime.now().isoformat(timespec='seconds')}")
    print()

    if args.dry_run:
        print("[!] DRY RUN — no HTTP requests will be sent\n")

    targets = [args.attack] if args.attack else list(ATTACKS.keys())

    for name in targets:
        start = time.time()
        try:
            ATTACKS[name](dry_run=args.dry_run)
        except Exception as e:
            print(f"  [!] Attack '{name}' raised: {e}")
        elapsed = time.time() - start
        print(f"  [done] {name} completed in {elapsed:.1f}s\n")

    print("=" * 60)
    print("Atomic attacks complete.")
    print("Run the harness to see which rules fired:")
    print("  python -m detections.harness --verbose")
    print("=" * 60)


if __name__ == "__main__":
    main()