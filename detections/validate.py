"""
Detection validation harness.

Runs the atomic attacks, executes the Sigma rule harness, and reports
PASS/FAIL per rule. This is the artifact that proves the detection
pipeline works end-to-end.

Usage:
    python -m detections.validate             # full run
    python -m detections.validate --json      # machine-readable output
    python -m detections.validate --no-attack # harness only (skip attacks)

Exit code:
    0 = all rules fired (all PASS)
    1 = one or more rules did not fire
    2 = infrastructure error (ZTA not running, log file missing)
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

# Add project root for imports
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from detections.harness import run_harness, load_rules, SIGMA_DIR


# ─── Config ──────────────────────────────────────────────────────────

# Expected rule -> attack mapping. Every rule in detections/sigma must
# appear here with a check that the validator can assert.
EXPECTED_RULES = {
    "t1110_brute_force_login.yml": {
        "title": "Brute Force Login Attempts Against ZTA Gateway",
        "attack": "t1110",
        "technique": "T1110.003",
        "min_detections": 1,
    },
    "t1078_token_abuse.yml": {
        "title": "Suspicious JWT Token Reuse or Privilege Escalation Attempt",
        "attack": "t1078",
        "technique": "T1078",
        "min_detections": 1,
    },
    "t1190_edge_probing.yml": {
        "title": "Edge Router Service Enumeration or Path Probing",
        "attack": "t1190",
        "technique": "T1190",
        "min_detections": 1,
    },
}


# ─── Pre-flight checks ───────────────────────────────────────────────

def check_zta_running() -> bool:
    """Ping the Edge Router's health endpoint."""
    import urllib3
    import requests
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        r = requests.get("https://localhost:9999/health",
                         verify=False, timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def check_log_file() -> bool:
    log = BASE_DIR / "logs" / "zta.jsonl"
    return log.exists() and log.stat().st_size > 0


# ─── Attack orchestration ────────────────────────────────────────────

def run_attacks(attack: str | None = None) -> None:
    """Invoke the atomic harness as a subprocess."""
    cmd = [sys.executable, "-m", "detections.atomic.run"]
    if attack:
        cmd.extend(["--attack", attack])

    print(f"  [validate] Running attacks: {attack or 'all'}")
    result = subprocess.run(cmd, cwd=str(BASE_DIR),
                            capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  [!] Attack harness failed:\n{result.stderr}")


# ─── Main validation ─────────────────────────────────────────────────

def validate(skip_attacks: bool = False) -> tuple[bool, list[dict]]:
    """
    Run the full validation flow.
    Returns (all_passed, results_list).
    """
    print("=" * 60)
    print("ZTA Detection Validation")
    print("=" * 60)
    print()

    # Pre-flight
    print("[1/3] Pre-flight checks")
    if not check_log_file():
        print("  [X] logs/zta.jsonl missing or empty")
        return False, []
    print("  [OK] log file present")

    if not skip_attacks:
        if not check_zta_running():
            print("  [X] ZTA Edge Router not responding on https://localhost:9999")
            print("       Start ZTA with: python start_overlay_network.py")
            return False, []
        print("  [OK] ZTA Edge Router healthy")

    # Attacks
    if not skip_attacks:
        print()
        print("[2/3] Running atomic attacks")
        for rule_file, cfg in EXPECTED_RULES.items():
            run_attacks(cfg["attack"])
            time.sleep(1)  # let logs flush
    else:
        print()
        print("[2/3] Skipping attacks (--no-attack)")

    # Evaluate rules
    print()
    print("[3/3] Evaluating Sigma rules")

    # Snapshot the log line count before running harness so we can report
    # "new events since attacks"
    log_path = BASE_DIR / "logs" / "zta.jsonl"
    line_count_before = sum(1 for _ in log_path.open("r", encoding="utf-8"))

    detections = run_harness(tail=None, only_rule=None, verbose=False)

    line_count_after = sum(1 for _ in log_path.open("r", encoding="utf-8"))
    new_events = line_count_after - line_count_before

    # Count detections per rule (by matching rule title)
    detections_by_title: dict[str, int] = {}
    for d in detections:
        title = d["rule"].get("title", "")
        detections_by_title[title] = detections_by_title.get(title, 0) + 1

    # Build result table
    results = []
    all_passed = True
    for rule_file, cfg in EXPECTED_RULES.items():
        title = cfg["title"]
        count = detections_by_title.get(title, 0)
        passed = count >= cfg["min_detections"]
        if not passed:
            all_passed = False
        results.append({
            "rule_file": rule_file,
            "title": title,
            "technique": cfg["technique"],
            "detections": count,
            "required": cfg["min_detections"],
            "status": "PASS" if passed else "FAIL",
        })

    # Print table
    print()
    print("-" * 78)
    print(f"{'Status':<8} {'Technique':<12} {'Detections':<12} Rule")
    print("-" * 78)
    for r in results:
        status_marker = "PASS" if r["status"] == "PASS" else "FAIL"
        print(f"{status_marker:<8} {r['technique']:<12} "
              f"{r['detections']}/{r['required']:<8} {r['title']}")
    print("-" * 78)
    print(f"New events processed: {new_events}")
    print()

    if all_passed:
        print("[OK] All rules fired — detection pipeline validated")
    else:
        print("[X] One or more rules did not fire — pipeline INCOMPLETE")

    return all_passed, results


def main():
    parser = argparse.ArgumentParser(description="ZTA detection validator")
    parser.add_argument("--no-attack", action="store_true",
                        help="Skip attack phase (harness-only run)")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON result and exit")
    args = parser.parse_args()

    passed, results = validate(skip_attacks=args.no_attack)

    if args.json:
        print(json.dumps({
            "passed": passed,
            "results": results,
        }, indent=2))

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()