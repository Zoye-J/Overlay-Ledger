"""
Sigma rule harness for the ZTA Overlay Network.

Loads Sigma YAML rules from detections/sigma/, evaluates them against
JSONL logs (logs/zta.jsonl by default), and applies time-window
aggregation specified in each rule's extended `aggregation` block.

Usage:
    python -m detections.harness                    # scan full log
    python -m detections.harness --tail 500         # last 500 events
    python -m detections.harness --rule t1110       # single rule
    python -m detections.harness --verbose          # per-match output

Design notes:
- Base Sigma detection is single-event: "does this event match selection?"
- Aggregation (count over window) is a local extension the harness reads
  from `aggregation:` keys. Sigma has no native aggregation syntax.
- Field access uses dotted paths (e.g. `user.name`) resolved against the
  nested JSON structure of each event.
"""

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
SIGMA_DIR = BASE_DIR / "detections" / "sigma"
LOG_FILE = BASE_DIR / "logs" / "zta.jsonl"


# ─── Field resolution ────────────────────────────────────────────────

def get_field(event: dict, path: str) -> Any:
    """
    Resolve a dotted field path against a nested dict.
    Supports Sigma modifiers stripped from the field name (contains, etc.)
    handled by the caller.

    Example:
        get_field({"user": {"name": "alice"}}, "user.name") -> "alice"
    """
    parts = path.split(".")
    current = event
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


# ─── Selection matching ──────────────────────────────────────────────

def match_field(event: dict, field_spec: str, expected: Any) -> bool:
    """
    Match a single field against expected value(s).

    Supports Sigma modifiers:
        field                 -> exact match
        field|contains        -> substring match
        field|startswith      -> prefix match
        field|endswith        -> suffix match
        field|re              -> regex match
    """
    # Parse modifier
    if "|" in field_spec:
        field_name, modifier = field_spec.split("|", 1)
    else:
        field_name, modifier = field_spec, None

    actual = get_field(event, field_name)

    # Sigma treats lists in the rule as OR of the values
    expected_values = expected if isinstance(expected, list) else [expected]

    for exp in expected_values:
        if modifier is None:
            if actual == exp:
                return True
        elif modifier == "contains":
            if actual is not None and str(exp) in str(actual):
                return True
        elif modifier == "startswith":
            if actual is not None and str(actual).startswith(str(exp)):
                return True
        elif modifier == "endswith":
            if actual is not None and str(actual).endswith(str(exp)):
                return True
        elif modifier == "re":
            import re
            if actual is not None and re.search(str(exp), str(actual)):
                return True
        elif modifier == "contains|all":
            # All substrings must be present
            if actual is not None and all(str(e) in str(actual) for e in expected_values):
                return True
        else:
            # Unknown modifier — treat as exact match on the base field
            if actual == exp:
                return True

    return False


def match_selection(event: dict, selection: dict) -> bool:
    """A selection is a dict of field->expected. All must match (AND)."""
    for field_spec, expected in selection.items():
        if not match_field(event, field_spec, expected):
            return False
    return True


def match_detection(event: dict, detection: dict) -> bool:
    """
    Evaluate the Sigma `detection` block's `condition` against an event.

    Supported conditions:
        "selection"                 -> single selection must match
        "selection_a or selection_b"-> OR of selections
        "selection_a and selection_b" -> AND of selections
        "selection and not filter"  -> AND with negation
    """
    condition = detection.get("condition", "selection")

    # Ignore non-selection keys
    selections = {
        k: v for k, v in detection.items()
        if k not in ("condition", "group_by", "aggregation", "timeframe")
        and not k.startswith("_")
    }

    # Simple tokenizer — handles and / or / not with left-to-right precedence
    # This is intentionally minimal; real pySigma has a full parser.
    tokens = condition.replace("(", " ( ").replace(")", " ) ").split()

    # Build a boolean evaluator
    def evaluate_expression(tokens: list[str]) -> bool:
        # Handle "not X" by wrapping
        result = None
        operator = None
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "and":
                operator = "and"
                i += 1
                continue
            if tok == "or":
                operator = "or"
                i += 1
                continue
            if tok == "not":
                i += 1
                if i < len(tokens):
                    name = tokens[i]
                    val = not match_selection(event, selections.get(name, {}))
                    if result is None:
                        result = val
                    elif operator == "and":
                        result = result and val
                    elif operator == "or":
                        result = result or val
                i += 1
                continue
            if tok in ("(", ")"):
                i += 1
                continue

            # Assume it's a selection name
            val = match_selection(event, selections.get(tok, {}))
            if result is None:
                result = val
            elif operator == "and":
                result = result and val
            elif operator == "or":
                result = result or val
            i += 1

        return bool(result)

    return evaluate_expression(tokens)


# ─── Event loading ───────────────────────────────────────────────────

def load_events(log_file: Path, tail: int | None = None) -> list[dict]:
    """Load JSONL events. Optionally return only the last N lines."""
    if not log_file.exists():
        print(f"[harness] Log file not found: {log_file}", file=sys.stderr)
        return []

    with log_file.open("r", encoding="utf-8") as f:
        lines = f.readlines()

    if tail:
        lines = lines[-tail:]

    events = []
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as e:
            print(f"[harness] Skipping malformed line {i}: {e}", file=sys.stderr)

    return events


# ─── Rule loading ────────────────────────────────────────────────────

def load_rules(sigma_dir: Path, only: str | None = None) -> list[dict]:
    """Load Sigma YAML files. `only` filters to files whose name contains it."""
    pattern = str(sigma_dir / "*.yml")
    rules = []
    for path in glob.glob(pattern):
        if only and only not in os.path.basename(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)
        rule["_source_file"] = os.path.basename(path)
        rules.append(rule)
    return rules


# ─── Aggregation ─────────────────────────────────────────────────────

def parse_timestamp(event: dict) -> datetime | None:
    """Extract @timestamp as a datetime. Returns None if unavailable."""
    ts = event.get("@timestamp")
    if not ts:
        return None
    try:
        # Python 3.11+ handles the Z suffix directly; for safety:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def apply_aggregation(matches: list[dict], rule: dict) -> list[dict]:
    """
    Given a list of events matching the rule's selection, apply the
    aggregation block (group_by + count + window_seconds).

    Returns a list of "detection" records — one per group that crossed
    the threshold.
    """
    detection = rule.get("detection", {})
    agg = detection.get("aggregation")
    if not agg:
        # No aggregation — every match is a detection
        return [{"event": m, "rule": rule} for m in matches]

    group_by = detection.get("group_by", [])
    count_threshold = agg.get("count", 1)
    window_seconds = agg.get("window_seconds", 60)

    # Group matches by the group_by fields
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for m in matches:
        key = tuple(get_field(m, f) for f in group_by)
        groups[key].append(m)

    detections = []
    for key, events_in_group in groups.items():
        # Sort by timestamp
        events_in_group.sort(key=lambda e: parse_timestamp(e) or datetime.min)

        # Sliding window: for each event, count how many events fall
        # within window_seconds after it
        i = 0
        while i < len(events_in_group):
            window_start = parse_timestamp(events_in_group[i])
            if window_start is None:
                i += 1
                continue

            window_end = window_start + timedelta(seconds=window_seconds)
            window_events = []
            j = i
            while j < len(events_in_group):
                ts = parse_timestamp(events_in_group[j])
                if ts and ts <= window_end:
                    window_events.append(events_in_group[j])
                    j += 1
                else:
                    break

            if len(window_events) >= count_threshold:
                detections.append({
                    "rule": rule,
                    "group": dict(zip(group_by, key)),
                    "count": len(window_events),
                    "window_seconds": window_seconds,
                    "window_start": window_start.isoformat(),
                    "window_end": window_end.isoformat(),
                    "events": window_events,
                })
                # Skip ahead to avoid duplicate overlapping detections
                i = j
            else:
                i += 1

    return detections


# ─── Main ────────────────────────────────────────────────────────────

def run_harness(tail: int | None = None, only_rule: str | None = None,
                verbose: bool = False) -> list[dict]:
    """Load events, evaluate rules, return all detections."""
    print(f"[harness] Loading events from {LOG_FILE.name}"
          + (f" (last {tail})" if tail else ""))
    events = load_events(LOG_FILE, tail=tail)
    print(f"[harness] Loaded {len(events)} events")

    rules = load_rules(SIGMA_DIR, only=only_rule)
    print(f"[harness] Loaded {len(rules)} rules")

    all_detections = []
    for rule in rules:
        title = rule.get("title", "Untitled")
        detection = rule.get("detection", {})

        # Single-event matches
        matches = [e for e in events if match_detection(e, detection)]

        # Apply aggregation
        detections = apply_aggregation(matches, rule)

        print(f"[harness]   {title}: {len(matches)} single-event matches, "
              f"{len(detections)} aggregated detections")

        if verbose and detections:
            for d in detections:
                print(f"[harness]     group={d.get('group')} "
                      f"count={d.get('count')}/{d.get('window_seconds')}s")

        all_detections.extend(detections)

    return all_detections


def main():
    parser = argparse.ArgumentParser(description="ZTA Sigma rule harness")
    parser.add_argument("--tail", type=int, default=None,
                        help="Only process last N events")
    parser.add_argument("--rule", type=str, default=None,
                        help="Only run rules whose filename contains this string")
    parser.add_argument("--verbose", action="store_true",
                        help="Print per-detection details")
    parser.add_argument("--json", action="store_true",
                        help="Output detections as JSON")
    args = parser.parse_args()

    detections = run_harness(tail=args.tail, only_rule=args.rule,
                             verbose=args.verbose)

    print()
    print(f"[harness] Total detections: {len(detections)}")

    if args.json:
        # Serialize with rule titles only (avoid dumping entire events)
        summary = [
            {
                "rule": d["rule"].get("title"),
                "rule_id": d["rule"].get("id"),
                "level": d["rule"].get("level"),
                "group": d.get("group"),
                "count": d.get("count"),
                "window_start": d.get("window_start"),
                "window_end": d.get("window_end"),
            }
            for d in detections
        ]
        print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()