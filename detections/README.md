# ZTA Overlay Framework — Detection Layer

This directory contains the **detection-as-code** pipeline for the ZTA Overlay Network. It is the SOC-facing counterpart to the ZTA infrastructure itself.

## What's here

| Path | Purpose |
|------|---------|
| `sigma/` | Sigma detection rules (vendor-neutral YAML) |
| `harness.py` | Sigma rule evaluator with sliding-window aggregation |
| `atomic/` | Safe attack simulations that trigger each rule |
| `validate.py` | End-to-end PASS/FAIL validator |
| `attack_layer.json` | MITRE ATT&CK Navigator layer (import at https://mitre-attack.github.io/attack-navigator/) |

## The pipeline
┌─────────────────────┐
│ Atomic attacks │ detections/atomic/run.py
│ (T1110/T1078/T1190)│ → drives HTTP against ZTA Edge Router
└──────────┬──────────┘
│
▼
┌─────────────────────┐
│ ZTA services │ Gateway / API Server / Controller / Edge Router
│ emit JSONL events │ → logs/zta.jsonl (ECS-aligned, trace_id correlated)
└──────────┬──────────┘
│
▼
┌─────────────────────┐
│ Sigma evaluator │ detections/harness.py
│ (selection+agg) │ → loads YAML rules, evaluates against JSONL
└──────────┬──────────┘
│
▼
┌─────────────────────┐
│ Detections │ one detection per rule that crossed its threshold
│ (aggregated) │ → validator reports PASS/FAIL per rule
└─────────────────────┘

text

## Rules

| Rule | Technique | Log source | Trigger condition |
|------|-----------|------------|-------------------|
| `t1110_brute_force_login.yml` | T1110.003 (Password Spraying) | `gateway` | 5+ `auth.login.failure` from same `source.ip` within 60s |
| `t1078_token_abuse.yml` | T1078 (Valid Accounts) / T1550.001 | `gateway`, `api_server` | 3+ `auth.token.invalid` OR `authz.clearance.denied` from same `source.ip` within 120s |
| `t1190_edge_probing.yml` | T1190 (Exploit Public-Facing App) / T1046 | `edge_router` | 3+ `router.target.unknown` OR suspicious-path `router.request.received` from same `source.ip` within 60s |

## Running the pipeline

**1. Start the ZTA:**
```powershell
python start_overlay_network.py