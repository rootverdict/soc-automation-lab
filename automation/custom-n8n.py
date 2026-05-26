#!/usr/bin/env python3
import sys, json, requests

alert_file = sys.argv[1]
hook_url = sys.argv[3]

with open(alert_file) as f:
    alert = json.load(f)

payload = {
    "rule_id": alert.get("rule", {}).get("id"),
    "description": alert.get("rule", {}).get("description"),
    "level": alert.get("rule", {}).get("level"),
    "mitre": alert.get("rule", {}).get("mitre", {}),
    "agent": alert.get("agent", {}),
    "full_log": alert.get("full_log"),
    "timestamp": alert.get("timestamp"),
}

requests.post(hook_url, json=payload, timeout=10)
