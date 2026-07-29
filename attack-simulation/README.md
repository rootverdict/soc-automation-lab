# Attack Simulation (MITRE Caldera)

MITRE Caldera was used to generate realistic attacker behaviour against the monitored endpoint, so detections could be validated against real event sequences rather than synthetic log injection.

## Files

| File | Purpose |
|------|---------|
| `t1136-createuser.yml` | Custom Caldera ability that creates a local user (T1136), with a cleanup step |
| `operation-report.json` | Exported Caldera operation report (optional) |

## Setup summary

- Caldera 5.3 server deployed on the endpoint, with the VueJS (Magma) UI built via Node 20.
- A Sandcat agent deployed on the same host and run with root privileges (required for account-creation abilities such as `useradd`).
- Operations run from the Caldera UI against the `red` agent group.

## Custom ability (T1136)

The custom ability authored for this lab maps cleanly to MITRE ATT&CK T1136 (Create Account) and includes a cleanup command so the lab returns to a known state:

```yaml
- id: 8f2a1c4d-3b7e-4a91-9d6f-1e2c3b4a5d60
  name: Create local user account
  description: Creates a new local user (T1136 Create Account)
  tactic: persistence
  technique:
    attack_id: T1136
    name: Create Account
  platforms:
    linux:
      sh:
        command: |
          useradd caldera_t1136 && echo "user created"
        cleanup: |
          userdel -r caldera_t1136
```

Drop this file into `plugins/stockpile/data/abilities/persistence/` and restart the Caldera server to load it. Authoring an emulation ability mapped to a specific technique demonstrates detection-engineering maturity beyond running built-in operations.

## Validation approach

Detections were confirmed against Caldera-driven activity, not assumptions:

- A "Create local account (Linux)" operation executed `useradd` on the endpoint and fired Wazuh rule **100020** (T1136) — confirmed end-to-end through the dashboard.
- Discovery-tactic abilities were also run early in testing; these execute read-only commands (`whoami`, `cat /etc/passwd`, `ps`) that produce no security-relevant events, which is a useful reminder that **detection coverage must be matched to the tactic** — discovery is largely silent to a default ruleset, so persistence / credential-access abilities are needed to exercise these particular detections.

## Why Caldera over static log replay

Running an actual operation against a live agent produces realistic event ordering, timing, and log volume. This surfaces gaps that sanitized, pre-built datasets do not — for example, confirming that the right base rule fires for a real `useradd` log line versus an assumed one.
