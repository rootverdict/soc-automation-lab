# Sigma Rules (vendor-portable detections)

Portable [Sigma](https://sigmahq.io/) equivalents of the lab's custom Wazuh
detections. Sigma is a generic, vendor-neutral signature format: the same rule
converts to a Wazuh, Splunk, Elastic, Sentinel, or Chronicle query with
`sigma convert`. Maintaining the detection logic here as well as in
`local_rules.xml` shows the detection is **not locked to one SIEM** - the
engineering lives in the logic, not the vendor syntax.

## Rules

| File | Detects | MITRE | Wazuh equivalent |
|------|---------|-------|------------------|
| [ssh_brute_force.yml](ssh_brute_force.yml) | SSH auth failure + brute-force correlation | T1110 | 100001, 100002 |
| [sudo_abuse.yml](sudo_abuse.yml) | Failed sudo + repeated-abuse correlation | T1548.003 | 100010, 100011 |
| [local_account_created.yml](local_account_created.yml) | New local account | T1136.001 | 100020 |
| [win_powershell_encoded.yml](win_powershell_encoded.yml) | Encoded / cradle PowerShell | T1059.001 | 1001xx (Windows) |
| [win_scheduled_task.yml](win_scheduled_task.yml) | Scheduled-task persistence | T1053.005 | 1001xx (Windows) |
| [win_runkey_persistence.yml](win_runkey_persistence.yml) | Run-key persistence | T1547.001 | 1001xx (Windows) |
| [win_lsass_access.yml](win_lsass_access.yml) | LSASS access / cred dumping | T1003.001 | 1001xx (Windows) |

Files with two documents (`---` separated) hold an **atomic** rule and its
**correlation** rule - the same two-tier model used in `local_rules.xml`
(single event low-signal; correlated pattern high-signal).

## Validate / lint

```bash
pip install sigma-cli pysigma-backend-elasticsearch
# Lint every rule
sigma check detections/sigma/
# Example conversion to a backend
sigma convert -t elasticsearch -p ecs_windows detections/sigma/win_lsass_access.yml
```

CI runs `sigma check` on this folder - see
[`.github/workflows/detections-ci.yml`](../../.github/workflows/detections-ci.yml).

## Notes on portability

- The Linux brute-force / sudo-abuse rules use Sigma **correlation** (`event_count`,
  `group-by`, `timespan`), which mirrors Wazuh `frequency`/`timeframe`/`same_source_ip`.
  Older backends that don't support correlation still convert the atomic base rule.
- Field names follow Sigma taxonomy; the Windows rules assume ECS/Sysmon field
  mapping (`ScriptBlockText`, `TargetImage`, `GrantedAccess`, `TargetObject`).
- These are portability artifacts. The Wazuh `local_rules.xml` copy remains the
  one deployed and validated in this lab.
