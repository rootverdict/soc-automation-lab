# Detections

Custom detection logic authored for Wazuh, layered on top of the built-in decoders and base ruleset. All rules live in `local_rules.xml` (included in this folder) and are mapped to MITRE ATT&CK techniques. Each detection was validated by executing the corresponding attack and confirming the alert fired — not assumed.

## Rule summary

| Rule ID | Description | Parent rule(s) | MITRE | Level | Type |
|---------|-------------|----------------|-------|-------|------|
| 100001 | SSH authentication failure | 5710, 5716, 5760 | T1110 | 5 | atomic |
| 100002 | SSH brute force — 5+ failures in 120s from same source IP | 100001 | T1110 | 10 | correlation |
| 100010 | Failed sudo attempt | 5401 | T1548.003 | 7 | atomic |
| 100011 | Repeated failed sudo — 4+ in 120s | 100010 | T1548.003 | 10 | correlation |
| 100020 | Local account created | 5902 | T1136 | 8 | atomic |

## How the rules work

The rules use two Wazuh mechanisms:

- **`if_sid`** — inherits from a base rule. The custom rule fires whenever the parent decoder/rule matches, adding a higher severity and a MITRE tag. Example: rule 100020 fires on base rule 5902 (new user added).
- **`if_matched_sid` with `frequency`/`timeframe`** — correlation. The rule fires only when the referenced rule has matched N times within a window. Example: rule 100002 fires when rule 100001 (single SSH failure) matches 5 times in 120 seconds.

Severity is deliberately tiered: a single failure is low (level 5–7), while a correlated attack pattern is high (level 10). Only level ≥ 7 alerts are forwarded to the automation layer.

## MITRE ATT&CK mapping

| Technique | ID | Tactic | Detected by |
|-----------|----|--------|-------------|
| Brute Force | T1110 | Credential Access | 100001, 100002 |
| Create Account | T1136 | Persistence | 100020 |
| Abuse Elevation Control Mechanism: Sudo and Sudo Caching | T1548.003 | Privilege Escalation / Defense Evasion | 100010, 100011 |

## False-positive reduction

- **`same_source_ip`** on the brute-force rule (100002) ensures the correlation only fires when failures originate from a single source, not scattered noise across hosts.
- **Tiered severity** means low-signal single events do not escalate; only correlated patterns reach high severity and trigger downstream automation.
- **SIEM-level threshold** (level ≥ 7 forwarded) keeps low-value events out of the automation pipeline entirely.
- A documented **suppression pattern** (a level-0 rule scoped to a trusted source IP) is the approach used to allow-list known-good hosts without disabling the detection.

## Mapping decoder output to the correct base rule

A key lesson during development was matching custom rules to the right base rule. For example:

- `5401` = "Failed attempt to run sudo" (a single failed sudo) — the correct parent for the failed-sudo detection.
- `5403` = "First time user executed sudo" (a successful, first-time sudo) — *not* a failure.
- `5404` = "Three failed attempts to run sudo" (a composite) — fires on the single 3-attempt log line, so an `if_sid: 5401` rule will not catch it.

Choosing the wrong parent (initially `5403`) meant the rule never fired on actual failures. Always confirm which base rule a given log line produces (via `wazuh-logtest` or the dashboard) before writing `if_sid`.

## Validation

Each rule was confirmed by executing the matching attack and observing the alert in the Wazuh dashboard:

- 100020 — `useradd <user>` → alert with `decoder: useradd`, `rule.mitre.id: T1136`.
- 100002 — repeated failed SSH logins from one source → correlated alert, `T1110`.
- 100010 / 100011 — failed `sudo` attempts → `T1548.003`.

Account-creation was additionally validated end-to-end via a MITRE Caldera "Create local account" operation.
