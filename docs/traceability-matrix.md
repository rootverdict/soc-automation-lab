# Traceability Matrix

One table that ties the whole lab together: **attack → detection → MITRE →
response → forensic evidence → casebook**. It's the fastest way for a reviewer
to see that every detection connects to a rule, a technique, a response, and a
worked case - and, where a link in that chain is not yet proven, to see it
labelled rather than implied. The
[status table](../README.md#status---proven-vs-committed) is the single source of
truth for what has been executed vs. what is committed.

## Linux - custom rules (validated by execution; 100020 by Caldera emulation)

| Attack | Rule | MITRE | Auto-response | Forensic confirm | Casebook |
|--------|------|-------|---------------|------------------|----------|
| SSH brute force (external) | 100001 → 100002 | T1110 | Wazuh `firewall-drop` (timed 600s) | auth.log / no `Accepted` | [CASE-001](../casebook/CASE-001-ssh-bruteforce-external.md) |
| SSH brute force (internal scanner) | 100002 | T1110 | *suppressed - FP* | - | [CASE-002](../casebook/CASE-002-ssh-bruteforce-internal.md) |
| Repeated failed sudo | 100010 → 100011 | T1548.003 | host action (not IP block) | session / account state | [CASE-006](../casebook/CASE-006-sudo-abuse.md) |
| Local account created | 100020 | T1136 | gated Velociraptor branch | `Linux.Sys.Users` (uid confirmed) | [CASE-003](../casebook/CASE-003-account-creation.md) |

## Linux - built-in telemetry (casebook coverage)

| Attack | Source | MITRE | Config artifact | Casebook |
|--------|--------|-------|-----------------|----------|
| Successful login post-brute-force | SSH ruleset | T1078 | default | [CASE-007](../casebook/CASE-007-ssh-successful-login-post-bruteforce.md) |
| Anomalous-geo login | SSH ruleset | T1078 | default | [CASE-008](../casebook/CASE-008-ssh-anomalous-geo-login.md) |
| sshd_config modified | FIM | T1556 | [syscheck-fim](../detections/telemetry/syscheck-fim.conf.xml) | [CASE-009](../casebook/CASE-009-fim-critical-file-modified.md) |
| Web shell dropped | FIM + web log | T1505.003 | [syscheck-fim](../detections/telemetry/syscheck-fim.conf.xml), [web log](../detections/telemetry/ossec-localfile-web.xml) | [CASE-010](../casebook/CASE-010-webshell-dropped.md) |
| SQL injection | Web ruleset | T1190 | [web log](../detections/telemetry/ossec-localfile-web.xml) | [CASE-011](../casebook/CASE-011-web-sql-injection.md) |
| Rootkit / hidden proc | rootcheck | T1014 | default | [CASE-012](../casebook/CASE-012-rootcheck-rootkit.md) |
| Cron persistence | FIM | T1053.003 | [syscheck-fim](../detections/telemetry/syscheck-fim.conf.xml) | [CASE-013](../casebook/CASE-013-cron-persistence.md) |
| Reverse shell outbound | auditd | T1059.004 / T1071.001 | [auditd](../detections/telemetry/auditd-soc-lab.rules) | [CASE-014](../casebook/CASE-014-reverse-shell-outbound.md) |
| Logging service stopped | auditd | T1562.001 | [auditd](../detections/telemetry/auditd-soc-lab.rules) | [CASE-015](../casebook/CASE-015-logging-service-stopped.md) |
| Bash history cleared | auditd + FIM | T1070.003 | [auditd](../detections/telemetry/auditd-soc-lab.rules) | [CASE-016](../casebook/CASE-016-bash-history-cleared.md) |
| Recon tool installed | auditd | T1046 | [auditd](../detections/telemetry/auditd-soc-lab.rules) | [CASE-017](../casebook/CASE-017-recon-tool-installed.md) |
| Malicious file by hash | FIM + VirusTotal | T1105 | [VT integration](../detections/telemetry/virustotal-integration.xml) | [CASE-018](../casebook/CASE-018-malicious-file-hash.md) |

## Windows - custom rules (authored; live validation pending endpoint)

| Attack | Rule | MITRE | Source | Casebook |
|--------|------|-------|--------|----------|
| Encoded PowerShell | 100100 / 100101 | T1059.001 | PS EID 4104 / Sysmon 1 | CASE-004 *(pending)* |
| Scheduled task persistence | 100110 / 100111 | T1053.005 | Sysmon 1 / Security 4698 | - |
| Run-key persistence | 100120 | T1547.001 | Sysmon 13 | - |
| LSASS access | 100131 | T1003.001 | Sysmon 10 | CASE-005 *(pending)* |

## Portability

Every custom rule above has a vendor-portable [Sigma](../detections/sigma)
equivalent, and all techniques render on the
[ATT&CK coverage map](../detections/coverage). Rule firing is enforced in
[CI](../.github/workflows/detections-ci.yml).
