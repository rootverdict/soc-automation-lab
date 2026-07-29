# CASE-015 - Logging/monitoring service stopped (defense evasion)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-015 |
| **Date/Time (UTC)** | 2026-07-2X 21:25:47 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh rule - agent/service state change: `auditd`/`rsyslog`/Wazuh agent stopped, or `ossec: Agent disconnected` |
| **Severity** | 9 |
| **MITRE technique** | T1562.001 - Impair Defenses: Disable or Modify Tools |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Escalated |
| **Detection source** | Wazuh agent state + syslog rules |

## 1. Alert summary
A security-relevant service (`auditd`, `rsyslog`, or the Wazuh agent itself) was **stopped**, or
the agent went silent. Attackers disable logging to blind detection before/after malicious
activity (defense evasion).

<!-- EVIDENCE: attach the service-stop / agent-disconnect alert -->

## 2. Triage (the L1 questions)
- **Internal or external?** Local action on the host.
- **Known asset / user?** Was there planned maintenance/patching that restarts services?
- **Expected behavior?** A brief stop during a known reboot/patch window = benign. An unexplained
  stop = evasion until proven otherwise.
- **Enrichment corroborates?** What happened right before the stop, and did the service come back?
- **Correlated?** A logging gap around other suspicious events is a strong evasion signal.
- **Severity vs impact?** Losing visibility on a monitored host is serious.

## 3. Enrichment
- Checked for a maintenance/change window explaining the restart.
- Examined events immediately **before** the stop and whether the service **restarted** cleanly.
- Looked for a **gap** in telemetry aligned with other cases (an attacker silencing logs mid-op).

<!-- EVIDENCE: attach the timeline around the stop + whether the service resumed -->

## 4. Analysis
An unexplained stop of `auditd`/logging with no maintenance record, especially near other
suspicious activity, is **defense evasion (T1562.001)** - the attacker is reducing visibility. A
stop that maps cleanly to a scheduled patch/reboot is a **benign true positive**.

## 5. Verdict
**True Positive - impair defenses (T1562.001)** without a maintenance record; **Benign True
Positive** if it maps to a known reboot/patch window.

## 6. Action taken
- Confirmed whether monitoring was restored; flagged any telemetry gap for correlation.
- Recommended re-enabling and hardening the service (prevent non-root stop) under L2.

## 7. Escalation / handoff
**Escalated to L2.** Handoff: `<service>` stopped at `<time>`, no change record, telemetry gap of
`<duration>`. Open: (a) confirm restore + persistence of the setting, (b) fill the visibility gap
from other sources, (c) correlate with activity during the blind window.

## 8. IOCs
| Type | Value |
|------|-------|
| Service | auditd / rsyslog / wazuh-agent <!-- EVIDENCE --> |
| Gap window | <start–end> <!-- EVIDENCE --> |
| Host | soc-endpoint (192.168.100.20) |
