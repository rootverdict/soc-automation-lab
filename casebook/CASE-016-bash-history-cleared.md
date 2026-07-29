# CASE-016 - Shell history cleared (indicator removal)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-016 |
| **Date/Time (UTC)** | 2026-07-2X 21:31:10 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh FIM/command rule - `.bash_history` truncated/deleted, or `history -c` / `unset HISTFILE` observed |
| **Severity** | 7 |
| **MITRE technique** | T1070.003 - Indicator Removal: Clear Command History |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Escalated |
| **Detection source** | Wazuh syscheck on `~/.bash_history` and/or command monitoring |

## 1. Alert summary
A user's shell history file was **cleared or truncated** (or history logging was disabled). This
is a common **anti-forensics** step - an attacker removing evidence of the commands they ran.

<!-- EVIDENCE: attach FIM alert on .bash_history (size → 0) or the history -c command -->

## 2. Triage (the L1 questions)
- **Internal or external?** Local action by an account on the host.
- **Known asset / user?** Which user cleared history, and do they have a legitimate reason?
- **Expected behavior?** Rarely - routine admin work does not require wiping history.
- **Enrichment corroborates?** What account, and what was happening around that time?
- **Correlated?** History clearing right after suspicious activity is a strong TP signal.
- **Severity vs impact?** Moderate on its own, high in context of other compromise cases.

## 3. Enrichment
- Identified the user and the exact action (file truncated to 0 bytes, deleted, or `HISTFILE` unset).
- Checked surrounding telemetry (auditd, other cases) for what the clearing may be hiding.

<!-- EVIDENCE: attach the account + timeline around the clear -->

## 4. Analysis
Deliberately clearing shell history maps to **T1070.003** and, in the context of other indicators
on this host, points to an actor cleaning up. On its own it can occasionally be a tidy admin, so it
is weighed with the surrounding activity - but it is never dismissed silently.

## 5. Verdict
**True Positive - indicator removal (T1070.003)**, especially alongside other compromise cases;
**Benign True Positive** only if a specific legitimate reason is confirmed with the user.

## 6. Action taken
- Preserved what history remained and the auditd record (auditd captures commands even when
  `.bash_history` is wiped - a good reason it should be running; see CASE-015).
- Reconstructed likely activity from auditd/other sources.

## 7. Escalation / handoff
**Escalated to L2.** Handoff: `<user>` cleared shell history at `<time>`; reconstructed activity
from auditd `<summary>`. Open: (a) confirm intent with user/owner, (b) correlate with CASE-007/014,
(c) ensure command auditing can't be trivially bypassed.

## 8. IOCs
| Type | Value |
|------|-------|
| User | <user> <!-- EVIDENCE --> |
| Action | .bash_history truncated / history -c <!-- EVIDENCE --> |
| Host | soc-endpoint (192.168.100.20) |
