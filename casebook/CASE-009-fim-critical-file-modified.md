# CASE-009 - Critical system file modified (FIM)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-009 |
| **Date/Time (UTC)** | 2026-07-2X 16:22:31 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh FIM/syscheck rule `550` - "Integrity checksum changed" on `/etc/ssh/sshd_config` |
| **Severity** | 7 |
| **MITRE technique** | T1556 - Modify Authentication Process |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Escalated |
| **Detection source** | Wazuh syscheck (FIM) - requires the path under `<syscheck>` monitoring |

## 1. Alert summary
File Integrity Monitoring detected that a **critical configuration file** (`/etc/ssh/sshd_config`)
was modified. Changes to SSH config can weaken authentication (e.g. enabling root login or
password auth), a common post-compromise hardening-reversal.

<!-- EVIDENCE: attach Wazuh FIM alert with before/after diff -->

## 2. Triage (the L1 questions)
- **Internal or external?** Local change on the host (who/what made it is the question).
- **Known asset / user?** Was the change made by a sanctioned admin/config-management tool, or an
  unexpected account?
- **Expected behavior?** Is there a change ticket / Ansible run explaining it? If not, suspicious.
- **Enrichment corroborates?** FIM records the diff - inspect *what* changed, not just *that* it did.
- **Correlated?** Any preceding privilege escalation or account-creation events around the same time?
- **Severity vs impact?** SSH config controls remote access - high impact if weakened.

## 3. Enrichment
- Reviewed the FIM **diff**: what directive changed (e.g. `PermitRootLogin yes`,
  `PasswordAuthentication yes`)?
- Identified the modifying process/user via auditd or surrounding events.
- Checked for a legitimate change record.

<!-- EVIDENCE: attach the syscheck diff and the modifying user/process -->

## 4. Analysis
An unplanned modification to `sshd_config` - especially one that loosens authentication - with no
change record is consistent with an attacker weakening controls to preserve access. If the diff is
benign (e.g. a comment change by a known admin under a ticket), it downgrades to benign TP.

## 5. Verdict
**True Positive** (assuming no legitimate change record and a security-relevant diff) - unauthorized
modification of a critical SSH configuration file.

## 6. Action taken
- Preserved the FIM diff and identified the actor **before** any change.
- Recommended reverting the file from a known-good baseline (defer the actual revert to L2 to
  avoid destroying evidence/scope).

## 7. Escalation / handoff
**Escalated to L2.** Handoff: unauthorized `sshd_config` change (directive `<X>`), actor `<user/
process>`, no change ticket. Open for L2: (a) confirm and revert, (b) tie to any account-creation/
privilege events (CASE-003/006), (c) restart sshd after revert, (d) scope other monitored files.

## 8. IOCs
| Type | Value |
|------|-------|
| File | /etc/ssh/sshd_config |
| Change | <directive before → after> <!-- EVIDENCE --> |
| Actor | <user/process> <!-- EVIDENCE --> |
