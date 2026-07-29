# CASE-013 — Cron-based persistence (scheduled job added)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-013 |
| **Date/Time (UTC)** | 2026-07-2X 21:12:44 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh FIM/syscheck rule `554/550` on `/etc/cron.*` or `/var/spool/cron/*` |
| **Severity** | 8 |
| **MITRE technique** | T1053.003 — Scheduled Task/Job: Cron |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Escalated |
| **Detection source** | Wazuh syscheck (FIM) on cron directories |

## 1. Alert summary
A new or modified cron entry was detected under a cron directory. Attackers use cron for
**persistence** — a scheduled job that re-establishes access or re-runs a payload on a timer.

<!-- EVIDENCE: attach FIM alert on the cron file + the added line -->

## 2. Triage (the L1 questions)
- **Internal or external?** Local change; concern is the *content* and *who* added it.
- **Known asset / user?** Was the cron entry added by a sanctioned admin / package install?
- **Expected behavior?** Legitimate software adds cron jobs; a change record or known package = benign.
- **Enrichment corroborates?** Inspect the command the cron runs — does it call back out, decode a
  blob, or launch a shell?
- **Correlated?** Any preceding account creation / privilege events on this host?
- **Severity vs impact?** Persistence mechanism → escalate if the command is suspicious.

## 3. Enrichment
- Read the **cron command line** — the payload is the whole story (e.g. a curl-to-shell,
  base64-decoded script, reverse shell).
- Identified the owning user and whether the referenced binary/script is legitimate.
- Checked package history for a benign explanation.

<!-- EVIDENCE: attach the cron line + the script/binary it references -->

## 4. Analysis
A cron job whose command reaches out to the internet, decodes an obfuscated payload, or spawns a
shell is **persistence (T1053.003)**, not maintenance. A cron entry from a known package with a
benign command is a **benign true positive** to document and close.

## 5. Verdict
**True Positive — cron persistence (T1053.003)** for a suspicious payload; **Benign True Positive**
if it resolves to a legitimate package/admin job.

## 6. Action taken
- Preserved the cron entry and referenced script before change.
- Recommended removing the entry + the payload under L2 direction; blocked any callback IP found.

## 7. Escalation / handoff
**Escalated to L2.** Handoff: cron persistence in `<file>`, command `<...>`, owner `<user>`,
callback `<IP if any>`. Open: (a) remove entry + payload, (b) tie to initial access (CASE-007) and
other persistence (CASE-003), (c) check other hosts for the same job.

## 8. IOCs
| Type | Value |
|------|-------|
| Cron file | <path> |
| Command | <cron command> <!-- EVIDENCE --> |
| Callback IP | <IP if present> <!-- EVIDENCE --> |
