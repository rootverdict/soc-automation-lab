# CASE-017 — Reconnaissance tool installed (benign true positive / policy)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-017 |
| **Date/Time (UTC)** | 2026-07-2X 10:58:22 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh package/command rule — installation of a recon/dual-use tool (`nmap`, `netcat`, `masscan`, `tcpdump`) |
| **Severity** | 6 |
| **MITRE technique** | T1046 — Network Service Discovery (dual-use) |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Closed — Benign True Positive |
| **Detection source** | Wazuh command/package monitoring (apt/dpkg logs) |

## 1. Alert summary
A **dual-use reconnaissance tool** (`nmap`) was installed on the endpoint. These tools are
legitimate for admins but also used by attackers for internal discovery, so their appearance is
flagged for review.

<!-- EVIDENCE: attach the package-install alert -->

## 2. Triage (the L1 questions)
- **Internal or external?** Local install action.
- **Known asset / user?** Who installed it — an admin, or an unexpected/compromised account?
- **Expected behavior?** On an admin/SOC host, tooling installs can be routine; on a locked-down
  server, they are not.
- **Enrichment corroborates?** Was the install via the normal package manager by a sudoer, with a
  change record?
- **Correlated?** Was the tool then *used* to scan the network (that would change the verdict)?
- **Severity vs impact?** Low unless tied to unauthorized activity.

## 3. Enrichment
- Confirmed the installing user is a legitimate admin acting under a change/task.
- Checked whether any **scan activity** followed the install (nmap runs, mass connection attempts).
- No discovery scan followed; install matched a documented admin task.

<!-- EVIDENCE: attach installing user + absence/presence of subsequent scan traffic -->

## 4. Analysis
The alert correctly fired (a dual-use tool was installed) but the context is legitimate: a known
admin installed it under a task, and it was not used for unauthorized discovery. This is the kind
of **policy/hygiene alert** an L1 clears with context — while staying alert to the scenario where
the same tool is installed by a *compromised* account and then used to scan (which would be a TP).

## 5. Verdict
**Benign True Positive** — authorized admin installed a dual-use tool; no unauthorized discovery
followed. (Would flip to **True Positive — discovery (T1046)** if installed by an unexpected
account or followed by scanning.)

## 6. Action taken
- Verified with the admin; documented the change.
- Noted a policy recommendation: restrict/inventory dual-use tooling on production hosts.

## 7. Escalation / handoff
**Not escalated.** Closed as benign with context. Policy note logged for hardening (approved-
software list, alert if the tool is *executed against internal ranges* rather than merely installed).

## 8. IOCs
| Type | Value |
|------|-------|
| Package | nmap <!-- EVIDENCE --> |
| Installing user | <admin> <!-- EVIDENCE --> |
| Follow-on scan? | none observed |
