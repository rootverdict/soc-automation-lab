# CASE-007 — Successful SSH login following brute-force (confirmed compromise)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-007 |
| **Date/Time (UTC)** | 2026-07-2X 14:06:40 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh rule `5715` (SSH authentication success) correlated after custom rule `100002` (brute-force) from the same source |
| **Severity** | 12 (escalated — success after brute-force) |
| **MITRE technique** | T1110 — Brute Force → T1078 — Valid Accounts |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Escalated — CRITICAL |
| **Detection source** | SSH ruleset (built-in) correlated with custom rule 100002 |

## 1. Alert summary
A **successful** SSH login (`Accepted password`) occurred from the same source IP that had just
tripped the brute-force correlation rule (`100002`) in CASE-001. A guess landed — this is no
longer an attempt, it is a **confirmed unauthorized authentication**.

<!-- EVIDENCE: attach Wazuh timeline showing 100002 followed by 5715 from same srcip -->

## 2. Triage (the L1 questions)
- **Internal or external?** External source (public IP), same as CASE-001.
- **Known asset / user?** The account that authenticated is a real local account — meaning the
  attacker guessed a valid credential.
- **Expected behavior?** No — a public IP authenticating seconds after a failed-login burst is
  not legitimate admin activity.
- **Enrichment corroborates?** Yes — source IP is VirusTotal-flagged (CASE-001), and the
  success immediately follows the failure burst.
- **Correlated?** Strongly — brute-force → success from one source within seconds.
- **Severity vs impact?** This is the highest-impact case in the book: an external actor now has
  an interactive session.

## 3. Enrichment
- Confirmed the `Accepted` event's source IP matches the brute-force source.
- Pulled the session: source port, the authenticated username, and any immediate post-login
  commands from auth/journald.

<!-- EVIDENCE: attach auth.log Accepted line + first post-login activity -->

## 4. Analysis
The brute-force succeeded. An external, reputation-flagged host authenticated with a valid
credential and now holds an interactive session (T1078 Valid Accounts). Any further activity by
this session must be treated as attacker action until proven otherwise.

## 5. Verdict
**True Positive — confirmed compromise.** External brute-force resulted in a successful login
with valid credentials.

## 6. Action taken
- The source IP was already firewall-dropped by active-response (CASE-001), but since a session
  may persist, this needs **session termination**, not just an IP block.
- Preserved evidence (session details, post-login commands) before any host action.

## 7. Escalation / handoff
**Escalated to L2 as CRITICAL.** Handoff: confirmed compromise — external actor authenticated as
`<user>` after brute-force (T1110 → T1078). Already contained at the network layer (IP dropped).
Open for L2/IR: (a) kill the live session and force-reset the credential, (b) determine what the
session did post-login, (c) scope for lateral movement and additional persistence, (d) full IR on
the host may be warranted.

## 8. IOCs
| Type | Value |
|------|-------|
| Source IP | <public IP, same as CASE-001> |
| Compromised account | <user> <!-- EVIDENCE --> |
| Session | source port / login time <!-- EVIDENCE --> |
