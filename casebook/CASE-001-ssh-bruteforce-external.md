# CASE-001 — SSH brute-force from external IP

| Field | Value |
|-------|-------|
| **Case ID** | CASE-001 |
| **Date/Time (UTC)** | 2026-07-2X 14:02:11 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh rule `100002` — "SSH BRUTE FORCE: 5+ failures from <srcip> in 120s" |
| **Severity** | 10 |
| **MITRE technique** | T1110 — Brute Force |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Escalated |

## 1. Alert summary
Correlation rule `100002` fired: 5+ SSH authentication failures from a single **public** source
IP within 120 seconds against `soc-endpoint`. This is the brute-force pattern, not a single
mistyped password.

<!-- EVIDENCE: attach Wazuh alert screenshot (rule 100002, MITRE T1110) -->

## 2. Triage (the L1 questions)
- **Internal or external?** **External** — the source is a public IP (not RFC1918).
- **Known asset / user?** Target is a managed host; the attempted usernames include invalid/
  non-existent accounts (`admin`, `test`, `oracle`) — not our real users.
- **Expected behavior?** No. No admin or automation legitimately hammers SSH with failed logins
  from a public address against this host.
- **Enrichment corroborates?** Yes — see §3, VirusTotal flags the IP.
- **Correlated?** Yes — this is the *correlation* rule (5+ failures), not a single 100001 event.
- **Severity vs impact?** Severity 10 matches: external, automated credential-guessing against a
  reachable host.

## 3. Enrichment
- Source classified **public** by the n8n workflow → routed to the VirusTotal enrichment branch.
- VirusTotal: **15 malicious detections** on the source IP → verdict `MALICIOUS`.
- No successful login observed after the failures (no matching `Accepted password` event).

<!-- EVIDENCE: attach VirusTotal score + n8n MALICIOUS verdict -->

## 4. Analysis
An external host is conducting an automated SSH credential-guessing attack. The username pattern
(common/default accounts) and rate (5+/120s) are consistent with a brute-force tool. Threat-intel
reputation corroborates the source is known-bad. No evidence of a successful authentication yet,
so this is an **attempt**, caught in progress.

## 5. Verdict
**True Positive** — external, reputation-flagged source conducting an SSH brute-force; behavior
and enrichment both corroborate.

## 6. Action taken
- **Automated containment fired:** Wazuh active-response `firewall-drop` blocked the source IP on
  `soc-endpoint` (timed, 600s auto-unblock). Confirmed via `iptables -L -n` and
  `/var/ossec/logs/active-responses.log`.
- Verified no successful login from the source before/after the block.

<!-- EVIDENCE: attach iptables drop + active-responses.log line -->

## 7. Escalation / handoff
**Escalated to L2.** Handoff: confirmed external SSH brute-force (T1110), source auto-blocked
(time-bound) and reputation-flagged (VT 15). Open questions for L2: (a) should the block be made
permanent / pushed to the perimeter firewall, (b) review other hosts for the same source IP,
(c) confirm no credential was guessed successfully across the estate.

## 8. IOCs
| Type | Value |
|------|-------|
| Source IP | <public IP> <!-- EVIDENCE --> |
| Attempted usernames | admin, test, oracle, root <!-- EVIDENCE --> |
| VT malicious count | 15 <!-- EVIDENCE --> |
