# CASE-006 — Repeated failed sudo (local privilege abuse)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-006 |
| **Date/Time (UTC)** | 2026-07-2X 11:15:52 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh rule `100011` — "SUDO ABUSE: repeated failed sudo" |
| **Severity** | 10 |
| **MITRE technique** | T1548.003 — Sudo and Sudo Caching |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Escalated |

## 1. Alert summary
Correlation rule `100011` fired: repeated failed `sudo` attempts by a user on `soc-endpoint`
within the timeframe. Repeated sudo failures suggest a user (or a compromised account) probing
for privilege escalation.

<!-- EVIDENCE: attach Wazuh alert screenshot (rule 100011, T1548.003) -->

## 2. Triage (the L1 questions)
- **Internal or external?** **Local** event — a user at a shell on the host. No source IP (this
  is why the response is a *host* action, not a firewall block).
- **Known asset / user?** Identify `srcuser`. Is it a real admin who legitimately has sudo, or a
  service/low-priv account that should never be running sudo?
- **Expected behavior?** A one-off failed sudo is normal (mistyped password). **Repeated** failures
  crossing the correlation threshold are not typical for a legitimate admin.
- **Enrichment corroborates?** N/A (local). Context comes from the account's role and recent activity.
- **Correlated?** Yes — the correlation rule (multiple failures) is what fired, not a single 100010.
- **Severity vs impact?** If the account is not a sanctioned sudoer, severity 10 is justified —
  this is attempted privilege escalation.

## 3. Enrichment (context)
- Reviewed `who` / recent auth for the offending user and session origin.
- Checked whether the account is in `sudo`/`wheel` and whether it has any business reason to
  escalate. In the lab run the failures come from an account that is **not** a sanctioned sudoer.

<!-- EVIDENCE: attach active-responses.log evidence block (who + auth.log tail) -->

## 4. Analysis
Repeated failed sudo by an account without a legitimate escalation need is consistent with
privilege-abuse probing (T1548.003) — either a curious/compromised local account or an attacker
who already has a foothold trying to elevate. The correlation threshold rules out a single typo.

## 5. Verdict
**True Positive — local privilege abuse (T1548.003).** Repeated unauthorized sudo attempts by a
non-sanctioned account.

## 6. Action taken (within L1 authority)
- **Automated host action fired:** the custom active-response script (`sudo-abuse-response.sh`)
  recorded evidence (active sessions + auth tail) and, per policy, ran in **log-only** mode by
  default — account locking is opt-in to avoid disrupting a legitimate user before L2 review.
- Notified the asset owner to confirm whether the user had any legitimate reason to escalate.

<!-- EVIDENCE: attach active-responses.log showing the sudo-abuse-response evidence block -->

## 7. Escalation / handoff
**Escalated to L2.** Handoff: repeated failed sudo by `<srcuser>` on `soc-endpoint` (T1548.003),
evidence captured, host action in log-only mode. Open questions for L2: (a) is the account
compromised or misused, (b) authorize account lock/disable, (c) check how the account obtained
shell access in the first place (tie back to any brute-force / account-creation cases).

## 8. IOCs
| Type | Value |
|------|-------|
| Account (srcuser) | <user> <!-- EVIDENCE --> |
| Host | soc-endpoint (192.168.100.20) |
| Pattern | repeated failed sudo within correlation window |
