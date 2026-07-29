# CASE-003 — Local account created (persistence)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-003 |
| **Date/Time (UTC)** | 2026-07-2X 16:20:04 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh rule `100020` — "ACCOUNT CREATED: new user added to system" |
| **Severity** | 8 |
| **MITRE technique** | T1136 — Create Account |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Escalated |

## 1. Alert summary
Rule `100020` fired: a new local user account was created on `soc-endpoint`. Account creation is
a classic **persistence** mechanism — an attacker adding a foothold that survives reboots and
password resets.

<!-- EVIDENCE: attach Wazuh alert screenshot (rule 100020, T1136) -->

## 2. Triage (the L1 questions)
- **Internal or external?** The action is local to the host (executed on the endpoint).
- **Known asset / user?** The new account (`e2e_attacker` / `caldera_t1136` in lab runs) is
  **not** a provisioned user — it does not match any known/managed account.
- **Expected behavior?** No scheduled onboarding, provisioning job, or change ticket accounts for
  a new local user on this host at this time.
- **Enrichment corroborates?** N/A for a local account event; enrichment here is **forensic**
  (Velociraptor), not reputation-based.
- **Correlated?** Check for surrounding activity — how was the account created, and by whom
  (preceding sudo/privilege events)?
- **Severity vs impact?** Persistence on a monitored host is meaningful; severity 8 is appropriate.

## 3. Enrichment (forensic)
- Triggered a **Velociraptor** `Linux.Sys.Users` collection on the endpoint to confirm the
  account exists live on disk (not just a log artifact).
- Result: the new user is present with a fresh UID (e.g. uid 1015), confirming the creation.

<!-- EVIDENCE: attach Velociraptor Linux.Sys.Users output showing the account -->

## 4. Analysis
An unrecognized local account was created on a monitored host with no corresponding change/
onboarding record, and Velociraptor confirms it exists live. This matches T1136 persistence.
Without a legitimate business reason, this is treated as unauthorized.

## 5. Verdict
**True Positive — persistence (T1136).** Unauthorized local account creation, forensically
confirmed on the host.

## 6. Action taken (within L1 authority)
- Forensic confirmation collected (above) — **evidence preserved before any remediation**.
- Flagged the account for removal; did **not** unilaterally delete pending L2 sign-off (deleting
  destroys evidence and may need scoping first).

## 7. Escalation / handoff
**Escalated to L2.** Handoff: confirmed unauthorized local account `<name>` (uid `<n>`) created on
`soc-endpoint`, forensically verified via Velociraptor, mapped to T1136. Open questions for L2:
(a) how was it created — what process/parent and which existing account performed it,
(b) does the account have sudo/group membership granting privilege, (c) authorize removal and
check other hosts for the same account name.

## 8. IOCs
| Type | Value |
|------|-------|
| Account name | e2e_attacker <!-- EVIDENCE --> |
| UID | 1015 <!-- EVIDENCE --> |
| Host | soc-endpoint (192.168.100.20) |
