# CASE-002 - SSH brute-force from internal host (false positive)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-002 |
| **Date/Time (UTC)** | 2026-07-2X 09:47:33 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh rule `100002` - "SSH BRUTE FORCE: 5+ failures from <srcip> in 120s" |
| **Severity** | 10 |
| **MITRE technique** | T1110 - Brute Force |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Closed - False Positive |

## 1. Alert summary
The same correlation rule `100002` fired, but the source IP is **internal** (`192.168.100.10`,
the Wazuh/admin host). Multiple failed SSH logins in a short window triggered the brute-force
pattern.

<!-- EVIDENCE: attach Wazuh alert screenshot (source = internal IP) -->

## 2. Triage (the L1 questions)
- **Internal or external?** **Internal** - RFC1918, and specifically the known admin/management host.
- **Known asset / user?** Yes - the source is our own admin box; the username tried is a real
  admin account, not a spray of default accounts.
- **Expected behavior?** Plausibly - an admin repeatedly failing SSH (wrong key, expired
  password, an automation/Ansible run with a stale credential) produces the same failure pattern.
- **Enrichment corroborates?** N/A - internal source, so the n8n workflow routes to
  `INTERNAL_SKIP_ENRICHMENT` (VirusTotal has no useful reputation for RFC1918).
- **Correlated?** Yes, but correlation alone doesn't make it malicious - the *source context*
  changes the meaning.
- **Severity vs impact?** Severity 10 overstates the real risk here; the source is trusted.

## 3. Enrichment
- Source classified **private/RFC1918** → routed to internal branch, verdict
  `INTERNAL_SKIP_ENRICHMENT`. No external reputation lookup (correct behavior).
- Checked auth log: failures are for a **single known admin account**, followed shortly by a
  **successful** login from the same host - consistent with an admin fixing their own credential.

<!-- EVIDENCE: attach auth.log excerpt showing eventual Accepted for the admin user -->

## 4. Analysis
The alert is technically accurate (5+ failures did occur) but the activity is **not malicious**:
an internal, trusted admin host, a real account, a failure-then-success pattern typical of a
credential/key mix-up rather than guessing. This is exactly the FP an L1 must recognize instead
of reflexively escalating.

## 5. Verdict
**False Positive** - internal trusted source; failed-then-successful login by a legitimate admin
account. Not an attack.

## 6. Action taken
- No containment. Confirmed the admin host is **whitelisted** in the active-response config so it
  cannot be auto-blocked (verified no firewall-drop fired for this event).
- Closed the case with the justification above.

## 7. Escalation / handoff
**Not escalated.** Instead, **tuning recommendation** logged for detection engineering:
- Add internal management hosts to a brute-force exclusion list, **or**
- Lower severity when `srcip` is RFC1918 and the target account exists and later authenticates
  successfully within the window.

This keeps the external detection (CASE-001) sharp while cutting internal-admin noise.

## 8. IOCs
| Type | Value |
|------|-------|
| Source IP | 192.168.100.10 (internal admin host) |
| Account | <admin user> <!-- EVIDENCE --> |
| Outcome | failures followed by successful login (benign) |
