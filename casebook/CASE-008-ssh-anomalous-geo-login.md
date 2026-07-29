# CASE-008 - SSH login from anomalous location (benign true positive)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-008 |
| **Date/Time (UTC)** | 2026-07-2X 03:14:09 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh rule `5715` (SSH authentication success) + geolocation/enrichment flag |
| **Severity** | 6 |
| **MITRE technique** | T1078 - Valid Accounts |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Closed - Benign True Positive |
| **Detection source** | SSH ruleset (built-in) + GeoIP enrichment |

## 1. Alert summary
A successful SSH login for a valid user occurred from a **public IP in an unusual geolocation**
and **outside normal working hours**. No failed attempts preceded it (single clean success).

<!-- EVIDENCE: attach Wazuh alert + GeoIP location -->

## 2. Triage (the L1 questions)
- **Internal or external?** External, but a **single clean success** - not a brute-force pattern.
- **Known asset / user?** The account is a legitimate, provisioned user.
- **Expected behavior?** Possibly - remote work, travel, or a VPN exit node can produce an
  off-hours login from an unexpected region.
- **Enrichment corroborates?** GeoIP shows a new region; VirusTotal shows the IP is **clean**
  (no detections) - lowers suspicion.
- **Correlated?** No preceding failures, no follow-on suspicious activity.
- **Severity vs impact?** Low-to-moderate; needs confirmation, not immediate containment.

## 3. Enrichment
- VirusTotal on the source IP: **0 malicious** - likely a residential/VPN address, not known-bad.
- Checked the user's recent login history for a baseline: is this region/time ever seen before?
- No sensitive commands or privilege escalation followed the login.

<!-- EVIDENCE: attach VT clean result + user login baseline -->

## 4. Analysis
The alert is accurate (a real off-hours login from a new location) but the weight of evidence
points to **legitimate access**: valid account, clean IP reputation, no brute-force, no malicious
follow-on. The right L1 move is **verify with the user**, not escalate blindly - but also not
dismiss, since anomalous-location logins are a real account-takeover indicator.

## 5. Verdict
**Benign True Positive** - real anomalous login, confirmed as the legitimate user working
remotely. (If the user denies it → immediately reclassify as TP account takeover and escalate.)

## 6. Action taken
- Contacted the account owner (out-of-band) to confirm the login.
- Owner confirmed remote access → closed as benign, with the new location noted to the baseline.

## 7. Escalation / handoff
**Not escalated.** Documented the verification. Tuning note: consider an allow-list of known
remote regions/VPN ranges per user to reduce off-hours false alarms without blinding the detection.

## 8. IOCs
| Type | Value |
|------|-------|
| Source IP | <public IP> (VT clean) <!-- EVIDENCE --> |
| Account | <user> |
| Location / time | <region>, off-hours <!-- EVIDENCE --> |
