# CASE-011 — SQL injection attempt (web access log)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-011 |
| **Date/Time (UTC)** | 2026-07-2X 18:33:55 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh web ruleset — "SQL injection attempt" (Apache/Nginx access log) |
| **Severity** | 7 |
| **MITRE technique** | T1190 — Exploit Public-Facing Application |
| **Asset** | soc-endpoint (192.168.100.20) — web service |
| **Status** | Escalated |
| **Detection source** | Wazuh web ruleset — requires the web server access log shipped to the agent |

## 1. Alert summary
The Wazuh web ruleset flagged a request containing **SQL-injection syntax** (e.g. `' OR '1'='1`,
`UNION SELECT`, `information_schema`) against the web application on the endpoint.

<!-- EVIDENCE: attach Wazuh alert with the offending request URI -->

## 2. Triage (the L1 questions)
- **Internal or external?** Check the client IP — external scanning vs an internal test.
- **Known asset / user?** The target is the public-facing web app.
- **Expected behavior?** SQLi payloads are never legitimate user traffic.
- **Enrichment corroborates?** VirusTotal / AbuseIPDB on the client IP; is it a known scanner?
- **Correlated?** Single probe or a sustained campaign (many payloads / paths)? Any 200-response
  suggesting success vs 403/500 suggesting it was blocked/errored?
- **Severity vs impact?** Depends on whether the app is vulnerable and whether the injection returned data.

## 3. Enrichment
- Reviewed the **HTTP response code** for the malicious requests — did any injection return `200`
  with data (possible success) vs `403/404/500` (blocked/failed)?
- Reputation-checked the source IP.
- Counted attempts and payload variety to gauge automated vs manual.

<!-- EVIDENCE: attach access-log lines with payloads + response codes + source IP reputation -->

## 4. Analysis
An external source is probing the web app for SQL injection (T1190). Whether this is a
**True Positive attack in progress** (many payloads, automated tooling) or a low-value scanner
depends on volume and any sign of success. Absent evidence of a successful extraction it is an
**attempted** exploit; a `200` with reflected DB content would escalate it to a likely breach.

## 5. Verdict
**True Positive — exploitation attempt (T1190).** External SQL-injection probing of the web app.
(Reclassify to confirmed exploitation if any payload returned database content.)

## 6. Action taken
- Recommended blocking the source IP (and adding it to a WAF/deny list if present).
- Flagged the targeted endpoint/parameter for the app team.

## 7. Escalation / handoff
**Escalated to L2 / app team.** Handoff: SQLi probing of `<endpoint>` from `<source IP>`,
`<N>` payloads, response codes `<...>`. Open: (a) confirm the parameter is not injectable,
(b) review for any successful extraction, (c) patch/parameterize the query, (d) correlate with
CASE-010 (web shell) in case the injection led to file write.

## 8. IOCs
| Type | Value |
|------|-------|
| Source IP | <public IP> <!-- EVIDENCE --> |
| Targeted endpoint | <URI/parameter> <!-- EVIDENCE --> |
| Sample payload | `' UNION SELECT ...` <!-- EVIDENCE --> |
