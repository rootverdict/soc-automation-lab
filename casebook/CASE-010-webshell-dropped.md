# CASE-010 — Web shell dropped in web root (FIM)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-010 |
| **Date/Time (UTC)** | 2026-07-2X 18:41:07 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh FIM/syscheck rule `554` — "File added to the system" (new `.php` in web root) |
| **Severity** | 10 |
| **MITRE technique** | T1505.003 — Web Shell |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Escalated — CRITICAL |
| **Detection source** | Wazuh syscheck (FIM) on the web root — requires a web server + syscheck on its docroot |

## 1. Alert summary
A new file (`.php`) appeared in the web server's document root. An unexpected script in the web
root is a classic **web shell** — remote code execution persistence reachable over HTTP.

<!-- EVIDENCE: attach FIM "file added" alert with path + hash -->

## 2. Triage (the L1 questions)
- **Internal or external?** The file landed locally, but the delivery vector is likely a web request.
- **Known asset / user?** Web root files should only change via a sanctioned deploy — did one run?
- **Expected behavior?** No deploy/change record → highly suspicious.
- **Enrichment corroborates?** Hash the file and check VirusTotal; inspect content for web-shell markers.
- **Correlated?** Cross-reference web access logs for the request that wrote it.
- **Severity vs impact?** RCE persistence — top severity.

## 3. Enrichment
- Computed the file **hash** → VirusTotal lookup (web-shell families are often flagged).
- Inspected content for tell-tale functions (`eval`, `system`, `base64_decode`, `passthru`).
- Correlated web access logs around the create time for the uploading request and source IP.

<!-- EVIDENCE: attach VT hash result + web-shell content markers + uploading source IP -->

## 4. Analysis
An unauthorized executable script placed in the web root, matching web-shell characteristics, is a
confirmed compromise vector: it gives an attacker code execution on the server via HTTP. Delivery
almost always ties to a preceding web attack (see CASE-011 SQLi/upload abuse).

## 5. Verdict
**True Positive — web shell (T1505.003).** Unauthorized code-execution artifact in the web root.

## 6. Action taken
- Preserved the file (hash + copy) as evidence — **did not delete** it before scoping.
- Recommended isolating the web service / removing the file under L2 direction, and blocking the
  uploading source IP.

## 7. Escalation / handoff
**Escalated to L2 as CRITICAL.** Handoff: web shell `<path>` (hash `<h>`) dropped via `<source
IP>`. Open for L2/IR: (a) determine the initial vector (vuln/upload), (b) check for additional
shells and command execution through it, (c) remove + patch, (d) scope data access.

## 8. IOCs
| Type | Value |
|------|-------|
| File | <web root path>/<name>.php |
| Hash | <sha256> <!-- EVIDENCE --> |
| Uploading source IP | <public IP> <!-- EVIDENCE --> |
