# CASE-018 - Malicious file detected by hash reputation

| Field | Value |
|-------|-------|
| **Case ID** | CASE-018 |
| **Date/Time (UTC)** | 2026-07-2X 19:02:39 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh FIM (`554` file added) → VirusTotal hash enrichment integration flags the file |
| **Severity** | 10 |
| **MITRE technique** | T1105 - Ingress Tool Transfer / T1204 - User Execution |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Escalated - CRITICAL |
| **Detection source** | Wazuh syscheck + VirusTotal integration (hash lookup on new/changed files) |

## 1. Alert summary
A new file appeared on the host, and the Wazuh **VirusTotal integration** matched its **hash** to
a known-malicious sample (multiple AV detections). A known-bad binary is now on disk.

<!-- EVIDENCE: attach FIM add + VirusTotal hash verdict (detection count) -->

## 2. Triage (the L1 questions)
- **Internal or external?** File landed locally; delivery vector (download/transfer) is the question.
- **Known asset / user?** Which user/process wrote it, and where (temp, home, web root)?
- **Expected behavior?** A hash-flagged malicious file is never legitimate.
- **Enrichment corroborates?** VirusTotal detection count + malware family; higher count = higher confidence.
- **Correlated?** Was the file **executed** after being written (T1204)? Did it spawn processes/connections?
- **Severity vs impact?** Known malware on disk → top severity; executed → confirmed infection.

## 3. Enrichment
- Reviewed the VirusTotal result: **detection count**, family/label, first-seen date.
- Identified the writing process/user and the file location.
- Checked for **execution** post-write (process creation from that path, child processes, egress).

<!-- EVIDENCE: attach VT family/label + writing process + any execution evidence -->

## 4. Analysis
A file whose hash matches a known-malicious sample is high-confidence malicious (reputation-based,
not heuristic). If it was merely dropped, it is a staged tool (T1105); if it was executed, it is a
**confirmed infection** (T1204) and likely ties to the C2/reverse-shell case (CASE-014).

## 5. Verdict
**True Positive - malicious file present (T1105)**, escalating to **confirmed execution (T1204)**
if run. Hash reputation makes this high-confidence.

## 6. Action taken
- Preserved the file (hash + copy) as evidence - **did not delete** before scoping.
- Recommended quarantine via Velociraptor and blocking any associated C2 IP.

## 7. Escalation / handoff
**Escalated to L2/IR as CRITICAL.** Handoff: known-malicious file `<path>` (hash `<h>`, VT `<n>`
detections, family `<label>`), written by `<process/user>`, executed = `<yes/no>`. Open:
(a) quarantine, (b) determine delivery vector, (c) check for execution + C2 (CASE-014),
(d) hunt the hash across the estate.

## 8. IOCs
| Type | Value |
|------|-------|
| File | <path>/<name> |
| Hash | <sha256> <!-- EVIDENCE --> |
| VT detections | <n> / family <label> <!-- EVIDENCE --> |
