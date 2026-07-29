# CASE-012 - Rootkit / hidden process indicator (rootcheck)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-012 |
| **Date/Time (UTC)** | 2026-07-2X 20:05:18 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh rootcheck rule `510` - "Host-based anomaly / possible rootkit" (hidden process or file) |
| **Severity** | 8 |
| **MITRE technique** | T1014 - Rootkit |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Escalated |
| **Detection source** | Wazuh rootcheck (built-in anomaly detection) |

## 1. Alert summary
Wazuh rootcheck reported a host anomaly consistent with a rootkit - for example a **hidden
process** (visible to the kernel via `/proc` but not to `ps`) or a hidden/immutable file in a
system directory.

<!-- EVIDENCE: attach rootcheck alert detail -->

## 2. Triage (the L1 questions)
- **Internal or external?** Host-level anomaly; the concern is what is already resident.
- **Known asset / user?** Rootkits imply prior compromise + privilege - no legitimate use.
- **Expected behavior?** No - hidden processes/files are not normal system behavior.
- **Enrichment corroborates?** Rootcheck can false-positive on some legitimate software; the
  named artifact must be examined, not taken at face value.
- **Correlated?** Any prior compromise cases on this host (CASE-003/006/007)?
- **Severity vs impact?** Potential kernel/user-mode rootkit → high, but confirm before alarm.

## 3. Enrichment
- Examined the specific artifact rootcheck named (PID discrepancy, hidden path).
- Cross-checked with a live Velociraptor collection (process list, kernel modules, `/proc` vs `ps`).
- Ruled out known benign causes (some monitoring/AV agents trip rootcheck heuristics).

<!-- EVIDENCE: attach Velociraptor process/kernel-module output confirming or clearing the anomaly -->

## 4. Analysis
Rootcheck findings need corroboration - the ruleset flags heuristics that legitimate software can
trip. If Velociraptor confirms a genuinely hidden process or unexpected kernel module, this is a
**True Positive rootkit (T1014)** indicating deep compromise. If the artifact resolves to known-good
software, it is a **False Positive** to tune out.

## 5. Verdict
**True Positive - rootkit indicator** *if corroborated by live forensics*; otherwise **False
Positive** (documented benign cause). Verdict stated only after the Velociraptor check.

## 6. Action taken
- Ran the forensic confirmation before any action (host is potentially untrustworthy - treat
  tooling output with care).
- On confirmation, recommended host isolation and full IR (do not attempt in-place cleanup of a
  rootkitted host at L1).

## 7. Escalation / handoff
**Escalated to L2/IR** on confirmation. Handoff: rootcheck anomaly `<artifact>`, corroborated by
Velociraptor `<finding>`. Open: (a) isolate host, (b) full forensic image before remediation,
(c) determine initial access, (d) plan rebuild - a confirmed rootkit typically means reimage.

## 8. IOCs
| Type | Value |
|------|-------|
| Artifact | <hidden process / file path> <!-- EVIDENCE --> |
| Host | soc-endpoint (192.168.100.20) |
