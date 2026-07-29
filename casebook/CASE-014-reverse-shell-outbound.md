# CASE-014 - Suspicious outbound connection (reverse shell)

| Field | Value |
|-------|-------|
| **Case ID** | CASE-014 |
| **Date/Time (UTC)** | 2026-07-2X 21:20:03 <!-- EVIDENCE: replace with real run --> |
| **Analyst** | L1 |
| **Source alert** | Wazuh command/audit rule - shell process with an outbound socket to an external IP (e.g. `bash`/`nc`/`python` spawning a network connection) |
| **Severity** | 10 |
| **MITRE technique** | T1059.004 - Command and Scripting Interpreter: Unix Shell / T1071.001 - Application Layer Protocol: Web Protocols (C2) |
| **Asset** | soc-endpoint (192.168.100.20) |
| **Status** | Escalated - CRITICAL |
| **Detection source** | Wazuh command monitoring / auditd (requires audit or command-wodle config) |

## 1. Alert summary
A shell interpreter established an **outbound connection to an external IP on an unusual port** -
the signature of a **reverse shell** (host dialing out to an attacker-controlled listener for
command-and-control).

<!-- EVIDENCE: attach the process + destination IP:port from the alert -->

## 2. Triage (the L1 questions)
- **Internal or external?** Destination is external (attacker infrastructure).
- **Known asset / user?** What process/user opened it? A `bash`/`python`/`nc` egress is abnormal
  for a server that shouldn't dial out.
- **Expected behavior?** No - servers rarely open interactive shells to the internet.
- **Enrichment corroborates?** Reputation-check the destination IP; is the port a known C2 pattern?
- **Correlated?** Follows other compromise indicators on this host (CASE-007/010/013)?
- **Severity vs impact?** Active C2 channel → top severity.

## 3. Enrichment
- Identified the process tree (parent → shell → socket) and the destination IP:port.
- VirusTotal / AbuseIPDB on the destination.
- Checked whether this destination appears in the cron/web-shell cases (shared infrastructure).

<!-- EVIDENCE: attach process tree + destination reputation -->

## 4. Analysis
An interactive shell with an outbound socket to external infrastructure is a **live C2 channel**
(reverse shell). Combined with prior compromise indicators, this confirms the attacker has
hands-on-keyboard access to the host.

## 5. Verdict
**True Positive - command-and-control / reverse shell.** Active outbound C2 from a shell process.

## 6. Action taken
- **Containment path:** the gated n8n response branch launches the Velociraptor remediation
  artifact (collect-then-contain) to snapshot the process/connection and, once trusted, kill it;
  the destination IP is added to the firewall deny list.
- Preserved the process tree and network evidence first.

## 7. Escalation / handoff
**Escalated to L2/IR as CRITICAL.** Handoff: active reverse shell from `<process>` (pid `<n>`) to
`<dst IP:port>`. Contained via `<action>`. Open: (a) confirm session killed, (b) determine what
was executed over the channel, (c) isolate host, (d) hunt the destination IP across the estate.

## 8. IOCs
| Type | Value |
|------|-------|
| Process | <bash/python/nc> (pid) <!-- EVIDENCE --> |
| Destination | <IP:port> <!-- EVIDENCE --> |
| Host | soc-endpoint (192.168.100.20) |
