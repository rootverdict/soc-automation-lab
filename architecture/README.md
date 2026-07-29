# Architecture

This section documents how telemetry moves between the components of the lab. The emphasis is on the flow of an alert from detection through to forensic validation, not on exact deployment commands.

## Components and hosts

The lab runs on two Ubuntu Server 22.04 virtual machines on VMware Workstation. Each VM has two network interfaces: a host-only adapter on the SOC network (`192.168.100.0/24`) for VM-to-VM traffic, and a NAT adapter for internet access (package installs, VirusTotal lookups).

| Host | SOC IP | Components |
|------|--------|------------|
| `wazuh-server` | 192.168.100.10 | Wazuh manager, Wazuh indexer, Wazuh dashboard, integrator daemon |
| `soc-endpoint` | 192.168.100.20 | Wazuh agent, n8n, MITRE Caldera, Velociraptor (server + client) |

## Data flow

1. **Attack execution.** MITRE Caldera runs an adversary operation against a Sandcat agent on the endpoint, generating real authentication, account, and privilege-escalation events.
2. **Detection.** The Wazuh agent ships endpoint telemetry (journald, auth events, and - for the broader casebook - FIM/syscheck, auditd, rootcheck, and web-server logs) to the manager. Custom rules in `local_rules.xml` (Linux) and `windows/windows_rules.xml` (Windows Sysmon + PowerShell) match the behaviour and raise MITRE-mapped alerts. The rules are version-controlled and CI-tested (see [`.github/workflows/detections-ci.yml`](../.github/workflows/detections-ci.yml)) and have vendor-portable [Sigma](../detections/sigma) equivalents.
3. **Forwarding.** The Wazuh integrator daemon invokes a custom integration script that POSTs alerts of level ≥ 7 to an n8n webhook over the SOC network.
4. **Automation and triage.** n8n extracts the IOC, classifies the source address (RFC1918 vs public), enriches public IOCs against VirusTotal, evaluates the malicious score, and routes the verdict.
5. **Notification.** A malicious verdict triggers an automated email to the analyst with the rule, MITRE technique, IOC, and VirusTotal score.
6. **Automated response (gated).** On a high-confidence, correlated verdict the pipeline contains the threat. Wazuh active-response firewall-drops a brute-force source IP on the affected agent (time-bound, auto-reverting after 600s); local sudo abuse - which has no source IP - instead triggers a custom host action. A gated n8n branch (`severity == 10 AND (VirusTotal malicious OR correlation rule 100002/100011)`) launches a Velociraptor remediation artifact that collects evidence *before* any containment and defaults to DryRun. See [`response/`](../response).
7. **Forensic validation.** Velociraptor collects a live VQL artifact from the endpoint to confirm the activity (for example, listing local accounts to confirm an account-creation attack).

## Key principle

Automation reduces response time, but context and validation still matter. The pipeline is designed so that a human analyst receives a small number of enriched, high-confidence alerts rather than a flood of raw events - and so that any automated verdict can be confirmed forensically. Automated containment is deliberately **gated and reversible** (high-confidence trigger, time-bound firewall block, DryRun-by-default remediation, evidence-before-containment) so that response speed never comes at the cost of an unrecoverable false-positive action.

## Diagram

[`diagram.svg`](diagram.svg) is the editable source of the architecture diagram
and reflects the current pipeline (cross-platform detection, the Active-Response
containment loop, and the detection-as-code layer). `diagram.png` is a raster
export and should be **re-exported from the SVG** after edits to stay in sync.

## Network note

Because the lab's monitored traffic originates entirely from the private SOC subnet, all real alert source IPs are RFC1918 addresses. These correctly route to the "internal / skip enrichment" branch. The VirusTotal enrichment branch is exercised by injecting a known public IOC during testing - a documented lab limitation rather than a gap in the logic.
