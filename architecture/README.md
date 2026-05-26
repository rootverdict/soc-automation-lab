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
2. **Detection.** The Wazuh agent ships endpoint telemetry (journald, auth events) to the manager. Custom rules in `local_rules.xml` match the behaviour and raise MITRE-mapped alerts.
3. **Forwarding.** The Wazuh integrator daemon invokes a custom integration script that POSTs alerts of level ≥ 7 to an n8n webhook over the SOC network.
4. **Automation and triage.** n8n extracts the IOC, classifies the source address (RFC1918 vs public), enriches public IOCs against VirusTotal, evaluates the malicious score, and routes the verdict.
5. **Notification.** A malicious verdict triggers an automated email to the analyst with the rule, MITRE technique, IOC, and VirusTotal score.
6. **Forensic validation.** Velociraptor collects a live VQL artifact from the endpoint to confirm the activity (for example, listing local accounts to confirm an account-creation attack).

## Key principle

Automation reduces response time, but context and validation still matter. The pipeline is designed so that a human analyst receives a small number of enriched, high-confidence alerts rather than a flood of raw events — and so that any automated verdict can be confirmed forensically.

## Network note

Because the lab's monitored traffic originates entirely from the private SOC subnet, all real alert source IPs are RFC1918 addresses. These correctly route to the "internal / skip enrichment" branch. The VirusTotal enrichment branch is exercised by injecting a known public IOC during testing — a documented lab limitation rather than a gap in the logic.
