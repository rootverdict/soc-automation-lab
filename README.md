# SOC Automation Lab

[![detections-ci](https://github.com/rootverdict/soc-automation-lab/actions/workflows/detections-ci.yml/badge.svg)](https://github.com/rootverdict/soc-automation-lab/actions/workflows/detections-ci.yml)

An end-to-end, open-source Security Operations Center (SOC) automation pipeline built from scratch. It takes a raw endpoint event and turns it into an enriched, triaged, and documented incident - automatically - with detection engineering, SOAR-style automation, threat enrichment, and forensic validation wired together.

This is a **learning and reference lab**, not a production deployment. The Linux detections were validated by executing the real attack against a live agent rather than replaying synthetic logs; the Windows detections are authored and awaiting that same treatment, and the [status table](#status---proven-vs-committed) says plainly which is which. Every failure encountered during the build is documented in [lessons-learned](./lessons-learned).

> **Reviewing this for SOC readiness?** Start with the [SOC L1 competency matrix](./docs/l1-competency-matrix.md) - it maps each Tier-1 analyst skill (triage, TP/FP decisioning, enrichment, containment, escalation, documentation) to where it's demonstrated with real work. Then open any [casebook](./casebook) case and read it top to bottom.

**[▶ Watch the end-to-end demo](https://youtu.be/5ahlclbnNrE)** (attack → detection → automated triage → forensic confirmation) - walkthrough notes in [demo_walkthrough.md](./demo_walkthrough.md), captured evidence at each layer in [screenshots/](./screenshots).

---

## What it does

An attacker action (e.g. creating a local account or brute-forcing SSH) is executed against a monitored Linux endpoint. Wazuh detects it with custom, MITRE-mapped rules and forwards the alert to an n8n automation workflow. n8n extracts the IOC, filters out internal (RFC1918) addresses, enriches public IOCs against VirusTotal, decides whether the activity is malicious, routes the verdict, and emails the analyst on a malicious finding. On a high-confidence verdict the pipeline **automatically contains** the threat - Wazuh active-response firewall-drops a brute-force source IP (timed, auto-reversing), and a gated n8n branch launches a Velociraptor remediation artifact on the host (committed; see [status](#status---proven-vs-committed)). Velociraptor also provides live forensic confirmation on the affected host. Every alert type is worked end-to-end in the analyst [casebook](./casebook) the way a SOC L1 handles it on shift.

```
[Attack Simulation]     [Detection]         [Automation / Triage / Response]         [Forensics]
   MITRE Caldera  ────▶  Wazuh SIEM  ────▶   n8n Workflow                    ────▶   Velociraptor
 (account creation,      (custom rules,       ├─ IOC extraction                       (live VQL
  SSH brute force,        MITRE-mapped)        ├─ RFC1918 filter                        artifact
  sudo abuse)                 │                ├─ VirusTotal enrichment                 collection)
                              │                ├─ verdict decision
                              │                ├─ email notification (malicious)
                              │                └─ launch host response (gated) ─┐
                              │                                                 ▼
                              └─ Active-Response ──▶ firewall-drop src IP    Velociraptor
                                 (timed, auto-revert) host action (sudo)     collect-then-contain
```

**Pipeline:** Detection → Enrichment → Triage → **Automated Response** → Notification → Forensic Validation

---

## Stack

| Tool | Version | Role |
|------|---------|------|
| **Wazuh** | 4.9.2 | SIEM - detection, custom rules, alert forwarding |
| **n8n** | 2.8.4 | Automation engine - webhook ingestion, enrichment, routing, notification |
| **VirusTotal API** | v3 | Threat intelligence - IOC reputation enrichment |
| **MITRE Caldera** | 5.3 | Adversary emulation - generates realistic attack telemetry |
| **Velociraptor** | 0.74 | Endpoint DFIR - live forensic artifact collection |

**Lab environment:** 2 × Ubuntu Server 22.04 VMs (VMware Workstation, host-only + NAT networking).
- `wazuh-server` (192.168.100.10) - Wazuh manager, indexer, dashboard
- `soc-endpoint` (192.168.100.20) - Wazuh agent, n8n, Caldera, Velociraptor

---

## Detection coverage (MITRE ATT&CK)

Five custom **Linux** rules authored in `local_rules.xml`, mapped to three techniques and validated by executing the matching attack (account creation additionally driven by a MITRE Caldera operation):

| Rule ID | Detection | MITRE Technique | Level |
|---------|-----------|-----------------|-------|
| 100001 | SSH authentication failure | T1110 - Brute Force | 5 |
| 100002 | SSH brute force (5+ fails / 120s, same source IP) | T1110 - Brute Force | 10 |
| 100010 | Failed sudo attempt | T1548.003 - Sudo and Sudo Caching | 7 |
| 100011 | Repeated failed sudo (correlation) | T1548.003 - Sudo and Sudo Caching | 10 |
| 100020 | Local account created | T1136 - Create Account | 8 |

Extended to **Windows** (Sysmon + PowerShell) in [`detections/windows/`](./detections/windows) - encoded PowerShell (T1059.001), scheduled-task persistence (T1053.005), Run-key persistence (T1547.001), and LSASS access (T1003.001), plus a level-0 suppression child for known-good LSASS accessors. These are **authored and CI-checked but not yet live-validated** - the Windows/Sysmon endpoint stand-up and the matching Atomic Red Team runs are the open item. The full analyst [casebook](./casebook) works a further set of cases off built-in telemetry (FIM, rootcheck, web ruleset, auditd, VirusTotal), whose enabling config is committed in [`detections/telemetry/`](./detections/telemetry).

**Totals:** 12 Wazuh rules (5 Linux + 7 Windows) and 11 portable Sigma rules, covering **7 ATT&CK techniques** from custom detections and 19 techniques once built-in telemetry sources are included.

Coverage across both platforms is visualized as a rendered [ATT&CK Navigator layer](./detections/coverage), and the attack → rule → technique → response → case chain is laid out in the [traceability matrix](./docs/traceability-matrix.md). Full detail and the rule source: [detections/](./detections).

### Detection-as-code

Rules are version-controlled and validated in CI ([`.github/workflows/detections-ci.yml`](./.github/workflows/detections-ci.yml)): XML syntax, a **sample-event test harness** ([`tests/`](./tests)) whose rule-firing assertions run on the live Wazuh manager, Sigma lint on the [portable Sigma equivalents](./detections/sigma), and a gitleaks secret scan. Break a rule's XML or Sigma in a PR and CI goes red.

---

## End-to-end validation

A single orchestrated run produced evidence at all four layers (≈3-second detection latency):

| Time (UTC) | Stage | Evidence |
|------------|-------|----------|
| T+0s  | **Attack** | `useradd e2e_attacker` executed on endpoint |
| T+3s  | **Detection** (Wazuh) | Rule `100020` - "ACCOUNT CREATED", T1136, agent `endpoint` |
| T+3s  | **Automation** (n8n) | Webhook → IOC extract → RFC1918 filter → verdict `INTERNAL_SKIP_ENRICHMENT` |
| T+5m  | **Forensics** (Velociraptor) | `Linux.Sys.Users` collection confirms `e2e_attacker` (uid 1015) |

The malicious path was separately validated by feeding a VirusTotal-flagged public IP (15 malicious detections) through the pipeline, which routed to the malicious branch and sent an automated analyst email.

---

## Status - proven vs. committed

Detection work is easy to overstate, so this repo separates **what has been run
and observed** from **what is written and reviewable but not yet exercised**.
Nothing below is padded in either direction.

| Component | Status |
|-----------|--------|
| Linux rules 100001/100002/100010/100011/100020 | **Validated by execution** - each fired on the real attack, confirmed in the dashboard |
| Rule 100020 (T1136) | **Validated by adversary emulation** - MITRE Caldera "Create local account" operation |
| n8n triage: extract → RFC1918 filter → VT enrich → verdict → notify | **Validated end-to-end**, both the internal and malicious branches |
| Velociraptor forensic confirmation (`Linux.Sys.Users`) | **Validated** - collection returned the attacker account |
| Wazuh `firewall-drop` active-response (rule 100002) | **Configured and deployed**; per-run timing not yet captured in [metrics](./validation/metrics.md) |
| Custom sudo host-action script (rule 100011) | **Committed and deployed**, log-only by default |
| Gated n8n → Velociraptor response branch | **Committed as workflow JSON, not yet exercised** against a live severity-10 event |
| Windows rules (T1059.001, T1053.005, T1547.001, T1003.001) | **Authored and CI-checked, not yet live-validated** - endpoint stand-up + Atomic Red Team pending |
| Casebook cases 001-018 | **Worked investigations against this lab's real rules and pipeline**; evidence fields marked `<!-- EVIDENCE -->` await capture from individual runs |
| MTTD / MTTR distributions | **Methodology defined, numbers pending** - only the single ~3s end-to-end run is measured |

The open items are tracked as such deliberately: back-filling them with invented
timestamps would make every other number in this repo worthless.

---

## Repository layout

| Path | Contents |
|------|----------|
| [`architecture/`](./architecture) | High-level design and data flow |
| [`detections/`](./detections) | `local_rules.xml`, MITRE mapping, sample alerts |
| [`detections/windows/`](./detections/windows) | Windows Sysmon + PowerShell rules (T1059.001, T1053.005, T1547.001, T1003.001) |
| [`detections/sigma/`](./detections/sigma) | Vendor-portable Sigma equivalents of the custom rules |
| [`detections/coverage/`](./detections/coverage) | ATT&CK Navigator coverage layer |
| [`detections/telemetry/`](./detections/telemetry) | FIM / auditd / web-log / VirusTotal config backing the casebook |
| [`tests/`](./tests) | Sample-event rule-firing tests (detection-as-code) |
| [`.github/workflows/`](./.github/workflows) | `detections-ci.yml` - XML syntax, test-harness, Sigma lint, secret scan |
| [`automation/`](./automation) | n8n workflow, Wazuh integration script, enrichment logic |
| [`response/`](./response) | Automated containment - Wazuh active-response, Velociraptor remediation artifact, gated n8n response branch, guardrails |
| [`casebook/`](./casebook) | SOC L1 analyst casebook - worked investigations (triage → enrich → verdict → escalate) |
| [`attack-simulation/`](./attack-simulation) | Caldera setup, custom ability, validation approach |
| [`validation/`](./validation) | Velociraptor deployment, forensic artifacts, and [SOC metrics](./validation/metrics.md) |
| [`docs/`](./docs) | [Traceability matrix](./docs/traceability-matrix.md) and [SOC L1 competency matrix](./docs/l1-competency-matrix.md) |
| [`lessons-learned/`](./lessons-learned) | Real failures encountered and how they were fixed |
| [`screenshots/`](./screenshots) | Captured evidence at each layer (Wazuh alerts, n8n execution, VT email, Velociraptor collection, Caldera operation) |
| [`demo_walkthrough.md`](./demo_walkthrough.md) | End-to-end walkthrough + [video demo](https://youtu.be/5ahlclbnNrE) |

---

## Design decisions worth noting

- **Threshold at the SIEM, not the automation layer.** Wazuh forwards only alerts of level ≥ 7, so noise is filtered before it reaches n8n. This keeps the automation focused and prevents alert fatigue downstream.
- **RFC1918 handling is explicit.** Private source IPs are detected and routed away from VirusTotal - public reputation lookups on internal addresses return nothing useful and waste API quota.
- **Notification only on a malicious verdict.** Clean and internal verdicts are logged but do not page the analyst, deliberately controlling alert volume.
- **Detections validated by execution, not assumption.** Caldera runs real adversary operations; rules are confirmed against actual event sequences rather than synthetic log injection.
- **Automated response is gated and reversible.** Containment fires only on high-confidence, correlated verdicts; the firewall block is time-bound (auto-reverts after 600s), the Velociraptor remediation defaults to DryRun, and evidence is collected *before* any destructive action. The response is also matched to the telemetry - a network block for brute-force (which has a source IP), a host action for local sudo abuse (which does not).
- **Response is documented as an analyst workflow, not just automation.** The [casebook](./casebook) shows each alert worked through triage, true/false-positive decisioning, enrichment, and escalation - the real SOC L1 job, not only the tooling.

---

## Disclaimer

All configurations are simplified and sanitized for a lab context. API keys, credentials, and secrets have been removed and replaced with placeholders. This is a reference build for learning detection engineering and SOC automation, not a hardened production system.
