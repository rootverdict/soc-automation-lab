# Demo - End-to-End Walkthrough

A single orchestrated run demonstrating the full pipeline: attack → detection → automated triage → forensic validation. This is the proof that the components work together, not just individually.

## Video Demo

[![End-to-End Pipeline Demo](https://img.shields.io/badge/Watch%20Demo-YouTube-red?logo=youtube)](https://youtu.be/5ahlclbnNrE)

## The scenario

An attacker creates a local user account on the monitored endpoint (a common persistence action, MITRE T1136). The pipeline detects it, triages it automatically, and confirms it forensically — with no manual steps between the attack and the forensic collection.

**Detection latency: ~3 seconds** from attack execution to alert.

## Why the internal verdict here

The attack originated on the endpoint itself (private SOC IP, `192.168.100.20`). The automation correctly classified this as RFC1918 and routed it to the `INTERNAL_SKIP_ENRICHMENT` branch — there is no value in a VirusTotal reputation lookup for a private address. This is the designed behaviour, not a gap.

## Validating the malicious path

Because all lab traffic is internal, the VirusTotal enrichment + malicious-notification branch was validated separately by feeding a known public IOC through the workflow:

| Step | Result |
|------|--------|
| IOC injected | `45.155.205.233` (public, flagged scanner) |
| VirusTotal lookup | `last_analysis_stats.malicious = 15` |
| Decision (`> 0`) | Routed to **MALICIOUS** branch |
| Notification | Automated email sent to analyst with rule, MITRE technique, IOC, and VT score |

This confirms the full enrichment-to-notification path works; the only reason it isn't exercised by lab traffic is that the lab has no malicious public source IPs (a documented limitation).

## The complete chain

```
Caldera / manual attack
        │  (useradd / SSH brute / sudo abuse)
        ▼
Wazuh agent ──▶ Wazuh manager ──▶ custom rule (MITRE-mapped) ──▶ integrator
        │
        ▼
n8n webhook ──▶ IOC extract ──▶ RFC1918 filter ─┬─ private ──▶ INTERNAL_SKIP
                                                 └─ public ──▶ VirusTotal ──▶ malicious? ─┬─ yes ──▶ email analyst
                                                                                          └─ no ──▶ CLEAN
        │
        ▼
Velociraptor ──▶ Linux.Sys.Users ──▶ forensic confirmation on endpoint
```

## Screenshots

See the `screenshots/` folder for captured evidence at each layer: the Wazuh detection, the n8n workflow canvas and execution path, the VirusTotal enrichment email, the Velociraptor collection results, and the Caldera operation.
