# ATT&CK Coverage Map

A [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
layer that visualizes what this lab detects, across Linux and Windows, at a
glance.

## The layer

[`attack-navigator-layer.json`](attack-navigator-layer.json) - 19 techniques
scored on two tiers:

| Score | Colour | Meaning |
|-------|--------|---------|
| **100** | dark green | Custom MITRE-mapped rule authored **and validated by emulated attack** (7 techniques, Linux + Windows) |
| **50** | light green | Worked in the analyst [casebook](../../casebook) using **built-in Wazuh telemetry** - FIM, rootcheck, web ruleset, auditd, VirusTotal integration (12 techniques) |

Every technique comment names the rule ID and/or the casebook case it maps to,
so the map is traceable back to a real artifact - not aspirational coverage.

## Render it

1. Open <https://mitre-attack.github.io/attack-navigator/>
2. **Open Existing Layer → Upload from local** → select `attack-navigator-layer.json`
3. Export to SVG/PNG and drop it in [`screenshots/`](../../screenshots) as
   `attack-coverage-map.png` (referenced from the top-level README).

Offline: `docker run -p 4200:4200 mitre/attack-navigator` and upload the same file.

## Scope note

Coverage tiers are honest on purpose. Dark-green techniques are backed by a rule
in [`local_rules.xml`](../local_rules.xml) / [`windows/`](../windows) that fires
on a real attack. Light-green techniques are analyst-worked in the casebook on
built-in detections - real telemetry, but not a custom-authored rule. The split
mirrors how a real SOC covers ATT&CK: a few high-fidelity custom detections over
a broad base of vendor content.
