# ATT&CK Coverage Map

A [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
layer that visualizes what this lab detects, across Linux and Windows, at a
glance.

## The layer

[`attack-navigator-layer.json`](attack-navigator-layer.json) - 19 techniques
scored on two tiers:

| Score | Colour | Meaning |
|-------|--------|---------|
| **100** | dark green | Custom MITRE-mapped rule authored (7 techniques, Linux + Windows). The 3 Linux techniques are **validated by execution**; the 4 Windows techniques are **authored, live validation pending** - each technique comment says which |
| **50** | light green | Worked in the analyst [casebook](../../casebook) using **built-in Wazuh telemetry** - FIM, rootcheck, web ruleset, auditd, VirusTotal integration (12 techniques) |

Every technique comment names the rule ID and/or the casebook case it maps to,
so the map is traceable back to a real artifact - not aspirational coverage.

## Render it

1. Open <https://mitre-attack.github.io/attack-navigator/>
2. **Open Existing Layer → Upload from local** → select `attack-navigator-layer.json`
3. Export to SVG/PNG and drop it in [`screenshots/`](../../screenshots) as
   `attack-coverage-map.png` - not yet captured.

Offline: `docker run -p 4200:4200 mitre/attack-navigator` and upload the same file.

## Scope note

Coverage tiers are honest on purpose. Dark-green techniques are backed by a rule
in [`local_rules.xml`](../local_rules.xml) / [`windows/`](../windows) - the Linux
ones proven to fire on a real attack, the Windows ones authored and awaiting the
endpoint build (a map that scored them identically would be overstating
coverage). Light-green techniques are analyst-worked in the casebook on
built-in detections - real telemetry, but not a custom-authored rule. The split
mirrors how a real SOC covers ATT&CK: a few high-fidelity custom detections over
a broad base of vendor content.
