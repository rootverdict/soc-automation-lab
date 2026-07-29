# SOC L1 Competency Matrix

What a Tier-1 SOC analyst is actually expected to do on shift — and where in this
repo each competency is demonstrated with real work, not a claim. This is the
"can this person do the L1 job?" checklist, answered with evidence.

## Core analyst competencies

| L1 competency | Demonstrated by | Where |
|---------------|-----------------|-------|
| **Alert triage** — pick up an alert, establish what fired, decide real vs noise | 16 worked cases, each following a fixed triage workflow | [casebook/](../casebook) |
| **True / false / benign-positive decisioning** | Deliberate verdict mix (12 TP · 1 FP · 2 benign-TP · 1 conditional) with written rationale | [CASE-002 (FP)](../casebook/CASE-002-ssh-bruteforce-internal.md), [CASE-008 (benign-TP)](../casebook/CASE-008-ssh-anomalous-geo-login.md), [CASE-017](../casebook/CASE-017-recon-tool-installed.md) |
| **IOC extraction & enrichment** | Pull IP/hash/user, VirusTotal reputation, RFC1918 internal/external split | [automation/](../automation), each case §3 |
| **Internal vs external scoping** | RFC1918 filter routes private IPs away from VT; documented triage question | [CASE-001](../casebook/CASE-001-ssh-bruteforce-external.md) vs [CASE-002](../casebook/CASE-002-ssh-bruteforce-internal.md) |
| **MITRE ATT&CK mapping** | Every alert tagged to a technique; coverage visualized | [coverage map](../detections/coverage), [traceability](traceability-matrix.md) |
| **Containment within L1 authority** | Confirm automated firewall-drop / host action; know its limits | [CASE-001 §6](../casebook/CASE-001-ssh-bruteforce-external.md), [response/](../response) |
| **Escalation to L2 with clean handoff** | Each TP states what fired, why it's a TP, what's contained, IOCs, open question | [CASE-007](../casebook/CASE-007-ssh-successful-login-post-bruteforce.md) (CRITICAL escalation) |
| **Ticket documentation** | Consistent case template: summary → triage → enrich → verdict → action → IOCs | [CASE-TEMPLATE](../casebook/CASE-TEMPLATE.md) |
| **Working the whole sensor stack** | Cases span custom rules, FIM, rootcheck, web ruleset, auditd, VT — not one source | [telemetry/](../detections/telemetry), casebook source map |
| **Recognizing an attack chain** | Cases ordered initial-access → execution → persistence → C2 → anti-forensics | [casebook/README](../casebook/README.md) |
| **SLA / time awareness** | MTTD and MTTR measured with stated methodology | [validation/metrics.md](../validation/metrics.md) |
| **False-positive tuning judgment** | Suppression pattern (level-0 child rule / known-good accessor allow-list) documented | [detections/README](../detections/README.md), [windows rule 100132](../detections/windows/windows_rules.xml) |

## Adjacent / above-L1 signals (shows range)

| Competency | Demonstrated by | Where |
|------------|-----------------|-------|
| **Detection engineering** | 5 Linux + 7 Windows custom rules (4 techniques), tiered severity, correct base-rule mapping | [detections/](../detections) |
| **Detection-as-code** | Version control + CI that validates syntax and asserts rules fire | [CI](../.github/workflows/detections-ci.yml), [tests/](../tests) |
| **SOAR / automation** | n8n triage workflow: extract → filter → enrich → verdict → notify → gated response | [automation/](../automation), [response/](../response) |
| **DFIR / live forensics** | Velociraptor VQL artifact confirms activity on the host | [validation/](../validation) |
| **Adversary emulation** | Caldera + Atomic Red Team drive real telemetry; rules validated by execution | [attack-simulation/](../attack-simulation) |
| **Engineering judgment** | Documented failure→fix log and explicit design decisions | [lessons-learned/](../lessons-learned) |

## How to read this as a hiring manager

Start with any [casebook](../casebook) case and read it top to bottom: it shows
the analyst taking an alert, asking the standard triage questions, enriching it,
reaching a **defensible verdict**, acting within L1 authority, and escalating
cleanly — the actual L1 job. The [traceability matrix](traceability-matrix.md)
then proves each case is backed by a real detection and technique, and the
rest of the repo shows the detection-engineering and automation depth behind it.
