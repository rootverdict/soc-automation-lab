# SOC Metrics - Methodology & Results

Quantified outcomes for the pipeline. The point of this file is **defensible
numbers**: every metric states exactly what starts and stops the clock, the
sample size, and how it was measured - so a number can be explained in an
interview, not just quoted.

> **Current state:** one metric is measured (detection latency, from the
> documented end-to-end run); the rest have a defined method and no captured
> distribution yet. Rows are marked `measured` or `pending` below rather than
> being filled with plausible-looking numbers - an invented median would make
> every other figure in this repo unciteable. The measurement procedure is in
> [§ Measurement method](#measurement-method-reproducible); running it is
> ~20 minutes of lab time per metric.

## Definitions (what each clock measures)

| Metric | Start event | Stop event | Source of truth |
|--------|-------------|------------|-----------------|
| **MTTD** - mean time to detect | Attacker action executed on endpoint | Wazuh alert written | attack timestamp vs `alerts.json` `timestamp` |
| **MTTR (auto)** - mean time to respond | Wazuh alert written | Active-response block applied | `alerts.json` vs `active-responses.log` |
| **Triage latency** | Alert forwarded to n8n | n8n verdict reached | n8n execution start vs verdict node |
| **FP rate** | - | - | casebook verdicts: FP ÷ total worked |

## Results

| Metric | State | n (runs) | Min | Median | Max | Notes |
|--------|-------|----------|-----|--------|-----|-------|
| MTTD (account creation, rule 100020) | **measured** (single run) | 1 | - | ~3s | - | attack → alert, from the documented end-to-end run (see README); needs n ≥ 5 for a defensible distribution |
| MTTD (SSH brute force, rule 100002) | *pending* | - | | | | correlation adds the frequency window (5 fails/120s), so this clock is not comparable to 100020 |
| MTTR auto (firewall-drop) | *pending* | - | | | | target < 30s; alert → iptables DROP. The response is deployed; only the timing is uncaptured |
| Triage latency (n8n) | *pending* | - | | | | webhook → verdict node |
| Gated response latency (Velociraptor branch) | *pending* | - | | | | branch is committed but not yet exercised - see [response/n8n/](../response/n8n/response-branch-build-steps.md) |
| FP rate | **measured** | 16 worked | - | - | - | 1 FP / 16 cases = 6.25% (casebook mix, not tuning-representative) |

## Measurement method (reproducible)

1. **Timestamp the attack.** Wrap the attacker action so its execution time is
   logged (`date -u +%s.%N` immediately before `useradd`/the brute-force loop).
2. **Pull the alert time** from `/var/ossec/logs/alerts/alerts.json` for the
   matching `rule.id`.
3. **Pull the response time** from `/var/ossec/logs/active-responses.log` (the
   `firewall-drop` add line) for MTTR.
4. **Repeat n ≥ 5 times**, discard the first (cold-cache) run, report
   min/median/max - a single number hides variance and reads as cherry-picked.

```bash
# Example: detection latency for one account-creation run
t_attack=$(date -u +%s.%N); sudo useradd e2e_attacker
# ... then read the rule 100020 alert timestamp from alerts.json and subtract.
```

## Honesty notes

- The **~3s MTTD** figure is from a *single* documented end-to-end run. It is
  quoted in the README as "≈3s" for that reason - it is one observation, not a
  median, and should be described that way in conversation too.
- **FP rate here is casebook-derived** (a deliberately mixed teaching set), so it
  is *not* a production false-positive rate - it demonstrates TP/FP decisioning,
  and is labelled as such rather than dressed up as a tuning metric.
- MTTR applies to the **network** response (brute-force → firewall-drop). The
  host action (sudo abuse) and the gated Velociraptor branch are measured
  separately because they are triggered differently.
