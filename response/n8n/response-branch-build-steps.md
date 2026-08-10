# n8n Response Branch - design and verification

The **automated host-response branch** is committed in
[`../../automation/wazuh-triage-workflow.json`](../../automation/wazuh-triage-workflow.json)
(nodes `Response Gate` → `Should Respond?` → `Dedup Guard` →
`Velociraptor Remediation`). This document explains why it is shaped the way it
is, and how to verify it once imported.

The Wazuh firewall-drop (see [`../wazuh/`](../wazuh)) handles the *network* block
independently and does not depend on this branch. This branch handles the
*endpoint* response by launching the Velociraptor remediation artifact - and only
on a high-confidence verdict.

> **Validation status:** authored and committed, **not yet exercised against a
> live severity-10 event**. Run the verification below before describing it as
> validated. This mirrors how [`../../detections/windows/`](../../detections/windows)
> is labelled - committed work is not the same as proven work.

## The gate

```
severity == 10  AND  ( verdict == MALICIOUS  OR  rule_id ∈ {100002, 100011} )
```

- `severity == 10` - never respond to a single low-severity event.
- `verdict == MALICIOUS` - VirusTotal flagged the public IOC, **or**
- `rule_id ∈ {100002, 100011}` - a correlation rule already fired (brute-force /
  sudo abuse), which is high-confidence on its own and covers internal RFC1918
  traffic where VT enrichment is skipped entirely.

Both the `MALICIOUS` and `INTERNAL_SKIP_ENRICHMENT` verdict nodes feed the gate,
which is what makes that second clause reachable - an internal brute force never
touches VirusTotal, so without it the correlation case could never respond.

## The nodes

**1. `Response Gate` (Code)** - reads the alert back from `Extract IOC` (the Set
verdict nodes emit only the verdict field) and computes a single boolean:

```javascript
const alert = $('Extract IOC').first().json;
const level = Number(alert.level ?? 0);
const ruleId = String(alert.rule_id ?? '');
const verdict = String($json.verdict ?? '');
const vtMalicious = verdict === 'MALICIOUS';
const correlation = ['100002', '100011'].includes(ruleId);
// do_respond = level === 10 && (vtMalicious || correlation)
```

Collapsing the condition into one boolean in code, rather than nesting AND/OR
inside the IF node's condition builder, keeps the logic readable and reviewable
in the exported JSON - the IF is then simply `{{ $json.do_respond }} is true`.

**2. `Should Respond?` (If)** - the false branch is deliberately a dead end. A
gated-off alert has already been triaged and (if malicious) emailed; it does not
need a second notification.

**3. `Dedup Guard` (Code)** - five brute-force alerts must not launch five
remediations. Workflow static data holds a per-host suppression window:

```javascript
const key = `resp:${$json.agent?.name ?? 'unknown'}`;
const store = $getWorkflowStaticData('global');
if (Date.now() - (store[key] ?? 0) < 5 * 60 * 1000) return [];   // drop
store[key] = Date.now();
```

**4. `Velociraptor Remediation` (HTTP Request)** - POSTs a `CollectArtifact`
request for `Custom.Remediation.KillProcess` against the affected client with
**`DryRun=Y`**. Auth is an n8n **Header Auth credential**, never an inline key in
the JSON.

> **Do not pass an empty `ProcName`.** The artifact selects with
> `WHERE Name =~ ProcName`, so `""` is a regex matching *every* process. Under
> `DryRun=Y` that looks harmless - it just lists everything - which is precisely
> what makes it dangerous: the fault stays invisible until someone flips DryRun
> off, and then it kills the host. The node omits the parameter so the artifact's
> `this_should_match_nothing_by_default` applies. Send a real `ProcName` only for
> alerts that actually name a process.

## Guardrails recap

- Gated on `severity == 10` + a corroborating high-confidence signal.
- Dedup window prevents repeated firing per host.
- `DryRun=Y` until the gate is trusted → no destructive action during bring-up.
- The artifact itself collects evidence *before* any containment step.
- The network block (firewall-drop) is time-bound and auto-reverses independently.

## Verification (do this before claiming it works)

1. Import the workflow, attach the Velociraptor credential, and publish it.
2. Fire the SSH brute-force simulation so rule `100002` (level 10) triggers.
3. Confirm in the n8n execution log that `Response Gate` set `do_respond: true`
   and the branch reached `Velociraptor Remediation`.
4. Confirm in Velociraptor that **exactly one** collection was scheduled, with
   `DryRun` set - repeat the burst and confirm the second alert is dropped by
   `Dedup Guard`.
5. Negative test: fire a level-8 alert (rule `100020`, account creation) and
   confirm the gate blocks it.
6. Record the outcome in [`../../validation/metrics.md`](../../validation/metrics.md).

If you re-shape the branch in the n8n UI, re-export and overwrite
`automation/wazuh-triage-workflow.json`, and update the node count in
`automation/README.md`.
