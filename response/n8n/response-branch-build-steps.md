# n8n Response Branch — build steps

This adds an **automated host-response branch** to the existing triage workflow. Build it in
the n8n UI (don't hand-edit the exported JSON), then re-export and commit the updated
`automation/wazuh-triage-workflow.json`.

The Wazuh firewall-drop (see `../wazuh/`) handles the *network* block on its own. This branch
handles the *endpoint* response by launching the Velociraptor remediation artifact — and only
on a high-confidence verdict.

## The gate (fire response only when all of this is true)

```
severity == 10  AND  ( vt_malicious == true  OR  rule_id ∈ {100002, 100011} )
```

- `severity == 10` — never respond to a single low-severity event.
- `vt_malicious` — VirusTotal flagged the public IOC, **or**
- `rule_id ∈ {100002, 100011}` — a correlation rule already fired (brute-force / sudo abuse),
  which is high-confidence on its own and works for internal RFC1918 traffic where VT is skipped.

## Nodes to add (after the existing verdict node)

1. **IF — "response gate"**
   - Condition 1 (Number): `{{ $json.level }}` **equals** `10`
   - AND a nested OR for the second clause. In n8n the clean way is a small **Code** node
     before the IF that sets a single boolean, e.g.:
     ```javascript
     const level = Number($json.level ?? $json.rule?.level ?? 0);
     const ruleId = String($json.rule_id ?? $json.rule?.id ?? '');
     const vtMalicious = Boolean($json.vt_malicious);
     const correlation = ['100002', '100011'].includes(ruleId);
     return [{ json: { ...$json, do_respond: level === 10 && (vtMalicious || correlation) } }];
     ```
     Then the IF is simply `{{ $json.do_respond }}` **is true**.

2. **Dedup guard (prevents a response storm)**
   - Five brute-force alerts must not launch five remediations. Add a **Code** node using
     workflow **static data** as a short-lived cache keyed by host:
     ```javascript
     const key = `resp:${$json.agent?.name ?? $json.agent ?? 'unknown'}`;
     const now = Date.now();
     const store = $getWorkflowStaticData('global');
     const last = store[key] ?? 0;
     if (now - last < 5 * 60 * 1000) {        // 5-minute suppression window
       return [];                              // drop duplicate -> no response
     }
     store[key] = now;
     return [{ json: $json }];
     ```

3. **HTTP Request — "launch Velociraptor remediation"**
   - Method: `POST` to the Velociraptor API endpoint that schedules a collection.
   - Body: launch `Custom.Remediation.KillProcess` against the affected client, passing
     `ProcName` (derived from the alert where applicable) and **`DryRun=true`** for the first
     rollout — flip to `false` only once you trust the gate.
   - Auth: Velociraptor API credentials stored as an n8n credential (never inline in the JSON).

## Guardrails recap (mirror these in the response README)

- Gated on `severity == 10` + high-confidence signal.
- Dedup window prevents repeated firing per host.
- `DryRun=true` until the gate is trusted → no destructive action during bring-up.
- The network block (firewall-drop) is time-bound and auto-reverses independently.

## After building

1. Test with a severity-10 event and confirm the branch fires exactly once (check the
   Velociraptor collection was scheduled with DryRun).
2. **Export** the workflow (secrets scrubbed) and overwrite
   `automation/wazuh-triage-workflow.json`.
3. Update the node count / description in `automation/README.md`.
