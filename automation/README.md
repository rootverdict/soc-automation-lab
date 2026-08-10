# Automation (n8n)

The automation layer ingests Wazuh alerts and runs them through an enrichment-and-triage workflow in n8n. This folder contains the Wazuh-side integration that forwards alerts, and documents the n8n workflow logic.

## Files

| File | Purpose |
|------|---------|
| `custom-n8n.py` | Wazuh custom integration script - reads an alert and POSTs a structured payload to the n8n webhook |
| `ossec-integration-snippet.xml` | The `<integration>` block added to `ossec.conf` to register the script and set the forwarding threshold |
| `wazuh-triage-workflow.json` | Exported n8n workflow (secrets scrubbed) - import into n8n to reproduce |

## Wazuh → n8n forwarding

Wazuh's integrator daemon invokes `custom-n8n.py` for every alert at or above the configured level. The script extracts the relevant fields and POSTs them to the n8n production webhook:

```python
payload = {
    "rule_id":     alert["rule"]["id"],
    "description": alert["rule"]["description"],
    "level":       alert["rule"]["level"],
    "mitre":       alert["rule"]["mitre"],
    "agent":       alert["agent"],
    "full_log":    alert["full_log"],
    "timestamp":   alert["timestamp"],
}
```

The `<integration>` block forwards only level ≥ 7 alerts, so the noise threshold is enforced at the SIEM before automation runs:

```xml
<integration>
  <name>custom-n8n</name>
  <hook_url>http://192.168.100.20:5678/webhook/wazuh</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

## n8n workflow logic

The workflow (13 nodes) implements the triage pipeline and the gated response branch:

1. **Webhook** - receives the Wazuh alert (POST `/webhook/wazuh`).
2. **Extract IOC** (Code) - IOC extraction and normalization. Parses the source IP from `full_log`, falls back to the agent IP, and flags RFC1918 / loopback ranges.
3. **Is Public IOC?** (If) - routes on `is_private`:
   - **true (private)** → internal branch (skip enrichment).
   - **false (public)** → enrichment branch.
4. **VirusTotal Lookup** (HTTP Request) - GET `https://www.virustotal.com/api/v3/ip_addresses/{ioc_ip}` with the `x-apikey` header.
5. **VT Malicious?** (If) - checks `data.attributes.last_analysis_stats.malicious > 0`.
6. **Verdict nodes** (Set) - assigns one of three verdicts:
   - `MALICIOUS` (VirusTotal flagged the IOC)
   - `CLEAN` (public IOC, no detections)
   - `INTERNAL_SKIP_ENRICHMENT` (private/RFC1918 source)
7. **Notify Analyst** (Send Email) - on the malicious branch only, emails the analyst with the rule, MITRE technique, IOC, and VirusTotal malicious count.

### Gated response branch (nodes 8-11)

Both the `MALICIOUS` and `INTERNAL_SKIP_ENRICHMENT` verdicts feed the response
gate - the internal path matters because a brute-force or sudo-abuse correlation
is high-confidence on its own even though VirusTotal was skipped.

8. **Response Gate** (Code) - computes `do_respond`:
   `level == 10 AND (verdict == MALICIOUS OR rule_id ∈ {100002, 100011})`.
9. **Should Respond?** (If) - `do_respond` is true. The false branch is a dead end: no response, no notification beyond step 7.
10. **Dedup Guard** (Code) - per-host 5-minute suppression window held in workflow static data, so a burst of correlated alerts cannot launch a burst of remediations.
11. **Velociraptor Remediation** (HTTP Request) - POSTs a `Custom.Remediation.KillProcess` collection for the affected client with **`DryRun=Y`**, so the artifact reports what it would kill and does nothing destructive.

> **Status:** the response branch is committed here as workflow JSON. It has not
> yet been exercised against a live severity-10 event - import it, run the
> brute-force simulation, and confirm the collection is scheduled exactly once
> with DryRun before treating it as validated. The *network* containment path
> (Wazuh `firewall-drop`) is independent of this branch and does not depend on it.

## Enrichment and triage decisions

- **IOC extraction / normalization** - the source IP is pulled from the raw log and normalized to a single observable before any lookup.
- **RFC1918 filtering** - private and loopback addresses are detected with a regex (`10.`, `127.`, `192.168.`, `172.16-31.`) and routed away from VirusTotal, since public reputation data is meaningless for internal IPs and would waste API quota.
- **Conditional routing** - the malicious decision uses a tunable threshold (`> 0` in the lab); a production deployment would raise this or use a weighted score, since some legitimate IPs receive one or two low-confidence detections.
- **Notification control** - only the malicious branch notifies; clean and internal verdicts are recorded without paging the analyst.
- **Response is gated separately from notification.** Emailing an analyst is cheap and reversible; containing a host is not. The gate therefore demands severity 10 *plus* a corroborating signal, rather than reusing the notification condition.

## Testing the malicious path in an internal-only lab

Every real source IP in this lab is RFC1918, so the VirusTotal branch has no
naturally-occurring input. The `Extract IOC` node carries a `TEST_IOC` constant
(default `null`) for injecting a known public IOC to exercise that path:

```javascript
const TEST_IOC = "45.155.205.233";   // exercise the malicious branch
const TEST_IOC = null;               // normal operation - extract from the alert
```

Leave it `null` for normal runs. Setting it pins every alert to that IOC and
bypasses the real extraction, which is only ever what you want for a one-off
test of the enrichment branch.

## Reproducing

1. Import `wazuh-triage-workflow.json` into n8n.
2. Add your VirusTotal API key to the `VirusTotal Lookup` node's `x-apikey` header.
3. Add SMTP credentials (Gmail App Password) to the `Notify Analyst` node.
4. Add a Velociraptor API credential (Header Auth) to the `Velociraptor Remediation` node, and set the URL to your Velociraptor API endpoint.
5. Publish the workflow so the production webhook registers.
6. Deploy `custom-n8n.py` to `/var/ossec/integrations/` on the Wazuh manager and add the `<integration>` block to `ossec.conf`.
