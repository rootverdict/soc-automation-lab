# Automation (n8n)

The automation layer ingests Wazuh alerts and runs them through an enrichment-and-triage workflow in n8n. This folder contains the Wazuh-side integration that forwards alerts, and documents the n8n workflow logic.

## Files

| File | Purpose |
|------|---------|
| `custom-n8n.py` | Wazuh custom integration script — reads an alert and POSTs a structured payload to the n8n webhook |
| `ossec-integration-snippet.xml` | The `<integration>` block added to `ossec.conf` to register the script and set the forwarding threshold |
| `wazuh-triage-workflow.json` | Exported n8n workflow (secrets scrubbed) — import into n8n to reproduce |

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

The workflow (8 nodes) implements the triage pipeline:

1. **Webhook** — receives the Wazuh alert (POST `/webhook/wazuh`).
2. **Code (JavaScript)** — IOC extraction and normalization. Parses the source IP from `full_log`, falls back to the agent IP, and flags RFC1918 / private ranges.
3. **If — public IP?** — routes on `is_private`:
   - **false (private)** → internal branch (skip enrichment).
   - **true (public)** → enrichment branch.
4. **HTTP Request — VirusTotal** — GET `https://www.virustotal.com/api/v3/ip_addresses/{ioc_ip}` with the `x-apikey` header.
5. **If — malicious?** — checks `data.attributes.last_analysis_stats.malicious > 0`.
6. **Edit Fields (verdict nodes)** — assigns one of three verdicts:
   - `MALICIOUS` (VirusTotal flagged the IOC)
   - `CLEAN` (public IOC, no detections)
   - `INTERNAL_SKIP_ENRICHMENT` (private/RFC1918 source)
7. **Send Email** — on the malicious branch, emails the analyst with the rule, MITRE technique, IOC, and VirusTotal malicious count.

## Enrichment and triage decisions

- **IOC extraction / normalization** — the source IP is pulled from the raw log and normalized to a single observable before any lookup.
- **RFC1918 filtering** — private addresses are detected with a regex (`10.`, `192.168.`, `172.16–31.`) and routed away from VirusTotal, since public reputation data is meaningless for internal IPs and would waste API quota.
- **Conditional routing** — the malicious decision uses a tunable threshold (`> 0` in the lab); a production deployment would raise this or use a weighted score, since some legitimate IPs receive one or two low-confidence detections.
- **Notification control** — only the malicious branch notifies; clean and internal verdicts are recorded without paging the analyst.

## Reproducing

1. Import `wazuh-triage-workflow.json` into n8n.
2. Add your VirusTotal API key to the HTTP Request node's `x-apikey` header.
3. Add SMTP credentials (Gmail App Password) to the Send Email node.
4. Publish the workflow so the production webhook registers.
5. Deploy `custom-n8n.py` to `/var/ossec/integrations/` on the Wazuh manager and add the `<integration>` block to `ossec.conf`.
