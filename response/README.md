# Automated Response (SOAR — the "R")

This layer closes the loop: after an alert is detected, enriched, and triaged, the pipeline
takes an **automated containment action** — instead of only emailing an analyst. Response is
deliberately **gated and reversible**, because an over-eager auto-response is worse than none.

## Two response paths (matched to the telemetry)

The response action is chosen by *what kind of attack* fired, not a single generic action.

| Attack | Rule | Response | Why this action |
|--------|------|----------|-----------------|
| SSH brute-force | `100002` | **Firewall-drop the source IP** (Wazuh active-response), auto-unblock after 600s | It's a network attack with a real `srcip` — block the origin |
| Local sudo abuse | `100011` | **Host action** — flag/lock the offending account, log the session (custom AR script) | A sudo failure is *local*; there is **no source IP to block**, so a firewall drop would no-op |
| Malicious host activity (any platform) | severity 10 + malicious verdict | **Velociraptor** — collect evidence, then optionally kill/quarantine (DryRun by default) | Endpoint-level containment when the threat is on the host, not the network |

> **Design note worth stating in an interview:** the response is *matched to the layer of the
> attack*. Network attacks get a network block; local privilege abuse gets a host action;
> on-host malware gets endpoint containment. Blindly firewall-dropping every rule (e.g. a sudo
> event with no `srcip`) is a common mistake — this pipeline avoids it on purpose.

## Guardrails (why this is safe to automate)

1. **Gated on high confidence.** The n8n-driven host response fires only on
   `severity == 10 AND (VirusTotal malicious OR a correlation rule 100002/100011)` — never on a
   single low-severity event.
2. **Timed auto-unblock.** The firewall drop uses `<timeout>600</timeout>` — the IP is released
   automatically after 10 minutes, so a false positive rolls itself back. No permanent lockout.
3. **Admin whitelist — no self-lockout.** Management/host IPs are whitelisted so testing or
   admin traffic can never firewall-drop the operator. **Set this before enabling response.**
4. **DryRun by default.** The Velociraptor kill artifact ships with `DryRun=true` — it *reports*
   what it would kill and does nothing destructive until an operator explicitly flips it.
5. **Collect-then-contain.** Evidence (process list, network connections, hashes) is captured
   **before** any destructive remediation, so containment never destroys the forensic record.

## Files

| File | Purpose |
|------|---------|
| `wazuh/active-response.conf.xml` | `<active-response>` blocks for `ossec.conf` — binds `firewall-drop` to the brute-force rule |
| `wazuh/sudo-abuse-response.sh` | Custom active-response script for local sudo abuse (host action, not IP block) |
| `velociraptor/Custom.Remediation.KillProcess.yaml` | Velociraptor artifact — collect-then-contain, DryRun default |
| `n8n/response-branch-build-steps.md` | How to add the gated response branch to the existing n8n workflow |

## Deploy & test (Linux path — no new VM required)

1. Add the blocks from `wazuh/active-response.conf.xml` to `/var/ossec/etc/ossec.conf` on the
   **manager**, set your admin/host IP in the whitelist, and
   `sudo systemctl restart wazuh-manager`.
2. Confirm the **agent** has active-response enabled: `<active-response><disabled>no</disabled>`
   in its `ossec.conf`.
3. Run the SSH brute-force simulation against the endpoint.
4. On the endpoint: `sudo iptables -L -n` — the attacker IP should appear as dropped, then
   disappear after ~10 minutes. Cross-check `/var/ossec/logs/active-responses.log`.

## Manual unblock (false-positive runbook)

If a legitimate IP is blocked before the timeout expires:

```bash
# See what active-response did
sudo tail -n 50 /var/ossec/logs/active-responses.log

# Remove the drop rule manually (find the line number first)
sudo iptables -L INPUT -n --line-numbers
sudo iptables -D INPUT <line-number>
```

Then add the IP to the whitelist in `ossec.conf` so it is not re-blocked, and restart the manager.

## Reversibility summary

Every response action in this layer is either **time-bound** (firewall drop auto-expires),
**non-destructive by default** (DryRun), or **manually reversible** (documented unblock). That
combination is what makes automated containment defensible rather than reckless.
