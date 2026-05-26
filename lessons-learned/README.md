# Lessons Learned

Real problems encountered during the build and how they were resolved. These are documented intentionally — the failures were where most of the actual learning happened, and they reflect the kind of troubleshooting a SOC engineer does in practice.

## Networking and environment

- **Host-only network has no internet.** The SOC subnet was configured host-only for VM-to-VM isolation, but that left no path for package installs or VirusTotal lookups. Fix: add a second NAT adapter to each VM, set the host-only interface to a static IP and the NAT interface to DHCP in netplan.
- **Interface names shift when adding a second NIC.** netplan kept configuring DHCP on an interface name that no longer existed after a second adapter was attached, so the NAT NIC stayed down with no internet. Fix: always run `ip a` with both adapters attached and write netplan against the exact interface names shown.
- **Host could not reach VM dashboards.** A host-only network with no host virtual adapter means the Windows host has no route to the VMs. Fix: either enable a host virtual adapter on the network, or browse to the VM's NAT IP, which the host can already reach.

## Wazuh deployment

- **Ubuntu LVM provisions only part of the disk.** The default install allocated ~24 GB of a 50 GB disk to the root LV, leaving the rest unused in the volume group. The disk filled and silently killed the Wazuh API daemon (`apid`) with `OSError: [Errno 28] No space left on device`, which manifested as a confusing "manager won't start" failure. Fix: `lvextend -l +100%FREE` followed by `resize2fs` to claim the full disk. **Always check `df -h` early when a service mysteriously fails to start.**
- **Agent version must be ≤ manager version.** A freshly installed agent (4.14.5) was rejected by the 4.9.2 manager with "Agent version must be lower or equal to manager version." Fix: pin the agent to the manager's version (`apt install wazuh-agent=4.9.2-1`) and `apt-mark hold` it.
- **Reinstall left a config placeholder.** Reinstalling the agent left a literal `MANAGER_IP` placeholder in `ossec.conf` (the install-time env var did not re-apply), so the agent could not connect. Fix: set the manager address directly in `ossec.conf`.
- **Stale enrollment key after a failed enroll.** After the version-mismatch failures, the agent connected at the TCP layer but the manager still showed it as "Never connected" / "Unknown" because of a stale key. Fix: remove the agent entry on the manager (`manage_agents`), delete `client.keys` on the agent, re-enroll cleanly, and restart the manager to flush the cached key.

## Detection engineering

- **Map decoder output to the correct base rule.** The failed-sudo detection was initially built on rule `5403` ("First time user executed sudo" — a *success*), so it never fired on real failures. The correct parent is `5401` ("Failed attempt to run sudo"). Note also that `5404` ("Three failed attempts") fires on a single composite log line, so an `if_sid: 5401` rule will not catch it. Always confirm which base rule a given log line produces before writing `if_sid`.
- **Composite base rules can fire before your custom rule.** SSH "invalid user" failures matched base rule `5710`, not `5716`, so a custom rule scoped only to `5716` never matched and the built-in brute-force rule (`5712`) caught the event instead. Fix: widen the parent to `5710,5716,5760`.
- **Frequency rules need a valid `if_matched_sid`.** A correlation rule using `frequency`/`timeframe` failed to load (`Missing if_matched on rule`) and took the whole manager down with it. Fix: ensure the frequency rule references a valid `if_matched_sid` and test rule changes before relying on the manager restarting cleanly.

## Automation (n8n)

- **n8n 2.8 uses "Publish", not an Active toggle.** Production webhooks only register when the workflow is published; the test-listen mode is a one-shot and does not catch production POSTs. Repeated `404 webhook not registered` errors were simply an unpublished workflow.
- **Secure-cookie block when accessed by IP.** n8n refuses to load over an insecure URL (IP instead of localhost) unless `N8N_SECURE_COOKIE=false` is set — necessary for a lab accessed from the host browser.
- **Object fields render as `[object Object]`.** n8n expressions on object fields (e.g. `mitre`, `agent`) display `[object Object]`; reference sub-fields (`.mitre.id`, `.agent.name`) or `JSON.stringify()` instead.

## Enrichment and notification

- **RFC1918 has no public reputation.** Sending private source IPs to VirusTotal returns nothing useful and wastes API quota. The pipeline explicitly detects and routes private addresses away from enrichment.
- **VirusTotal free tier limits.** 4 requests/minute, 500/day — fine for a lab, but a production deployment would need caching and rate-limiting/queuing.
- **Gmail SMTP needs an App Password.** Sending mail from n8n requires 2-Step Verification enabled and a Gmail App Password; the account's normal password is rejected.
- **Notify only on a malicious verdict.** Emailing on every alert would create alert fatigue; only the malicious branch notifies.

## Adversary emulation (Caldera)

- **Ubuntu's apt Node is too old.** The default Node (v12) cannot build Caldera's Vite/VueJS UI; installing Node 20 via NodeSource resolved the build failure.
- **Caldera needs Go 1.19+** to compile the Sandcat agent on demand.
- **Tactic must match the detection.** Discovery-tactic abilities run read-only commands that generate no security events; persistence / credential-access abilities are needed to exercise account-creation and brute-force detections.
- **Agent privileges matter.** `useradd`-based abilities require the Sandcat agent to run as root.

## Resource management

- The endpoint VM (4 GB) runs the Wazuh agent, n8n, Caldera, and Velociraptor. Running everything simultaneously is tight; for the end-to-end test, stopping Caldera and triggering the attack manually is a practical fallback that exercises the same detection path with less memory pressure.
