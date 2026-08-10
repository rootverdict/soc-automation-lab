# Screenshots

Captured evidence at each layer of the pipeline. Referenced from the top-level
[README](../README.md) and the [demo walkthrough](../demo_walkthrough.md).

| File | Shows |
|------|-------|
| `wazuh-100020-account-created.png` | Wazuh alert for rule 100020 (T1136) |
| `wazuh-100002-ssh-bruteforce.png` | Wazuh alert for rule 100002 (T1110) |
| `wazuh-mitre-attack.png` | Wazuh MITRE ATT&CK module (T1110 / T1136 / T1548.003) |
| `n8n-workflow-canvas.png` | n8n workflow canvas |
| `n8n-execution-path.png` | An execution showing the verdict routing |
| `virustotal-email-alert.png` | The automated MALICIOUS analyst email |
| `velociraptor-users-collection.png` | `Linux.Sys.Users` collection results |
| `caldera-operation-success.png` | Caldera "Create local account" operation succeeding |

## Not yet captured

- `n8n-workflow-canvas.png` predates the gated response branch, so it shows the
  9-node triage workflow rather than the current 13-node version. Re-capture
  after importing the updated workflow.
- Windows rule firings (T1059.001, T1053.005, T1547.001, T1003.001) - pending the
  Windows/Sysmon endpoint build.
- Active-response evidence (`iptables` drop + `active-responses.log`) for the
  brute-force containment path.
- `attack-coverage-map.png` - the rendered ATT&CK Navigator layer (see
  [`detections/coverage/`](../detections/coverage) for how to export it).
