# Windows Detections (Sysmon + PowerShell)

Custom Wazuh rules for Windows endpoint telemetry, extending the lab from Linux
to the platform that is ~90% of real endpoint SOC work. Rules live in
[`windows_rules.xml`](windows_rules.xml) and use the `1001xx` ID block.

> **Status:** rules authored and mapped. Live validation against a Windows VM
> with Atomic Red Team, plus firing screenshots, is the remaining step (needs
> the endpoint stood up). Casebook CASE-004 / CASE-005 will be written **from
> real evidence** once that run happens - not back-filled.

## Rules

| Rule ID | Detection | MITRE | Source channel / event |
|---------|-----------|-------|------------------------|
| 100100 | Encoded / cradle PowerShell (script block) | T1059.001 | PowerShell Operational, EID 4104 |
| 100101 | Suspicious PowerShell command line | T1059.001 | Sysmon EID 1 |
| 100110 | Scheduled task created via `schtasks.exe` | T1053.005 | Sysmon EID 1 |
| 100111 | Scheduled task registered | T1053.005 | Security EID 4698 |
| 100120 | Registry Run-key persistence | T1547.001 | Sysmon EID 13 |
| 100131 | Suspicious LSASS access (cred dumping) | T1003.001 | Sysmon EID 10 |
| 100132 | LSASS access by known-good process (suppressed) | - | Sysmon EID 10 |

Rule 100132 is a **child of 100131** (`if_sid`), not an independent rule: when a
known-good accessor (`wininit`, `csrss`, `services`, Defender) matches, Wazuh's
last-matching-rule-wins evaluation downgrades the event to level 0, so it never
pages an analyst. Chaining the exclusion onto the detection avoids the trap of
two independent rules both matching a broad mask like `0x1fffff`. Tune the
accessor allow-list to your environment (EDR/AV/backup agents legitimately read
process memory).

## Endpoint setup (what the rules assume)

1. **Sysmon** installed with the SwiftOnSecurity config
   (`sysmon64.exe -accepteula -i sysmonconfig-export.xml`).
2. Wazuh agent forwarding **two** channels - Sysmon is not enough on its own,
   because EID 4104 is a PowerShell event:

   ```xml
   <!-- ossec.conf on the Windows agent -->
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   <localfile>
     <location>Microsoft-Windows-PowerShell/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```

3. **PowerShell Script Block Logging** enabled (Group Policy: *Administrative
   Templates → Windows Components → Windows PowerShell → Turn on PowerShell
   Script Block Logging*), otherwise EID 4104 is not produced.

## Field-path note

Wazuh's Windows decoder exposes event fields under `win.system.*` and
`win.eventdata.*` (the `data.` prefix seen in the dashboard JSON is dropped in
rule `<field name>` references). Matching the event ID via
`win.system.eventID` and the payload via `win.eventdata.*` is what makes these
rules fire - a common first-attempt mistake is using the dashboard's `data.win.*`
path verbatim.

## Validation plan (remaining)

Each rule maps to an [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
test; run the atomic, confirm the alert in the Wazuh dashboard, capture a screenshot:

| Rule | Atomic test |
|------|-------------|
| 100100/100101 | T1059.001 - encoded command / download cradle |
| 100110/100111 | T1053.005 - `schtasks /create` |
| 100120 | T1547.001 - Run-key registry value |
| 100131 | T1003.001 - LSASS access (e.g. `procdump`/`comsvcs`) |

Portable [Sigma](../sigma) equivalents of these rules are in `detections/sigma/`.
