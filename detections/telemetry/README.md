# Telemetry Prerequisites

The [casebook](../../casebook) works alerts from the **whole sensor stack**, not
just the five custom rules - a real L1 does the same. This folder commits the
**configuration that produces that telemetry**, so every casebook case is backed
by an artifact in the repo rather than an unstated assumption.

## Source → config → cases

| Telemetry source | Config here | Powers cases |
|------------------|-------------|--------------|
| **FIM / syscheck** (file integrity) | [`syscheck-fim.conf.xml`](syscheck-fim.conf.xml) | 009, 010, 013, 016, 018 |
| **auditd** (command / syscall monitoring) | [`auditd-soc-lab.rules`](auditd-soc-lab.rules) + [`ossec-localfile-auditd.xml`](ossec-localfile-auditd.xml) | 014, 015, 016, 017 |
| **Web access log** ingestion | [`ossec-localfile-web.xml`](ossec-localfile-web.xml) | 010, 011 |
| **VirusTotal** hash integration | [`virustotal-integration.xml`](virustotal-integration.xml) | 018 |
| **rootcheck** | default (see note below) | 012 |
| Built-in SSH ruleset | default | 007, 008 |

## How to deploy

All XML fragments go inside the relevant blocks of
`/var/ossec/etc/ossec.conf` on the **Wazuh manager** (integration, localfile) or
the **agent** (syscheck, localfile) - merge them, don't paste blindly. The
auditd rules file goes to `/etc/audit/rules.d/` on the endpoint, then
`augenrules --load`.

### rootcheck (CASE-012)

Rootcheck ships enabled in a default Wazuh install (`<rootcheck>` block with
`rootkit_files`/`rootkit_trojans` databases), so there's no custom artifact to
commit - the case relies on stock behavior. Confirm it's on:

```xml
<rootcheck>
  <disabled>no</disabled>
  <check_rootkit_files>yes</check_rootkit_files>
  <check_rootkit_trojans>yes</check_rootkit_trojans>
</rootcheck>
```

## Note on scope

These are the **minimum** stanzas that make the cited casebook alerts fire in
this lab; they are intentionally narrow (specific paths, specific syscalls)
rather than a hardened enterprise baseline. That keeps the signal high and the
config readable - the same design stance as the rest of the lab.
