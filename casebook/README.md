# SOC Analyst Casebook (Tier 1)

This casebook documents how alerts from this lab are **worked the way a SOC L1 analyst works
them on shift**: take an alert off the queue, triage it, enrich it, reach a defensible verdict,
take or recommend an action, and either close it or escalate - with a written record for every step.

Detection rules prove you can *engineer* a SIEM. This casebook proves you can do the *job*:
separate true positives from false positives, and document the reasoning an L2 can trust.

> **Evidence note.** Every case below is worked against this lab's **real detection rules,
> telemetry sources, and pipeline** - the alert, the rule ID, the technique, the triage path,
> and the response are all real. What is *not* yet captured per-case is the run-specific
> evidence: exact timestamps, the source IPs, and the alert screenshots. Those are marked
> `<!-- EVIDENCE -->` in the source and are being filled from individual runs rather than
> invented, which is why the analysis reads complete but the IOC tables are still generic.
> See the [status table](../README.md#status---proven-vs-committed).

---

## What a SOC L1 actually does (the workflow each case follows)

1. **Pick up the alert.** An alert arrives in the queue (here: a Wazuh alert, forwarded to n8n).
   Note the rule, severity, MITRE technique, asset, and time.
2. **Triage - is this real?** Answer a fixed set of questions (below) to decide *true positive*,
   *false positive*, or *benign true positive* (real activity, but authorized).
3. **Enrich.** Add context the raw alert lacks: IP reputation (VirusTotal), internal vs external
   (RFC1918), asset/user ownership, whether the behavior is expected for that host.
4. **Decide the verdict** and write the one-line justification.
5. **Act or escalate.** Apply the playbook action (contain / close) within L1 authority, or
   escalate to L2 with a clean handoff when it exceeds it.
6. **Document & close.** Record verdict, action, IOCs, and escalation notes in the case.

## The L1 triage questions (asked on every alert)

- **Internal or external?** Is the source an RFC1918/internal address or a public IP?
- **Known asset / user?** Is the target a managed host and the actor an expected account?
- **Expected behavior?** Could this be legitimate (an admin, a scanner, a backup job, patching)?
- **Does enrichment corroborate?** Does threat intel / reputation raise or lower suspicion?
- **Correlated?** Is this a single event or part of a pattern (a correlation rule firing)?
- **Severity vs impact.** Does the alert severity match the real-world impact on the asset?

## Verdict definitions

| Verdict | Meaning |
|---------|---------|
| **True Positive (TP)** | Real malicious/unauthorized activity. Contain and/or escalate. |
| **False Positive (FP)** | The alert fired but the activity is not malicious. Close with justification; propose tuning. |
| **Benign True Positive** | The detected activity really happened but was authorized (e.g. admin action). Close with context. |

## Escalation criteria (when L1 hands to L2)

Escalate when any of these are true:

- Confirmed **true positive** with evidence of compromise (persistence, credential access, lateral movement).
- Activity crosses the **containment authority** of an L1 (e.g. host isolation, account disable beyond the automated action).
- **Scope is unclear** - more than one host/account may be involved.
- The alert indicates a technique with **high blast radius** (credential dumping, privilege escalation).

A good escalation includes: what fired, why it's a TP, what was already contained automatically,
the IOCs, and the open question for L2.

## SLA mindset

L1 works to time targets: acknowledge high-severity alerts quickly, reach an initial verdict
within the triage SLA, and escalate true positives without sitting on them. This lab measures
detection-to-alert latency (~3s) and detection-to-automated-containment; those feed the
metrics work in v2.

---

## Detection sources & prerequisites

Not every case is powered by the five custom rules - a real analyst works alerts from the whole
sensor stack. Knowing *which telemetry powers which alert* is itself an L1 skill, so each case
names its **detection source**. Sources used across the book:

| Source | Powers cases | Prerequisite (committed config) |
|--------|--------------|--------------|
| Custom rules (`local_rules.xml`) | 001, 002, 003, 006 | [`detections/local_rules.xml`](../detections/local_rules.xml) - deployed |
| Wazuh SSH ruleset (built-in) | 007, 008 | Default |
| Wazuh **FIM / syscheck** | 009, 010, 013, 016, 018 | [`detections/telemetry/syscheck-fim.conf.xml`](../detections/telemetry/syscheck-fim.conf.xml) |
| Wazuh **rootcheck** | 012 | Default ([note](../detections/telemetry/README.md#rootcheck-case-012)) |
| Wazuh **web ruleset** | 010, 011 | [`detections/telemetry/ossec-localfile-web.xml`](../detections/telemetry/ossec-localfile-web.xml) |
| Wazuh **VirusTotal integration** | 018 | [`detections/telemetry/virustotal-integration.xml`](../detections/telemetry/virustotal-integration.xml) |
| auditd / command monitoring | 014, 015, 016, 017 | [`detections/telemetry/auditd-soc-lab.rules`](../detections/telemetry/auditd-soc-lab.rules) |
| Windows + Sysmon | 004, 005 | [`detections/windows/`](../detections/windows) - rules authored; _endpoint stand-up pending (v1)_ |

Each telemetry source now has a **committed config artifact** (see
[`detections/telemetry/`](../detections/telemetry)), so every case is backed by
something in the repo, not an unstated assumption.

## Case index

Ordered to read like a real intrusion where cases connect - initial access → execution →
persistence → C2 → anti-forensics - with a deliberate mix of **True Positive**, **False
Positive**, and **Benign True Positive** verdicts (separating them is the job).

**Authentication & access**
| Case | Alert | Verdict | Action |
|------|-------|---------|--------|
| [CASE-001](CASE-001-ssh-bruteforce-external.md) | SSH brute-force from external IP (rule 100002) | True Positive | Confirm auto-block, escalate L2 |
| [CASE-002](CASE-002-ssh-bruteforce-internal.md) | SSH brute-force from internal host (rule 100002) | **False Positive** | Close w/ justification, propose tuning |
| [CASE-007](CASE-007-ssh-successful-login-post-bruteforce.md) | Successful SSH login after brute-force | True Positive - **compromise** | Kill session, escalate CRITICAL |
| [CASE-008](CASE-008-ssh-anomalous-geo-login.md) | SSH login from anomalous location | **Benign True Positive** | Verify with user, close |

**Web application**
| Case | Alert | Verdict | Action |
|------|-------|---------|--------|
| [CASE-011](CASE-011-web-sql-injection.md) | SQL injection attempt (web log) | True Positive - exploit attempt | Block source, escalate app team |
| [CASE-010](CASE-010-webshell-dropped.md) | Web shell dropped in web root (FIM) | True Positive - **web shell** | Preserve, escalate CRITICAL |

**Privilege abuse & persistence**
| Case | Alert | Verdict | Action |
|------|-------|---------|--------|
| [CASE-006](CASE-006-sudo-abuse.md) | Repeated failed sudo (rule 100011) | True Positive - priv abuse | Host action, notify owner |
| [CASE-003](CASE-003-account-creation.md) | Local account created (rule 100020) | True Positive - persistence | Velociraptor confirm, escalate |
| [CASE-009](CASE-009-fim-critical-file-modified.md) | Critical file modified - sshd_config (FIM) | True Positive | Preserve diff, escalate |
| [CASE-013](CASE-013-cron-persistence.md) | Cron-based persistence (FIM) | True Positive - persistence | Remove payload, escalate |

**Malware, C2 & defense evasion**
| Case | Alert | Verdict | Action |
|------|-------|---------|--------|
| [CASE-018](CASE-018-malicious-file-hash.md) | Malicious file by hash reputation (VT) | True Positive - **malware** | Quarantine, escalate CRITICAL |
| [CASE-014](CASE-014-reverse-shell-outbound.md) | Suspicious outbound connection (reverse shell) | True Positive - **C2** | Contain via Velociraptor, escalate CRITICAL |
| [CASE-012](CASE-012-rootcheck-rootkit.md) | Rootkit / hidden process (rootcheck) | True Positive *if corroborated* | Forensic confirm, escalate IR |
| [CASE-015](CASE-015-logging-service-stopped.md) | Logging/monitoring service stopped | True Positive - defense evasion | Restore, correlate gap |
| [CASE-016](CASE-016-bash-history-cleared.md) | Shell history cleared (anti-forensics) | True Positive - indicator removal | Reconstruct from auditd |
| [CASE-017](CASE-017-recon-tool-installed.md) | Recon/dual-use tool installed | **Benign True Positive** | Verify admin, policy note |

**Windows (pending endpoint build)**
| Case | Alert | Status |
|------|-------|--------|
| CASE-004 | Encoded PowerShell (T1059.001) | _pending Windows build_ |
| CASE-005 | LSASS access (T1003.001) | _pending Windows build_ |

> **16 worked cases + 2 pending.** CASE-004/005 depend on the Windows + Sysmon endpoint and will
> be written **from real evidence** once it is built and the Atomic Red Team tests are run - not
> back-filled with sample data. Placeholders are intentional.

**Verdict mix:** 12 True Positive · 1 False Positive · 2 Benign True Positive · 1 conditional
(CASE-012) - a realistic spread that shows TP/FP decisioning, not a wall of confirmed incidents.

Use [CASE-TEMPLATE.md](CASE-TEMPLATE.md) to add new cases.
