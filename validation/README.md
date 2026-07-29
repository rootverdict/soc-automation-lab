# Forensic Validation (Velociraptor)

Velociraptor provides the forensic confirmation layer. After a detection fires and the automation pipeline triages it, Velociraptor collects live data from the endpoint to confirm the activity actually occurred on the host — closing the loop from alert to ground truth.

Scope is deliberately minimal (one client, one VQL artifact, one collection) to validate the concept without over-engineering.

## Setup summary

- Velociraptor 0.74 single-binary server deployed on the endpoint.
- GUI bind address set to `0.0.0.0` so it is reachable from the host browser (it defaults to `127.0.0.1`).
- A client deployed on the same host, enrolling against the server and appearing as the `endpoint` client.

## Forensic artifact used

**`Linux.Sys.Users`** — enumerates local user accounts on the endpoint.

This artifact directly validates the account-creation attack chain: after the attack creates a user (and the detection + automation fire), a `Linux.Sys.Users` collection lists the attacker-created account, confirming the alert reflects a real change on disk rather than a false positive.

In the end-to-end run, the collection returned 50 rows including the attacker account (`e2e_attacker`, uid 1015, home `/home/e2e_attacker`), providing forensic confirmation of the T1136 detection.

## Why this matters

A SIEM alert tells you something *looked* like an attack. A forensic artifact tells you whether it *was*. By pulling the actual account list (or, for SSH cases, the authentication logs) directly from the endpoint, the analyst can confirm the alert against live system state — the difference between "an alert fired" and "this happened, here is the evidence."

## Extending (out of scope for this lab)

The same model extends naturally to richer DFIR: collecting `/var/log/auth.log` for SSH brute-force forensics, running process or network artifacts, or building hunts across multiple endpoints. These were intentionally left out to keep the lab focused.
