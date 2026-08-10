# Detection Tests

Sample-event tests that assert each custom rule **actually fires** - the
"detection-as-code" half of the project. A saved raw log per rule is fed through
`wazuh-logtest`; the runner checks the rule that fires against the expectation.

The authoritative rule-firing assertion needs a full Wazuh manager (`wazuh-logtest`
talks to `analysisd` over a socket), so it runs **on the live manager**. CI, which
has no Wazuh install, instead validates that this harness is complete and
self-consistent - every case references an existing, non-empty sample and declares
exactly one expectation, and the runner compiles - so it is always ready to run on
the manager.

## Layout

| Path | What |
|------|------|
| [`cases.yml`](cases.yml) | Test manifest: sample file → expected (or forbidden) rule id |
| [`samples/`](samples) | One raw log line per case |
| [`run_rule_tests.py`](run_rule_tests.py) | Runner - pipes samples through `wazuh-logtest`, asserts results |

## Run locally

On a Wazuh manager (has `/var/ossec/bin/wazuh-logtest`):

```bash
pip install pyyaml
python3 tests/run_rule_tests.py
```

Off a manager, the runner prints `SKIP` rather than failing, so it is safe to run
anywhere. On the manager it performs the real assertions.

## What's covered

- **Atomic rules** (100001, 100010, 100020) - asserted directly from a single
  event.
- **A negative control** - a benign `Accepted password` login must *not* trip a
  custom rule, so loosening a rule is caught.
- **Correlation rules** (100002, 100011) depend on `frequency`/`timeframe` state
  across many events and are validated by the live emulation runs, not
  single-line logtest. This is stated in `cases.yml`, not silently skipped.

**Not covered:** the Windows rules (1001xx). They need Sysmon/PowerShell events in
Wazuh's Windows JSON envelope rather than a syslog line, and there is no captured
sample to test against until the Windows endpoint is stood up. Adding invented
samples would assert the rules against a payload shape nobody has verified, so
this gap is left open and stated rather than papered over.

## What CI checks vs. the manager

- **CI** (`test-harness` job): the harness is complete and self-consistent, plus
  XML syntax and Sigma lint on the rules themselves - so a malformed rule or a
  broken test manifest turns the build red without needing a Wazuh install.
- **Live manager** (`run_rule_tests.py`): the actual rule-firing assertion. Break a
  rule (e.g. change rule 100020's `if_sid` to a wrong base rule) and the runner goes
  red - the pipeline, not a human, catches the regression.
