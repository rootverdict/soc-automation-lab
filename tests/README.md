# Detection Tests

Sample-event tests that assert each custom rule **actually fires** — the
"detection-as-code" half of the project. A saved raw log per rule is fed through
`wazuh-logtest`; the runner checks the rule that fires against the expectation.
CI runs this on every push/PR, so breaking a rule turns the build red.

## Layout

| Path | What |
|------|------|
| [`cases.yml`](cases.yml) | Test manifest: sample file → expected (or forbidden) rule id |
| [`samples/`](samples) | One raw log line per case |
| [`run_rule_tests.py`](run_rule_tests.py) | Runner — pipes samples through `wazuh-logtest`, asserts results |

## Run locally

On a Wazuh manager (has `/var/ossec/bin/wazuh-logtest`):

```bash
pip install pyyaml
python3 tests/run_rule_tests.py
```

Off a manager, the runner prints `SKIP` rather than failing — the real run
happens in CI inside the `wazuh/wazuh-manager` container.

## What's covered

- **Atomic rules** (100001, 100010, 100020) — asserted directly from a single
  event.
- **A negative control** — a benign `Accepted password` login must *not* trip a
  custom rule, so loosening a rule is caught.
- **Correlation rules** (100002, 100011) depend on `frequency`/`timeframe` state
  across many events and are validated by the live emulation runs, not
  single-line logtest. This is stated in `cases.yml`, not silently skipped.

## Prove CI works

Break a rule in a PR (e.g. change rule 100020's `if_sid` to a wrong base rule)
and watch `rule-firing-tests` go red. That demonstration is the point of
detection-as-code — the pipeline, not a human, catches the regression.
