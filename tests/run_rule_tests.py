#!/usr/bin/env python3
"""
Sample-event test runner for the SOC Automation Lab custom Wazuh rules.

For each case in cases.yml it pipes a raw log line through `wazuh-logtest`
and checks the rule that fires against the expectation:

  expect_rule:     that rule id MUST appear in the logtest output
  expect_no_rule:  that rule id must NOT appear (negative control)

Exit code is non-zero if any case fails, so CI goes red on a broken rule.

Requires a Wazuh install (uses /var/ossec/bin/wazuh-logtest), so it runs on the
manager host - logtest talks to analysisd over a local socket.

GitHub Actions does NOT run these assertions: the `test-harness` job in
.github/workflows/detections-ci.yml only proves the harness is complete and
self-consistent (every case references an existing, non-empty sample and
declares exactly one expectation, and this runner parses). The authoritative
rule-firing check is running this script on the manager. See tests/README.md.
"""
import os
import re
import shutil
import subprocess
import sys
import time

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

HERE = os.path.dirname(os.path.abspath(__file__))
LOGTEST = os.environ.get("WAZUH_LOGTEST", "/var/ossec/bin/wazuh-logtest")
RULE_ID_RE = re.compile(r"id:\s*'?(\d+)'?", re.IGNORECASE)


def run_logtest(log_line: str, retries: int = 3) -> str:
    """Feed one log line to wazuh-logtest and return its output.

    analysisd's logtest socket can still be warming up on the first call even
    after the socket file exists, which yields empty output. Retry a couple of
    times so a cold socket isn't misreported as a rule-assertion failure.
    """
    out = ""
    for attempt in range(retries):
        proc = subprocess.run(
            [LOGTEST, "-q"],
            input=log_line,
            capture_output=True,
            text=True,
            timeout=30,
        )
        out = proc.stdout + proc.stderr
        if "id:" in out.lower() or "phase" in out.lower():
            return out
        time.sleep(3)
    return out


def fired_rule_ids(output: str) -> set:
    """Extract every rule id logtest reported for the event."""
    ids = set()
    for line in output.splitlines():
        if "id:" in line.lower() and ("rule" in line.lower() or "'" in line):
            m = RULE_ID_RE.search(line)
            if m:
                ids.add(m.group(1))
    return ids


def main() -> int:
    with open(os.path.join(HERE, "cases.yml")) as fh:
        cases = yaml.safe_load(fh)["cases"]

    if not shutil.which(LOGTEST) and not os.path.exists(LOGTEST):
        print(f"SKIP: {LOGTEST} not found (run on a Wazuh manager or in the "
              f"wazuh-manager container).")
        return 0

    failures = 0
    for case in cases:
        name = case["name"]
        with open(os.path.join(HERE, case["file"])) as fh:
            log_line = fh.read().strip()

        out = run_logtest(log_line)
        ids = fired_rule_ids(out)

        if "expect_rule" in case:
            want = str(case["expect_rule"])
            if want in ids:
                print(f"PASS  {name}: rule {want} fired")
            else:
                print(f"FAIL  {name}: expected rule {want}, got {sorted(ids) or 'none'}")
                failures += 1
        elif "expect_no_rule" in case:
            forbid = str(case["expect_no_rule"])
            if forbid not in ids:
                print(f"PASS  {name}: rule {forbid} correctly did not fire")
            else:
                print(f"FAIL  {name}: rule {forbid} fired but should not have")
                failures += 1

    print(f"\n{len(cases) - failures}/{len(cases)} cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
