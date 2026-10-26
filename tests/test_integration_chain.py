"""End-to-end chain across three skills on one Security Hub export: what to fix first, how to stop it coming back,
and whether the resulting guardrail is safe to attach.

  1. security-hub-triage: triage_findings.py drops resolved and suppressed findings and groups the rest by control;
  2. preventive-control-mapper: preventive_map.py maps the same failing controls to preventive options and writes a
     merged SCP draft with --scp-out;
  3. scp-guardrails: scp_lint.py lints that draft, which must pass with no issue once a break-glass role is given.

The two first steps must agree on which findings are open, and every control the triage lists must come back from
the mapper as preventable, detective-only or unmapped, never silently dropped.
"""
from __future__ import annotations

import json
import subprocess
import sys

from conftest import FIXTURES, SKILLS

EXPORT = FIXTURES / "findings" / "securityhub-findings.json"


def run(script: str, *args) -> tuple[int, str]:
    proc = subprocess.run([sys.executable, str(script), *map(str, args)], capture_output=True, text=True, encoding="utf-8",
                          timeout=120)
    assert "Traceback" not in proc.stderr, proc.stderr
    return proc.returncode, proc.stdout


def test_triage_then_prevent_then_lint(tmp_path):
    rc, out = run(SKILLS / "security-hub-triage" / "scripts" / "triage_findings.py", EXPORT, "--json", "--fail-on", "NONE")
    assert rc == 0
    triage = json.loads(out)
    triaged = {c["control"] for c in triage["by_control"]}
    assert triaged

    scp = tmp_path / "preventive-scp.json"
    rc, out = run(SKILLS / "preventive-control-mapper" / "scripts" / "preventive_map.py", "--findings", EXPORT, "--json",
                  "--scp-out", scp, "--break-glass-role", "SecurityBreakGlass")
    assert rc in (0, 1)  # 1 when a control is unmapped, as in this export
    mapped = json.loads(out)
    assert mapped["failing_findings"] == triage["open"]
    preventable = {c["control"] for c in mapped["controls"]}
    detective = {c["control"] for c in mapped["detective_only"]}
    unmapped = {c["control"] for c in mapped["unmapped"]}
    assert preventable | detective | unmapped == triaged
    assert not (preventable & unmapped)

    rc, out = run(SKILLS / "scp-guardrails" / "scripts" / "scp_lint.py", scp, "--json")
    assert rc == 0
    [lint] = json.loads(out)
    assert lint["issues"] == []
    assert lint["chars_compact"] <= 10240
    policy = json.loads(scp.read_text(encoding="utf-8"))
    assert all(st["Effect"] == "Deny" for st in policy["Statement"])
