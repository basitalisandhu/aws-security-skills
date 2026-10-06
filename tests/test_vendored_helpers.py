"""The spend and sandbox skills carry private copies of the SCP builder, the SCP linter and (sandbox only) the spend
generator, so each skill works when it is installed on its own. These tests keep every copy identical to its origin
apart from the two-line header and the private import names, and run each skill from a folder that holds only it."""
from __future__ import annotations

import shutil
import subprocess
import sys

import pytest
from conftest import SKILLS

SUBS = [("from scp_lint import", "from _scp_lint import"), ("from scp_builder import", "from _scp_builder import")]
COPIES = [
    ("aws-spend-guardrails", "_scp_builder.py", "scp-guardrails", "scp_builder.py"),
    ("aws-spend-guardrails", "_scp_lint.py", "scp-guardrails", "scp_lint.py"),
    ("sandbox-account-guardrail-pack", "_scp_builder.py", "scp-guardrails", "scp_builder.py"),
    ("sandbox-account-guardrail-pack", "_scp_lint.py", "scp-guardrails", "scp_lint.py"),
    ("sandbox-account-guardrail-pack", "_spend_guardrails.py", "aws-spend-guardrails", "spend_guardrails.py"),
]


@pytest.mark.parametrize(("skill", "copy", "origin_skill", "origin"), COPIES)
def test_copy_matches_origin(skill, copy, origin_skill, origin):
    lines = (SKILLS / skill / "scripts" / copy).read_text(encoding="utf-8").splitlines(keepends=True)
    assert lines[1].startswith(f"# Vendored copy of skills/{origin_skill}/scripts/{origin} ")
    assert lines[2].startswith("# Do not edit here")
    expected = (SKILLS / origin_skill / "scripts" / origin).read_text(encoding="utf-8")
    for old, new in SUBS:
        expected = expected.replace(old, new)
    assert lines[0] + "".join(lines[3:]) == expected, f"{skill}/scripts/{copy} drifted from {origin_skill}/scripts/{origin}"


@pytest.mark.parametrize(("skill", "script", "args"), [
    ("aws-spend-guardrails", "spend_guardrails.py", ["--budget", "references/example-budget.yaml", "--json"]),
    ("sandbox-account-guardrail-pack", "sandbox_pack.py", ["--spec", "references/example-spec.yaml", "--json"]),
])
def test_skill_runs_when_installed_alone(tmp_path, skill, script, args):
    alone = tmp_path / "skills" / skill
    shutil.copytree(SKILLS / skill, alone)
    proc = subprocess.run([sys.executable, str(alone / "scripts" / script), *args], cwd=alone, capture_output=True,
                          text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.lstrip().startswith("{")
