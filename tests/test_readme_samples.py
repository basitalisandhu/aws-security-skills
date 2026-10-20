"""The output samples in plugins/aws-security/README.md come from running the scripts on the committed fixtures.
These tests rerun the sampled commands and fail when a sampled line no longer matches the real output."""
from __future__ import annotations

import re
import subprocess
import sys

import pytest
from conftest import ROOT

README = (ROOT / "plugins" / "aws-security" / "README.md").read_text(encoding="utf-8")
SAMPLE_RE = re.compile(r"^\$ python3 (\S+\.py)(.*)$", re.M)


def samples():
    for m in SAMPLE_RE.finditer(README):
        script, args = m.group(1), m.group(2).split()
        block = README[m.end():].split("\n```", 1)[0]
        lines = [ln for ln in block.strip("\n").splitlines() if ln and not ln.startswith("$ ")]
        nxt = README[m.end():].find("\n$ ")
        if nxt != -1 and nxt < len(block):
            lines = [ln for ln in README[m.end():m.end() + nxt].strip("\n").splitlines() if ln]
        yield pytest.param(script, args, lines, id=script.rsplit("/", 1)[-1])


@pytest.mark.parametrize(("script", "args", "lines"), list(samples()))
def test_sampled_output_matches_the_script(script, args, lines):
    proc = subprocess.run([sys.executable, str(ROOT / script), *args], cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", timeout=120)
    assert proc.returncode in (0, 1), proc.stderr
    out = proc.stdout.splitlines()
    assert lines, script
    assert out[:len(lines)] == lines or all(ln in out for ln in lines), script


def test_readme_has_an_exit_code_table_and_six_sampled_commands():
    assert "## Exit codes" in README and "| 2 | Bad input or usage" in README
    assert len(list(samples())) == 6
