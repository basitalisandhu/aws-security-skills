"""The vendored YAML reader must finish on any input: every copy is identical, malformed sequences such as "- - -:"
raise YAMLError instead of looping for ever (before 0.6.1 they hung every script that reads a YAML spec), and a seeded
run over random YAML-like token strings ends inside a time limit with only YAMLError raised.

Each run happens in a child process with a timeout, so a regression shows up as a failed test, not a stuck suite.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest
from conftest import SKILLS

COPIES = sorted(SKILLS.glob("*/scripts/_miniyaml.py"))
HANGERS = ["- - -:", "- - - - -:", "-  - -: -", "a:\n  - - -:", "[{x: 1}: 2]", "--- &x \n"]

PROBE = r'''
import json, random, sys
sys.path.insert(0, sys.argv[1])
import _miniyaml
cases = json.load(sys.stdin)
toks = ["- ", "-", "  ", ":", ": ", "a", "b: ", "[", "]", "{", "}", ",", "\n", "\n  ", "\n    ", "#", '"', "'",
        "&x ", "*x", "|", ">", "---", "...", "? ", "!!str ", "1", "null", "- - ", "-:", "--- &x ", "\t"]
rng = random.Random(20261026)
cases += ["".join(rng.choice(toks) for _ in range(rng.randint(1, 18))) for _ in range(int(sys.argv[2]))]
for text in cases:
    try:
        _miniyaml.load(text)
    except _miniyaml.YAMLError:
        pass
print("done", len(cases))
'''


def test_every_copy_is_identical():
    assert len(COPIES) == 6
    assert len({p.read_text(encoding="utf-8") for p in COPIES}) == 1


@pytest.mark.parametrize("copy", COPIES, ids=lambda p: p.parent.parent.name)
def test_malformed_and_random_yaml_finishes_with_yamlerror_only(copy):
    count = 3000 if copy == COPIES[0] else 200
    proc = subprocess.run([sys.executable, "-c", PROBE, str(copy.parent), str(count)], input=json.dumps(HANGERS),
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr[-800:]
    assert proc.stdout.strip() == f"done {len(HANGERS) + count}"


def test_a_spec_that_used_to_hang_exits_2(tmp_path):
    spec = tmp_path / "spec.yaml"
    spec.write_text("allowed_regions:\n  - - -:\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, str(SKILLS / "scp-guardrails" / "scripts" / "scp_builder.py"), str(spec)],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2, proc.stderr
    assert "cannot parse" in proc.stderr
