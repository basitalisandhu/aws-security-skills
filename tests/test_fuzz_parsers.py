"""Seeded fuzz tests for every script that reads an export or a spec from outside.

Each parser gets the same kinds of bad input: empty files, a byte order mark, bytes that are not UTF-8, deep nesting,
truncated or byte-flipped copies of the committed fixtures, and fixtures with one value swapped for a value of another
type (a number where a list belongs, a list where an object belongs, an impossible date). The contract checked is the
documented one: exit 0, 1 or 2 and never a Python traceback. The generator is seeded, so a failure reproduces; set
AWS_SECURITY_FUZZ_SEED and AWS_SECURITY_FUZZ_CASES to explore further locally.
"""
from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys

import pytest
from conftest import FIXTURES, SKILLS

SEED = int(os.environ.get("AWS_SECURITY_FUZZ_SEED", "20261026"))
CASES = int(os.environ.get("AWS_SECURITY_FUZZ_CASES", "10"))
FIXED = [b"", b"\xef\xbb\xbf", b"\xff\xfe\x00", b"null", b"[]", b"{}", b"1", b'"text"', b"[" * 50000 + b"]" * 50000,
         b"key: [unclosed\n  - a: b: c\n", b"\t- x\n:\n"]
sys.path.insert(0, str(SKILLS / "scp-guardrails" / "scripts"))
import _miniyaml  # noqa: E402


class Fuzzer:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)

    def flip(self, text: str) -> bytes:
        b = bytearray(text.encode("utf-8"))
        for _ in range(self.rng.randint(1, 5)):
            if not b:
                b = bytearray(b"{")
            i = self.rng.randrange(len(b))
            op = self.rng.random()
            if op < 0.3:
                del b[i:i + self.rng.randint(1, 16)]
            elif op < 0.55:
                b[i:i] = bytes(self.rng.randrange(256) for _ in range(self.rng.randint(1, 6)))
            elif op < 0.75:
                b = b[:i]
            else:
                b[i:i] = self.rng.choice([b'"', b"{", b"[", b"\\", b"\xff", b"\x00", b"\n", b"null", b": ", b"- ", b"#"])
        return bytes(b)

    def swap(self, node):
        if isinstance(node, dict) and node and self.rng.random() < 0.75:
            key = self.rng.choice(list(node))
            node[key] = self.swap(node[key])
            return node
        if isinstance(node, list) and node and self.rng.random() < 0.75:
            i = self.rng.randrange(len(node))
            node[i] = self.swap(node[i])
            return node
        return self.rng.choice([None, 1, -1.5, True, "s", [], {}, ["s", 1, None], {"k": [1]}, "2026-13-45T99:99:99Z", "*"])

    def type_swap(self, text: str) -> bytes | None:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            try:
                doc = _miniyaml.load(text)
            except Exception:  # noqa: BLE001 - any parse failure means this seed cannot be type-swapped
                return None
        for _ in range(self.rng.randint(1, 3)):
            doc = self.swap(doc)
        return json.dumps(doc).encode("utf-8")

    def inputs(self, seeds: list[str]) -> list[bytes]:
        out = list(FIXED)
        for _ in range(CASES):
            seed = self.rng.choice(seeds)
            swapped = self.type_swap(seed) if self.rng.random() < 0.6 else None
            out.append(swapped if swapped is not None else self.flip(seed))
        return out


def assert_clean(argv: list, data: bytes) -> None:
    proc = subprocess.run([sys.executable, *map(str, argv)], capture_output=True, timeout=120)
    err = proc.stderr.decode("utf-8", errors="replace")
    assert "Traceback" not in err, f"{argv[0].name} crashed on {data[:120]!r}:\n{err[-600:]}"
    assert proc.returncode in (0, 1, 2), f"{argv[0].name} exited {proc.returncode} on {data[:120]!r}:\n{err[-600:]}"


def script(skill: str, name: str):
    return SKILLS / skill / "scripts" / name


# name: (script, seed fixtures, argv builder taking the fuzzed file, file suffix)
CASES_TABLE = {
    "scp_lint": (script("scp-guardrails", "scp_lint.py"), sorted((FIXTURES / "scp").glob("*.json")), lambda f: [f], ".json"),
    "scp_builder": (script("scp-guardrails", "scp_builder.py"), [FIXTURES / "scp" / "full-spec.yaml", FIXTURES / "scp" / "minimal-spec.json"],
                    lambda f: [f, "--json"], ".yaml"),
    "iam_review": (script("iam-least-privilege-review", "iam_review.py"), sorted((FIXTURES / "iam").glob("*.json")), lambda f: [f], ".json"),
    "blast_radius": (script("landing-zone-blast-radius", "blast_radius.py"),
                     [FIXTURES / "blast-radius" / "workloads.yaml", *sorted((FIXTURES / "blast-radius").glob("*.json"))],
                     lambda f: [f, "--json"], ".yaml"),
    "triage_findings": (script("security-hub-triage", "triage_findings.py"),
                        [FIXTURES / "findings" / "securityhub-findings.json", FIXTURES / "findings" / "guardduty-findings.json"],
                        lambda f: [f], ".json"),
    "triage_config": (script("security-hub-triage", "triage_findings.py"), [FIXTURES / "findings" / "triage-config.yaml"],
                      lambda f: [FIXTURES / "findings" / "securityhub-findings.json", "--config", f], ".yaml"),
    "ir_runbook": (script("aws-incident-response-runbook", "ir_runbook.py"), [FIXTURES / "incident" / "guardduty-findings.json"],
                   lambda f: ["triage", "--guardduty", f], ".json"),
    "agent_access_plan": (script("agent-safe-aws-access", "agent_access.py"), [FIXTURES / "agent-access" / "agent-spec.yaml"],
                          lambda f: ["plan", "--spec", f, "--json"], ".yaml"),
    "agent_access_review": (script("agent-safe-aws-access", "agent_access.py"), [FIXTURES / "agent-access" / "auth-details.json"],
                            lambda f: ["review", "--role-json", f, "--role-name", "agent-claude-code", "--json"], ".json"),
    "agent_access_get_role": (script("agent-safe-aws-access", "agent_access.py"), [FIXTURES / "agent-access" / "get-role-long-session.json"],
                              lambda f: ["review", "--role-json", FIXTURES / "agent-access" / "auth-details.json", "--role-name", "agent-claude-code",
                                          "--get-role", f], ".json"),
    "spend_generate": (script("aws-spend-guardrails", "spend_guardrails.py"), [FIXTURES / "spend" / "budget.yaml"],
                       lambda f: ["--budget", f, "--json"], ".yaml"),
    "spend_review": (script("aws-spend-guardrails", "spend_guardrails.py"), [FIXTURES / "spend" / "cost-explorer-daily.json"],
                     lambda f: ["review", "--cost-explorer", f, "--json"], ".json"),
    "sandbox_pack": (script("sandbox-account-guardrail-pack", "sandbox_pack.py"), [FIXTURES / "sandbox" / "sandbox.yaml"],
                     lambda f: ["--spec", f, "--json"], ".yaml"),
    "preventive_findings": (script("preventive-control-mapper", "preventive_map.py"),
                            [FIXTURES / "preventive-map" / "securityhub-findings.json", FIXTURES / "preventive-map" / "prowler-ocsf.json"],
                            lambda f: ["--findings", f], ".json"),
    "preventive_csv": (script("preventive-control-mapper", "preventive_map.py"),
                       [FIXTURES / "preventive-map" / "controls.csv", FIXTURES / "preventive-map" / "status-column.csv"],
                       lambda f: ["--findings", f], ".csv"),
    "preventive_mapping": (script("preventive-control-mapper", "preventive_map.py"),
                           [SKILLS / "preventive-control-mapper" / "references" / "preventive-map.json"],
                           lambda f: ["--findings", FIXTURES / "preventive-map" / "securityhub-findings.json", "--mapping", f], ".json"),
    "session_trail": (script("aws-agent-session-audit", "agent_session_audit.py"), [FIXTURES / "agent-session" / "trail.json"],
                      lambda f: [f], ".json"),
    "session_allow_list": (script("aws-agent-session-audit", "agent_session_audit.py"), [FIXTURES / "agent-session" / "allow-list.txt"],
                           lambda f: [FIXTURES / "agent-session", "--allow-list", f], ".txt"),
}


@pytest.mark.parametrize("name", sorted(CASES_TABLE))
def test_parser_never_crashes(tmp_path, name):
    target, seeds, argv, suffix = CASES_TABLE[name]
    fuzz = Fuzzer(SEED + sum(map(ord, name)))
    texts = [p.read_text(encoding="utf-8") for p in seeds]
    # the unmodified seed must be accepted, or the argv is wrong and the fuzzing below would only test argparse
    first = tmp_path / f"seed{suffix}"
    first.write_text(texts[0], encoding="utf-8")
    proc = subprocess.run([sys.executable, str(target), *map(str, argv(first))], capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert proc.returncode in (0, 1), f"{name}: the seed fixture is rejected: {proc.stderr[-400:]}"
    for i, data in enumerate(fuzz.inputs(texts)):
        f = tmp_path / f"in{i}{suffix}"
        f.write_bytes(data)
        assert_clean([target, *argv(f)], data)


def test_account_audit_folder_with_one_bad_file(tmp_path):
    src = FIXTURES / "account-audit" / "insecure"
    files = sorted(p for p in src.rglob("*") if p.is_file())
    fuzz = Fuzzer(SEED)
    for i in range(CASES + len(FIXED)):
        folder = tmp_path / f"acct{i}"
        shutil.copytree(src, folder)
        target = files[i % len(files)]
        inputs = fuzz.inputs([target.read_text(encoding="utf-8")])
        data = inputs[i % len(inputs)]
        (folder / target.relative_to(src)).write_bytes(data)
        assert_clean([script("aws-account-audit", "audit_account.py"), folder], data)


@pytest.mark.parametrize(("name", "content"), [
    ("not-utf8", b'{"Statement": "caf\xe9"}'),
    ("wrong-type", b'{"UserDetailList": [{"UserName": "alice", "UserPolicyList": [true]}]}'),
    ("deep", b"[" * 50000 + b"]" * 50000),
], ids=["not-utf8", "wrong-type", "deep"])
def test_bad_policy_exits_2_with_a_message(tmp_path, name, content):
    f = tmp_path / f"{name}.json"
    f.write_bytes(content)
    proc = subprocess.run([sys.executable, str(script("iam-least-privilege-review", "iam_review.py")), str(f)],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)
    assert proc.stderr.startswith("error:") and "Traceback" not in proc.stderr


def test_short_credential_report_row_is_read_as_empty_fields(tmp_path):
    folder = tmp_path / "acct"
    shutil.copytree(FIXTURES / "account-audit" / "insecure", folder)
    report = folder / "credential-report.csv"
    lines = report.read_text(encoding="utf-8").splitlines()
    report.write_text("\n".join([lines[0], lines[1].split(",", 3)[0] + ",x"] + lines[2:]) + "\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, str(script("aws-account-audit", "audit_account.py")), str(folder), "--json"],
                          capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert proc.returncode in (0, 1), proc.stderr
    assert "Traceback" not in proc.stderr
