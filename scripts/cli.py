#!/usr/bin/env python3
"""aws-security: one command for the aws-security skill scripts.

    aws-security <subcommand> [args]       run one skill script with the given arguments
    aws-security <subcommand> --help       that script's own help
    aws-security --help                    list the subcommands

Each subcommand runs plugins/aws-security/skills/<skill>/scripts/<script>.py unchanged, in a child process with
the same Python, stdin, stdout, stderr and exit code. Standard library only. This is the entrypoint of the
container image ghcr.io/basitalisandhu/aws-security-skills.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

__version__ = "0.4.0"

PROG = "aws-security"
ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "plugins" / "aws-security" / "skills"

# subcommand: (skill directory, script, one-line summary)
COMMANDS: dict[str, tuple[str, str, str]] = {
    "audit": ("aws-account-audit", "audit_account.py", "Offline checks over a folder of read-only AWS CLI exports"),
    "scp-build": ("scp-guardrails", "scp_builder.py", "Build deny-list SCPs from a YAML or JSON spec"),
    "scp-lint": ("scp-guardrails", "scp_lint.py", "Lint SCP JSON files (structure, size, risky patterns)"),
    "blast-radius": ("landing-zone-blast-radius", "blast_radius.py", "Organizations layout and blast-radius table from a spec"),
    "iam-review": ("iam-least-privilege-review", "iam_review.py", "Least-privilege review of IAM policy documents"),
    "triage": ("security-hub-triage", "triage_findings.py", "Group and order Security Hub (ASFF) and GuardDuty findings"),
    "agent-access": ("agent-safe-aws-access", "agent_access.py", "Plan or review least-privilege AWS access for an AI agent"),
    "ir-runbook": ("aws-incident-response-runbook", "ir_runbook.py", "Incident response runbook per scenario, or from GuardDuty"),
    "spend": ("aws-spend-guardrails", "spend_guardrails.py", "Budgets, anomaly monitor and spend SCPs; review cost exports"),
    "sandbox": ("sandbox-account-guardrail-pack", "sandbox_pack.py", "Guardrail pack for a sandbox OU (SCPs, baseline, expiry)"),
    "agent-audit": ("aws-agent-session-audit", "agent_session_audit.py", "What an agent role session did, from CloudTrail exports"),
}


def script_path(name: str) -> Path:
    skill, script, _ = COMMANDS[name]
    return SKILLS / skill / "scripts" / script


def usage() -> str:
    width = max(len(n) for n in COMMANDS)
    lines = [
        f"usage: {PROG} <subcommand> [args]",
        "",
        f"Runs one of the aws-security skill scripts. Use '{PROG} <subcommand> --help' for its options.",
        "",
        "subcommands:",
    ]
    lines += [f"  {n.ljust(width)}  {h} ({script})" for n, (_, script, h) in COMMANDS.items()]
    lines += ["", "options:", "  -h, --help     show this help and exit", "  --version      show the version and exit"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(usage(), file=sys.stderr)
        return 2
    first, rest = args[0], args[1:]
    if first in ("-h", "--help", "help") and not rest:
        print(usage())
        return 0
    if first == "help":
        first, rest = rest[0], ["--help"]
    if first == "--version":
        print(f"{PROG} {__version__}")
        return 0
    if first not in COMMANDS:
        print(f"{PROG}: unknown subcommand {first!r}\n\n{usage()}", file=sys.stderr)
        return 2
    return subprocess.call([sys.executable, str(script_path(first)), *rest])


if __name__ == "__main__":
    sys.exit(main())
