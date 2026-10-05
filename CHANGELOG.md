# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog, and the project uses semantic versioning.

## [Unreleased]

## [0.2.1] - 2026-10-05

### Changed

- Rewrote all nine skill descriptions to 363 to 594 characters (from up to 1,020): each starts with a verb, states the goal before the mechanism, carries one quoted phrase a user would type, a "Use when ..." sentence and a "Not for ..." boundary, and stays double-quoted.
- `aws-spend-guardrails` and `sandbox-account-guardrail-pack` no longer import modules from sibling skills, so each works when installed on its own: they carry private copies (`_scp_builder.py`, `_scp_lint.py`, and `_spend_guardrails.py` in the sandbox pack), each with a header naming its origin, and `tests/test_vendored_helpers.py` fails when a copy drifts and runs both skills from a folder that holds only that skill.
- `aws-account-audit` states its boundary with `aws-identity-and-logging-evidence` in compliance-evidence-skills.
- Tests open text files with `encoding="utf-8"`, and CI runs tests, ruff and the `--help` check on `windows-latest` as well as Ubuntu and macOS.
- The plugin and root READMEs mention the CIS AWS Foundations benchmark, the Well-Architected security pillar and permission boundaries, with what the skills do and do not cover.
- `scripts/validate_plugins.py` now fails when a description is over 600 characters, is not double-quoted, or lacks "Use " or "Not for", and when a SKILL.md has no `## Limits` section; `tests/test_validate_plugins.py` covers each rule.
- Version 0.2.1 in `pyproject.toml`, `plugin.json`, `marketplace.json`, the dispatcher and the README container examples.

## [0.2.0] - 2026-10-04

Four new skills, each with a standard-library script, hand-written fixtures with planted problems, and offline tests. The container image gains four subcommands.

### Added

- `agent-safe-aws-access`: `agent_access.py plan` turns a spec (agent, operators, accounts, regions, session length, tasks) into an IAM Identity Center or role-pattern trust policy that requires `agent` and `operator` session tags, a source identity and a `<agent>@<operator>` session name; a permission policy from a vetted allowlist per task type (read-only inventory, deploy one stack, invoke one Lambda function, read one log prefix, read one S3 prefix); a permissions boundary that denies IAM, Organizations and account changes, CloudTrail, GuardDuty, Security Hub and Config tampering, billing and purchase commitments, destructive deletes and role chaining; a sandbox OU SCP backstop; the `aws sts assume-role` commands; and a kill switch (`AWSRevokeOlderSessions` deny on `aws:TokenIssueTime`, locked trust policy, CloudTrail query). `agent_access.py review` checks an exported role against the same rules with 18 check ids.
- `aws-incident-response-runbook`: `ir_runbook.py` writes a Markdown runbook for six scenarios (leaked access key, compromised EC2 instance, public S3 bucket, suspicious IAM activity, ransomware against S3 or EBS, crypto-mining) with read-only inventory first, containment commands marked as requiring confirmation, evidence preservation (snapshots, `lookup-events`, Athena), eradication, recovery, a post-incident checklist and timeline and communications templates. `ir_runbook.py triage` maps exported GuardDuty finding types to a scenario and fills in identifiers that match their format.
- `aws-spend-guardrails`: `spend_guardrails.py` generates AWS Budgets JSON (cost and usage budgets with actual and forecast alerts), a Cost Anomaly Detection monitor and subscription, and sandbox spend-deny SCPs (instance types, EBS IOPS and volume types, SageMaker GPU instances, Bedrock customization and provisioned throughput, chosen services, purchase commitments, protection of budgets and anomaly monitors). `spend_guardrails.py review` summarises a daily Cost Explorer export by service, account and month against the budget and flags days above a factor of the prior 7-day median.
- `sandbox-account-guardrail-pack`: `sandbox_pack.py` emits SCPs built by importing `scp_builder.py` and `spend_guardrails.py` (plus IAM user creation and owner-tag denies), packed under 5120 characters and linted with `scp_lint.py`; an account baseline checklist; a tag-based auto-expiry design with the EventBridge Scheduler command, a Lambda sweeper in Python pseudocode (dry run by default) and its role policies; budget files; and a README for sandbox users.
- Dispatcher subcommands `agent-access`, `ir-runbook`, `spend` and `sandbox`, with tests.
- Six good first issues for the new skills.

### Changed

- Version 0.2.0 in `pyproject.toml`, `plugin.json`, `marketplace.json` and the dispatcher; README skill tables, coverage lists and container examples updated.
- CI runs `--help` for the new subcommands in the container job.

## [0.1.1] - 2026-10-04

The skill scripts are published as a container image on GitHub Packages, using only the workflow's `GITHUB_TOKEN`: `ghcr.io/basitalisandhu/aws-security-skills`, tagged `0.1.1` and `latest`, for linux/amd64 and linux/arm64, with an SPDX SBOM, a build provenance attestation and a keyless cosign signature. The skills themselves are unchanged.

### Added

- `scripts/cli.py`: a standard-library dispatcher, `aws-security <subcommand> [args]`, over the skill scripts (`audit`, `scp-build`, `scp-lint`, `blast-radius`, `iam-review`, `triage`), with `--help` listing the subcommands and `--version`; tests in `tests/test_cli.py`.
- `Dockerfile`: two stages on a digest-pinned `python:3.12-slim`, only the dispatcher and the skill scripts, no pip dependencies, uid 1000, `WORKDIR /work`, entrypoint `aws-security`.
- `publish-github-packages.yml`: on a `v*` tag, tests, checks that every version field matches the tag, builds, pushes, attests and signs the image, and creates the GitHub release with the SBOM attached. Pull requests that touch packaging run it as a dry run.
- CI job that builds the image and runs `--help`, every subcommand's `--help` and `--version`, and checks the user and working directory.
- README Install section with the `docker run` usage and the verify commands.

## [0.1.0] - 2026-10-04

### Added

- Plugin marketplace `aws-security-skills` with one plugin, `aws-security`.
- `aws-account-audit`: read-only collection commands and `audit_account.py`, 17 offline checks (root MFA and keys, CloudTrail, GuardDuty, Security Hub, S3 public access block, open security groups, console users without MFA, access key age, admin policies, default VPC, EBS default encryption, password policy) with severity, evidence and fix commands.
- `scp-guardrails`: `scp_builder.py` (deny-list SCPs from a YAML or JSON spec, packed under the 5120-character limit), `scp_lint.py` (structure, size, Allow in deny-list, region denies that block global services, NotAction misuse, Principal, duplicate Sids) and `references/scp-catalog.md`.
- `landing-zone-blast-radius`: `blast_radius.py` (OU tree, account naming, foundation accounts, SCP attachment map, blast-radius table).
- `iam-least-privilege-review`: `iam_review.py` (wildcards, unscoped PassRole and AssumeRole, NotAction and NotResource, published privilege-escalation paths, tightened policy templates).
- `security-hub-triage`: `triage_findings.py` (ASFF and GuardDuty input, suppression config, grouping by control and resource, owner rules, ordered next actions).
- Offline pytest suite with hand-written fixtures, `scripts/validate_plugins.py`, ruff configuration, and a CI workflow with read-only permissions.
