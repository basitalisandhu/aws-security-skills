# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog, and the project uses semantic versioning.

## [Unreleased]

## [0.1.0] - 2026-10-04

### Added

- Plugin marketplace `aws-security-skills` with one plugin, `aws-security`.
- `aws-account-audit`: read-only collection commands and `audit_account.py`, 17 offline checks (root MFA and keys, CloudTrail, GuardDuty, Security Hub, S3 public access block, open security groups, console users without MFA, access key age, admin policies, default VPC, EBS default encryption, password policy) with severity, evidence and fix commands.
- `scp-guardrails`: `scp_builder.py` (deny-list SCPs from a YAML or JSON spec, packed under the 5120-character limit), `scp_lint.py` (structure, size, Allow in deny-list, region denies that block global services, NotAction misuse, Principal, duplicate Sids) and `references/scp-catalog.md`.
- `landing-zone-blast-radius`: `blast_radius.py` (OU tree, account naming, foundation accounts, SCP attachment map, blast-radius table).
- `iam-least-privilege-review`: `iam_review.py` (wildcards, unscoped PassRole and AssumeRole, NotAction and NotResource, published privilege-escalation paths, tightened policy templates).
- `security-hub-triage`: `triage_findings.py` (ASFF and GuardDuty input, suppression config, grouping by control and resource, owner rules, ordered next actions).
- Offline pytest suite with hand-written fixtures, `scripts/validate_plugins.py`, ruff configuration, and a CI workflow with read-only permissions.
