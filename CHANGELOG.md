# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog, and the project uses semantic versioning.

## [Unreleased]

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
