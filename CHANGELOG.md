# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog, and the project uses semantic versioning.

## [Unreleased]

## [0.6.0] - 2026-10-26

### Added

- `aws-account-audit`: `GD-DISABLED` also fires for a GuardDuty detector that exists but whose `get-detector` status is not `ENABLED`, from optional `guardduty-detector-<id>.json` files saved next to `guardduty-detectors.json`; the fix is `aws guardduty update-detector --detector-id <id> --enable`. The collection loop in SKILL.md saves the files, a detector id that is not a GuardDuty id exits 2, and the secure fixture carries enabled detectors (closes #5).
- A `README.md` in every skill folder with one real sample run on a committed fixture; `tests/test_readme_samples.py` re-runs each sampled command and fails when the sample is no longer the start of the real output.
- Seeded fuzz tests for every script that reads an export or a spec (`tests/test_fuzz_parsers.py`): empty files, byte order marks, bytes that are not UTF-8, deep nesting, truncated and byte-flipped fixtures, and fixtures with one value swapped for another type. Each case first checks the unmodified fixture is accepted, so the fuzzing reaches the parser and not only argparse. Set `AWS_SECURITY_FUZZ_SEED` and `AWS_SECURITY_FUZZ_CASES` to explore further.
- An end-to-end test (`tests/test_integration_chain.py`) that runs Security Hub triage, the preventive control mapper and the SCP linter on one export, checking that triage and the mapper agree on the open findings, that every triaged control comes back as preventable, detective-only or unmapped, and that the merged SCP draft lints clean.

### Fixed

- Every script: a file that is not UTF-8, JSON nested tens of thousands of levels deep, or a value of the wrong type anywhere in an export or spec (`"suppress_accounts": 1` in a triage config, a string where `SecurityGroups` should be a list, `true` in a `UserPolicyList`) ended in a traceback. Each now exits 2 with a message, as documented; before the fix 21 of the 23 fuzz tests failed. A credential report row with missing trailing fields reads as empty fields instead of crashing the root checks.
- `landing-zone-blast-radius`: each account's callers were found by scanning every workload account, so 12,000 workloads took 4.8 s; they are indexed once now (0.2 s), with a scaling test.

### Changed

- Skill descriptions for `aws-agent-session-audit`, `iam-least-privilege-review`, `aws-spend-guardrails`, `sandbox-account-guardrail-pack`, `preventive-control-mapper` and `aws-incident-response-runbook` name the neighbours they are not for and the requests they were missing (cost alerts, admin policies on a role, ransomware that deletes objects); quoted trigger phrases are specific enough not to fire on any prompt that mentions an agent and an account.
- Version 0.6.0 in `pyproject.toml`, `plugin.json`, `marketplace.json`, the dispatcher and the README container examples.

## [0.5.0] - 2026-10-20

### Added

- `preventive-control-mapper`: `preventive_map.py` turns failing Security Hub controls (ASFF `get-findings` export), Prowler JSON-OCSF findings or a CSV with a `control_id` column into the preventive controls that stop the same misconfiguration being created again. A bundled table (`references/preventive-map.json`) covers 25 Security Hub controls across S3, EC2 and EBS, IAM, CloudTrail, Config, GuardDuty, KMS, RDS and Lambda, with the matching Prowler check ids. Each control lists its options strongest first (SCP statement, account setting, EC2 declarative policy, IaC check, then the AWS Config managed rule that detects a regression), each with the exact snippet, caveats and the AWS documentation page it was checked against. The script merges the SCP statements into one draft policy and reports its size against the 10,240-character SCP limit, lists unmapped controls instead of dropping them, and exits 0 (all mapped), 1 (unmapped control or draft over the limit) or 2 (bad input). Options: `--mapping`, `--format markdown|json`, `--out`, `--scp-out`, `--break-glass-role`, `--scp-limit`. 35 tests with synthetic fixtures under `tests/fixtures/preventive-map/`.
- Dispatcher subcommand `preventive-map`; the container image carries the mapping table and its build smoke-tests it, and the container check in CI runs the subcommand's `--help`.

### Changed

- `security-hub-triage` and `scp-guardrails` name the new skill as the next step after a clean-up.
- Version 0.5.0 in `pyproject.toml`, `plugin.json`, `marketplace.json`, the dispatcher and the README container examples; the READMEs list the new skill and say eleven skills.

## [0.4.2] - 2026-10-20

### Fixed

- `agent_access.py`: the list of spend and commitment actions denied by the permissions boundary and the sandbox SCP is named `SPEND_ACTIONS` (was `BILLING`). CodeQL's sensitive-name heuristic read the old name as private data and raised a false high-severity clear-text logging alert on `plan --json`; the list holds IAM action names only and the generated policies are unchanged. A test keeps module constants off names the heuristic treats as secrets.

### Changed

- `iam-least-privilege-review`: Scope sensitive data-read suggestions for Secrets Manager, SSM parameters, KMS decrypt, and S3 objects to resource ARNs instead of `*`.
- Version 0.4.2 in `pyproject.toml`, `plugin.json`, `marketplace.json`, the dispatcher and the README container examples.

## [0.4.1] - 2026-10-18

### Fixed

- SCP size and attachment quotas checked against the AWS Organizations quotas page: an SCP document can be 10,240 characters (5120 is the resource control policy limit) and 10 SCPs attach directly to one root, OU or account. `scp_builder.py`, `scp_lint.py`, `spend_guardrails.py`, `sandbox_pack.py`, `agent_access.py` and their vendored copies use 10,240 and 10; the docs and the catalog say so with the source.
- `sandbox_pack.py`, `spend_guardrails.py` and `agent_access.py` wrote SCP files indented although they measured the compact form. The AWS CLI and SDKs upload whitespace as written, so the files on disk could be larger than the reported size; SCP files are now written compact (IAM documents stay indented, since IAM does not count whitespace). `scp_lint.py` adds `SCP-SIZE-AS-WRITTEN` for a file that is over the limit only because of whitespace.
- `scp_lint.py`: `SCP-ALLOW-NOTACTION` is a warning, not an error (SCPs accept NotAction in Allow statements), and the new `SCP-ALLOW-RESOURCE` error flags an Allow statement whose Resource is not "*". The builder manifest passed by the documented `./scps/*.json` glob is refused with a hint; the SKILL.md command is now `./scps/scp-*.json`.
- `securityhub:DisableSecurityHubV2` (in the Service Authorization Reference and the AWS sample SCP) added to the Security Hub guardrail, the agent permissions boundary and the agent session audit's logging-tamper list.
- `agent_session_audit.py` reports CloudTrail events as IAM actions: Lambda event names lose their API version suffix, S3 ListBuckets is `s3:ListAllMyBuckets`, ListObjects, ListObjectsV2 and HeadBucket are `s3:ListBucket`, HeadObject is `s3:GetObject`, and event source `monitoring` is `cloudwatch`. Before, real exports flagged allowed calls and proposed removing permissions that were used.
- `landing-zone-blast-radius` recommended `aws:SourceAccount` for a pipeline role's deployment role; that key is only present for calls by AWS service principals, so it now says `aws:PrincipalArn`.
- `audit_account.py` exits 2 and names the file when a saved file is not the expected CLI output (a JSON list, an empty credential report, or no `SummaryMap`, `SecurityGroups` and so on) instead of counting its checks as passed or raising a traceback.
- `agent_session_audit.py` says "empty file" for an empty export, rejects lists that hold non-records, names the filter and record count when nothing matches, and refuses an empty or malformed allow list instead of flagging every call.
- `ir_runbook.py triage` rejects Findings entries without a Type (a list of numbers used to count as findings with exit 0) and names the file in errors; `agent_access.py review` names the file in JSON errors and exits 2 on a `--get-role` file of the wrong shape (it raised a traceback with exit 1); `spend_guardrails.py review` and `triage_findings.py` name the file in errors, and `--top` below 1 is a usage error.
- `scp_builder.py` rejects string booleans (`deny_root_user: "no"` used to switch the guardrail on), region codes and role names of the wrong form, and `max_policy_chars` outside 1 to 10,240.
- `blast_radius.py` rejects unknown keys (a typo such as `depend_on` was ignored), an `internet_facing` value other than true or false, an `email_domain` that is not a domain, and a workload that depends on itself; `depends_on` may be a single name.

### Changed

- `scp-guardrails` and `aws-account-audit` descriptions rewritten for recall on the shared trigger prompts (lexical eval recall 0.60 to 1.00 and 0.80 to 1.00, precision unchanged at 1.00).
- The plugin README has one exit code table for every script and real output samples from the fixtures, kept honest by `tests/test_readme_samples.py`; a synthetic CloudTrail fixture for `aws-agent-session-audit` is committed under `tests/fixtures/agent-session/`.
- Version 0.4.1 in `pyproject.toml`, `plugin.json`, `marketplace.json`, the dispatcher and the README container examples.

## [0.4.0] - 2026-10-09

### Added

- Warn when a region Deny uses a positive string comparison on aws:RequestedRegion,
  including IfExists and set-operator variants, with offline regression tests.

## [0.3.0] - 2026-10-05

### Added

- `aws-agent-session-audit`: `agent_session_audit.py` audits what an AI coding agent did in an AWS account from saved CloudTrail events (`lookup-events` output, delivered log files including `.json.gz`, or JSON lines of records) filtered by role session name or role: the time window, sessions and source IPs, actions by service with reads, writes and errors, resources touched, and 7 checks (logging and detection tampering, IAM writes and role assumption, destructive calls, actions outside a declared allow list, console sign-in, bursts of access-denied errors, other regions). With `--granted` it proposes which explicit grants to remove and what to replace each wildcard grant with; without it, it drafts an allow list from the actions used. Markdown or JSON, `--out`, access key ids and request parameters never printed, `--redact` for account ids, IPs and e-mail addresses. 14 tests with synthetic records.
- Dispatcher subcommand `agent-audit`; the container check in CI runs its `--help`.

### Changed

- `iam-least-privilege-review` and `agent-safe-aws-access` name their boundary with the new skill.
- Version 0.3.0 in `pyproject.toml`, `plugin.json`, `marketplace.json`, the dispatcher and the README container examples; the READMEs list the new skill and the searches it answers.

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
