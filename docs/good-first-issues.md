# Good first issues

Small, well-specified pieces of work for a first contribution. Each is self-contained, has a test to add, and needs no AWS account, credentials or network access. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first: standard library only, tests with every change, scripts never call AWS, plain language without em-dashes.

To claim one, open an issue with the title below (or comment on the existing one) and say you are working on it. Run `python3 -m pytest -q`, `python3 -m ruff check .` and `python3 scripts/validate_plugins.py` before opening the pull request.

## 1. aws-account-audit: unused IAM credentials

**Labels:** good first issue, aws-account-audit, python

**Context.** The credential report already holds `password_last_used` and `access_key_N_last_used_date`, but `audit_account.py` only checks key age, not keys or passwords that have not been used for a long time.

**Acceptance criteria.**
- New check `IAM-UNUSED-CREDENTIAL` (low): an active key or password not used for more than `--max-unused-days` (default 90), or never used and created more than that many days before `--as-of`.
- Fixture rows that trigger it and one that must not; tests in `tests/test_audit_account.py`.
- Docstring, `SKILL.md` and the README coverage section list the new check.

## 2. aws-account-audit: GuardDuty detector status

**Labels:** good first issue, aws-account-audit, python

**Context.** `GD-DISABLED` only checks that `list-detectors` returns an id. A detector can exist with `Status: DISABLED`.

**Acceptance criteria.**
- Optional input `guardduty-detector-<id>.json` (output of `aws guardduty get-detector --detector-id <id> --output json`) in the regional folder; a `Status` other than `ENABLED` produces `GD-DISABLED`.
- The collection loop in `SKILL.md` saves the file; a test covers enabled and disabled detectors.

## 3. scp-lint: condition operator mistakes

**Labels:** good first issue, scp-guardrails, python

**Context.** A region deny written with `StringEquals` instead of `StringNotEquals` on `aws:RequestedRegion` denies the allowed regions instead of the others.

**Acceptance criteria.**
- New warning `SCP-REGION-OPERATOR` when a Deny uses `StringEquals` or `StringLike` on `aws:RequestedRegion`.
- A fixture and a test; the docstring lists the check.

## 4. iam-review: read classification for data-reading actions

**Labels:** good first issue, iam-least-privilege-review, python

**Context.** `is_read()` treats every `Get*` action as read, so `secretsmanager:GetSecretValue` and `s3:GetObject` keep `"Resource": "*"` in the suggested policy.

**Acceptance criteria.**
- A short list of data-reading actions that are scoped like write actions in `suggest()`.
- A test showing `secretsmanager:GetSecretValue` on `*` gets a scoped resource template.

## 5. security-hub-triage: owner rules on resource tags

**Labels:** good first issue, security-hub-triage, python

**Context.** ASFF resources carry `Tags`; teams often route by an `owner` or `team` tag.

**Acceptance criteria.**
- Owner rule key `tag: {key: team, value: payments}` (exact match) in the config.
- A fixture finding with tags and a test; the config example and `SKILL.md` document the key.
