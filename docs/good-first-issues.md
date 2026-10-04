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

## 6. agent-safe-aws-access: inventory allowlist for Step Functions

**Labels:** good first issue, agent-safe-aws-access, python

**Context.** `INVENTORY_ACTIONS` in `agent_access.py` has no entry for `states`, so a read-only inventory task cannot list state machines.

**Acceptance criteria.**
- A `states` entry with metadata-only actions (`states:ListStateMachines`, `states:DescribeStateMachine`, `states:ListExecutions`), and no action that returns execution input or output.
- A test that plans an inventory task for `states` and checks the statement and its region condition; the SKILL.md limits line still holds.

## 7. agent-safe-aws-access: report an engaged kill switch

**Labels:** good first issue, agent-safe-aws-access, python

**Context.** After the kill switch runs, the agent role carries an inline policy named `AWSRevokeOlderSessions` that denies everything for sessions issued before a time. `review` treats it as an ordinary inline policy and says nothing about it.

**Acceptance criteria.**
- New info finding `AGENT-KILL-SWITCH-ACTIVE` naming the `aws:TokenIssueTime` value when that inline policy is present.
- A fixture role with the policy and a test; the docstring check list and `SKILL.md` mention the finding.

## 8. aws-incident-response-runbook: map RDS login findings

**Labels:** good first issue, aws-incident-response-runbook, python

**Context.** GuardDuty RDS Protection finding types (`CredentialAccess:RDS/*`) are reported as unmapped by `ir_runbook.py triage`.

**Acceptance criteria.**
- Map them to `suspicious-iam-activity` or a new scenario, with a line in `references/guardduty-mapping.md` explaining why.
- A parametrized case in `tests/test_ir_runbook.py`.

## 9. aws-incident-response-runbook: checklist items in the JSON output

**Labels:** good first issue, aws-incident-response-runbook, python

**Context.** Teams track the post-incident checklist in a ticketing tool and copy it by hand from the Markdown.

**Acceptance criteria.**
- `--json` output gains a `checklist` list with one string per item.
- A test that the list matches the Markdown checklist items.

## 10. aws-spend-guardrails: group the review by region

**Labels:** good first issue, aws-spend-guardrails, python

**Context.** `review` reads `SERVICE` and `LINKED_ACCOUNT` groups. Crypto-mining spikes often show first in an unused region, which a `REGION` group would reveal.

**Acceptance criteria.**
- `REGION` is read when it is one of the two group-by dimensions, and the text and JSON output gain a by-region total.
- A small fixture grouped by `SERVICE` and `REGION`, and a test.

## 11. sandbox-account-guardrail-pack: per-account README values

**Labels:** good first issue, sandbox-account-guardrail-pack, python

**Context.** `README-sandbox-users.md` names the OU-wide budget only. Some teams give each sandbox account its own budget amount.

**Acceptance criteria.**
- Optional spec key `accounts: [{id, name, monthly_limit}]`; when set, the README lists each account with its limit.
- A test with two accounts; the spec docstring and `references/example-spec.yaml` document the key.
