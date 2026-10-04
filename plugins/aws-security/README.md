# AWS Security

Five AWS security skills for Claude Code: a read-only account audit, an SCP guardrail builder and linter, a landing zone blast-radius designer, an IAM least-privilege reviewer, and a Security Hub and GuardDuty triage tool.

## Install

```text
/plugin marketplace add basitalisandhu/aws-security-skills
/plugin install aws-security@aws-security-skills
```

Skills then appear as `/aws-security:<skill>`. Scripts need Python 3.11 or newer on `PATH` as `python3`; they use the standard library only and make no network calls. The AWS CLI is used only in the collection steps the skills describe, with read-only credentials.

## Skills

| Skill | Triggers on | Produces |
|---|---|---|
| `aws-account-audit` | audit, baseline or health-check one AWS account | `audit_account.py` findings (17 checks) with severity, evidence and a fix command to review |
| `scp-guardrails` | write, review or debug service control policies | `scp_builder.py` SCP documents under 5120 characters; `scp_lint.py` findings |
| `landing-zone-blast-radius` | design an AWS organization, place a workload | `blast_radius.py` OU tree, account names, SCP map, blast-radius table |
| `iam-least-privilege-review` | review or tighten an IAM policy, check escalation | `iam_review.py` ranked findings and a tightened policy template |
| `security-hub-triage` | Security Hub or GuardDuty backlog, weekly review | `triage_findings.py` grouped findings and an owner-assigned action list |
