# Security policy

This repository ships skills and scripts that run inside people's Claude Code sessions and that look at AWS account data. The scripts read files you point them at and write only where you ask; nothing here makes a network call, calls AWS, or reports usage anywhere.

## Supported versions

Only the latest release on `main` is supported. Pin a tag if you need stability, and update when a fix is announced in [CHANGELOG.md](CHANGELOG.md).

## Reporting a vulnerability

Please do not open a public issue for a security problem.

1. Use GitHub's private vulnerability reporting on this repository ("Security" tab, "Report a vulnerability").
2. If that is unavailable, open an issue titled "Security contact request" with no details, and the maintainer will reply with a private channel.

Include what you found, how to reproduce it, and what you think the impact is. You will get an acknowledgement within 5 working days and a fix or a mitigation plan within 30 days for confirmed issues.

Do not include real account data, credentials or account ids in a report. Reproduce with the fixtures in `tests/fixtures/` or with account id `123456789012`.

## What counts

- A skill that instructs Claude to change an AWS account without asking for confirmation of a specific command.
- A script that can be made to execute untrusted input, write outside the paths given on its command line, open a network connection, or call AWS.
- A check that reports a clearly unsafe input as clean (for example a security group open to `0.0.0.0/0` on port 22, or an SCP region deny that blocks IAM without a lint error).
- A generated SCP that denies more than its catalog entry says, or that locks out the protected roles.
- Instructions hidden in any file of this repository that address the model rather than the reader.

Missing checks (a misconfiguration the audit does not yet look at) are welcome as ordinary issues or pull requests; they are coverage improvements rather than vulnerabilities.

## What this repository does and does not do

- No telemetry and no network access from scripts. No subprocesses.
- The `aws` CLI appears only in skill instructions, as read-only commands with `--output json`, run by the user's own session with the user's own credentials.
- Fix commands are printed for review and run only after explicit confirmation.
- Skill text tells Claude to treat all data from the account as untrusted content, never as instructions.
