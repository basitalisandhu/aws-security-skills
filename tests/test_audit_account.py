import json
import shutil

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("aws-account-audit", "audit_account.py")
INSECURE = FIXTURES / "account-audit" / "insecure"
SECURE = FIXTURES / "account-audit" / "secure"


def checks(report):
    return [f["check"] for f in report["findings"]]


def test_insecure_account_reports_every_seeded_issue():
    rc, rep = run_json(mod, [str(INSECURE), "--json", "--as-of", "2026-10-01"])
    assert rc == 1
    assert rep["account_id"] == "123456789012"
    found = set(checks(rep))
    assert found == {"ROOT-MFA", "ROOT-ACCESS-KEYS", "CT-MULTI-REGION", "CT-NOT-LOGGING", "GD-DISABLED", "SH-DISABLED",
                     "S3-ACCOUNT-PAB", "S3-BUCKET-PAB", "SG-OPEN-ADMIN", "SG-OPEN-ALL", "IAM-CONSOLE-NO-MFA",
                     "IAM-KEY-AGE", "IAM-ADMIN-POLICY", "VPC-DEFAULT-IN-USE", "EBS-DEFAULT-ENCRYPTION",
                     "IAM-PASSWORD-POLICY"}
    assert rep["counts"]["critical"] == 3
    # Sorted by severity, critical first.
    assert rep["findings"][0]["severity"] == "critical"
    assert all("fix" in f and "evidence" in f for f in rep["findings"])


def test_security_group_rules_cover_ssh_rdp_range_ipv6_and_all_traffic():
    _, rep = run_json(mod, [str(INSECURE), "--json", "--as-of", "2026-10-01"])
    sg = {(f["check"], f["resource"].split()[0]) for f in rep["findings"] if f["check"].startswith("SG-")}
    assert ("SG-OPEN-ADMIN", "sg-0123456789abcdef0") in sg        # 22 from 0.0.0.0/0
    assert ("SG-OPEN-ADMIN", "sg-0fedcba9876543210") in sg        # 3000-4000 range covers 3389, from ::/0
    assert ("SG-OPEN-ALL", "sg-0aaaabbbbccccdddd") in sg
    assert not any(r == "sg-0eeeeffff00001111" for _, r in sg)    # 10.0.0.0/8 is not open
    ipv6 = next(f for f in rep["findings"] if f["resource"].startswith("sg-0fedcba9876543210"))
    assert "Ipv6Ranges" in ipv6["fix"]


def test_admin_policy_skips_aws_managed_and_non_default_versions():
    _, rep = run_json(mod, [str(INSECURE), "--json", "--as-of", "2026-10-01"])
    admin = sorted(f["resource"] for f in rep["findings"] if f["check"] == "IAM-ADMIN-POLICY")
    assert admin == ["arn:aws:iam::123456789012:policy/LegacyAdmin", "arn:aws:iam::123456789012:user/alice inline:everything"]


def test_key_age_uses_as_of_and_threshold():
    _, rep = run_json(mod, [str(INSECURE), "--json", "--as-of", "2026-10-01"])
    aged = sorted(f["resource"] for f in rep["findings"] if f["check"] == "IAM-KEY-AGE")
    assert aged == ["arn:aws:iam::123456789012:user/alice", "arn:aws:iam::123456789012:user/ci-deployer"]
    _, rep = run_json(mod, [str(INSECURE), "--json", "--as-of", "2026-10-01", "--max-key-age", "2000"])
    assert "IAM-KEY-AGE" not in checks(rep)


def test_missing_per_bucket_file_is_not_evaluated_not_passed():
    _, rep = run_json(mod, [str(INSECURE), "--json", "--as-of", "2026-10-01"])
    assert any("example-not-collected" in n for n in rep["not_evaluated"])
    assert not any("example-private-data" in f["resource"] for f in rep["findings"])


def test_secure_account_with_regions_folder():
    rc, rep = run_json(mod, [str(SECURE), "--json", "--as-of", "2026-10-01"])
    assert rc == 0  # default --fail-on high
    assert [(f["check"], f["region"]) for f in rep["findings"]] == [("EBS-DEFAULT-ENCRYPTION", "ap-southeast-2"),
                                                                     ("S3-BUCKET-PAB", "")]
    assert rep["findings"][1]["severity"] == "low"  # account-level block is full
    rc, _, _ = run_main(mod, [str(SECURE), "--fail-on", "medium", "--as-of", "2026-10-01"])
    assert rc == 1


def test_partial_input_lists_not_evaluated(tmp_path):
    shutil.copy(INSECURE / "ec2-ebs-encryption-default.json", tmp_path)
    rc, rep = run_json(mod, [str(tmp_path), "--json", "--fail-on", "none"])
    assert rc == 0
    assert checks(rep) == ["EBS-DEFAULT-ENCRYPTION"]
    assert any(n.startswith("ROOT-MFA") for n in rep["not_evaluated"])
    assert any(n.startswith("GD-DISABLED") for n in rep["not_evaluated"])


def test_table_output_and_report_file(tmp_path):
    out = tmp_path / "report.json"
    rc, text, _ = run_main(mod, [str(INSECURE), "--as-of", "2026-10-01", "--output", str(out)])
    assert rc == 1
    assert "ROOT-MFA" in text and "need human verification" in text
    assert json.loads(out.read_text(encoding="utf-8"))["counts"]["critical"] == 3


def test_bad_input_exit_2(tmp_path, write):
    rc, _, err = run_main(mod, [str(tmp_path)])
    assert rc == 2 and "no recognised input files" in err
    write("account-summary.json", "{not json")
    rc, _, err = run_main(mod, [str(tmp_path)])
    assert rc == 2 and "invalid JSON" in err
    rc, _, _ = run_main(mod, [str(INSECURE), "--as-of", "yesterday"])
    assert rc == 2
    rc, _, _ = run_main(mod, [str(tmp_path / "missing")])
    assert rc == 2


def test_help_mentions_checks():
    rc, out, _ = run_main(mod, ["--help"])
    assert rc == 0 and "ROOT-MFA" in out and "SG-OPEN-ALL" in out
