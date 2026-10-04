from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("iam-least-privilege-review", "iam_review.py")
IAM = FIXTURES / "iam"


def review(*names, extra=()):
    rc, rep = run_json(mod, [*(str(IAM / n) for n in names), "--json", *extra])
    return rc, rep


def checks(rep):
    return {f["check"] for f in rep["findings"]}


def test_full_admin_is_critical_and_ranked_first():
    rc, rep = review("admin.json")
    assert rc == 1
    assert rep["findings"][0]["check"] in {"IAM-FULL-ADMIN", "IAM-PRIVESC"}
    assert rep["findings"][0]["severity"] == "critical" and rep["findings"][0]["rank"] == 1
    assert "IAM-FULL-ADMIN" in checks(rep)


def test_ci_deployer_findings():
    _, rep = review("ci-deployer.json")
    assert checks(rep) == {"IAM-PRIVESC", "IAM-ASSUMEROLE-ANY", "IAM-PASSROLE-UNSCOPED", "IAM-SERVICE-WILDCARD",
                           "IAM-WRITE-ON-ANY-RESOURCE", "IAM-WILDCARD-ACTION"}
    paths = {f["evidence"] for f in rep["findings"] if f["check"] == "IAM-PRIVESC"}
    assert "iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction" in paths
    assert "iam:CreatePolicyVersion" in paths  # policy/* is a wildcard resource


def test_scoped_policy_is_clean():
    rc, rep = review("scoped.json")
    assert rc == 0 and rep["findings"] == []
    assert rep["suggested_policies"] == {}


def test_explicit_deny_removes_escalation_paths():
    _, rep = review("denied-escalation.json")
    assert "IAM-PRIVESC" not in checks(rep)
    assert "IAM-PASSROLE-UNSCOPED" not in checks(rep)
    assert "IAM-SERVICE-WILDCARD" in checks(rep)


def test_notaction_allow_and_policy_version_output():
    _, rep = review("notaction.json")
    assert "IAM-NOTACTION-ALLOW" in checks(rep) and "IAM-PRIVESC" in checks(rep)
    _, rep = review("policy-version-output.json")
    assert any(f["check"] == "IAM-PRIVESC" and f["evidence"] == "iam:AttachUserPolicy" for f in rep["findings"])


def test_authorization_details_skips_aws_managed_unless_asked():
    _, rep = review("authorization-details.json")
    policies = {f["policy"] for f in rep["findings"]}
    assert "arn:aws:iam::123456789012:policy/LegacyAdmin" in policies
    assert "arn:aws:iam::aws:policy/AdministratorAccess" not in policies
    assert not any("app-role" in p for p in policies)  # URL-encoded scoped inline policy
    _, rep = review("authorization-details.json", extra=["--include-aws-managed"])
    assert "arn:aws:iam::aws:policy/AdministratorAccess" in {f["policy"] for f in rep["findings"]}


def test_suggested_policy_scopes_resources_and_passrole():
    _, rep = review("ci-deployer.json")
    sugg = rep["suggested_policies"]["ci-deployer.json"]["Statement"]
    by_sid = {s["Sid"]: s for s in sugg}
    assert by_sid["DeployRead"]["Action"] == ["lambda:GetFunction"] and by_sid["DeployRead"]["Resource"] == "*"
    assert by_sid["DeployIamScoped"]["Condition"]["StringEquals"]["iam:PassedToService"] == "<service>.amazonaws.com"
    assert by_sid["AssumeStsScoped"]["Resource"] == "arn:aws:iam::<account-id>:role/<role-name>"
    assert by_sid["BucketsS3Scoped"]["Action"] == ["<list-the-s3-actions-in-use>"]
    assert by_sid["PolicyAdmin"]["Resource"] == "arn:aws:iam::123456789012:policy/*"  # already specific, unchanged


def test_text_output_and_fail_on():
    rc, out, _ = run_main(mod, [str(IAM / "ci-deployer.json")])
    assert rc == 1 and "IAM-PRIVESC" in out and "replace every <placeholder>" in out
    rc, _, _ = run_main(mod, [str(IAM / "ci-deployer.json"), "--fail-on", "none"])
    assert rc == 0


def test_bad_input_exit_2(write):
    rc, _, err = run_main(mod, [str(write("x.json", '{"hello": 1}'))])
    assert rc == 2 and "not a policy document" in err
    rc, _, _ = run_main(mod, [str(write("y.json", "{broken"))])
    assert rc == 2
