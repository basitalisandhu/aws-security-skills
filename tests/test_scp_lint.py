import json

import pytest
from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("scp-guardrails", "scp_lint.py")
SCP = FIXTURES / "scp"


@pytest.mark.parametrize("operator", [
    "StringEquals", "StringLike", "StringEqualsIfExists", "StringLikeIfExists",
    "StringEqualsIgnoreCase", "StringEqualsIgnoreCaseIfExists",
    "ForAnyValue:StringEquals", "ForAllValues:StringLike",
    "ForAnyValue:StringEqualsIfExists", "ForAllValues:StringEqualsIgnoreCase",
])
def test_region_deny_warns_when_operator_denies_allowed_regions(operator):
    policy = json.loads((SCP / "bad-region-operator.json").read_text(encoding="utf-8"))
    statement = policy["Statement"][0]
    statement["Condition"] = {operator: {"aws:RequestedRegion": ["eu-west-1"]}}
    found = mod.lint_policy(policy)
    assert any(i["id"] == "SCP-REGION-OPERATOR" and i["level"] == "warning" for i in found)
    assert any(operator in i["message"] for i in found if i["id"] == "SCP-REGION-OPERATOR")
    assert "SCP-REGION-OPERATOR" in ids(SCP / "bad-region-operator.json")


@pytest.mark.parametrize("effect,operator,key", [
    ("Deny", "StringNotEquals", "aws:RequestedRegion"),
    ("Deny", "StringNotLike", "aws:RequestedRegion"),
    ("Deny", "StringNotEqualsIfExists", "aws:RequestedRegion"),
    ("Deny", "StringNotLikeIfExists", "aws:RequestedRegion"),
    ("Deny", "ForAnyValue:StringNotEquals", "aws:RequestedRegion"),
    ("Deny", "ForAllValues:StringNotLikeIfExists", "aws:RequestedRegion"),
    ("Allow", "StringEquals", "aws:RequestedRegion"),
    ("Allow", "StringEqualsIfExists", "aws:RequestedRegion"),
    ("Deny", "StringEquals", "aws:PrincipalArn"),
    ("Deny", "ForAnyValue:StringEqualsIfExists", "aws:PrincipalArn"),
])
def test_other_condition_operators_do_not_trigger_region_warning(effect, operator, key):
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": effect, "Action": "ec2:*", "Resource": "*",
        "Condition": {operator: {key: "eu-west-1"}},
    }]}
    assert not any(i["id"] == "SCP-REGION-OPERATOR" for i in mod.lint_policy(policy))


@pytest.mark.parametrize("operator,expected_code", [
    ("StringEqualsIfExists", 1),
    ("StringNotEqualsIfExists", 0),
])
def test_region_operator_variant_cli_exit_status(write, operator, expected_code):
    policy = json.loads((SCP / "bad-region-operator.json").read_text(encoding="utf-8"))
    condition = policy["Statement"][0]["Condition"]
    condition[operator] = condition.pop("StringEquals")
    file = write("region-variant.json", json.dumps(policy))
    rc, out = run_json(mod, [str(file), "--json", "--fail-on", "warning"])
    assert rc == expected_code
    assert [i["id"] for i in out[0]["issues"]] == (["SCP-REGION-OPERATOR"] if expected_code else [])


def ids(path):
    _, out = run_json(mod, [str(path), "--json", "--fail-on", "info"])
    return {i["id"] for i in out[0]["issues"]}


def test_allow_in_deny_list():
    assert ids(SCP / "bad-allow-in-deny-list.json") == {"SCP-ALLOW-IN-DENY-LIST"}
    _, out = run_json(mod, [str(SCP / "bad-allow-in-deny-list.json"), "--json", "--strategy", "allow-list"])
    assert out[0]["issues"] == []


def test_region_deny_with_action_star_blocks_global_services():
    found = ids(SCP / "bad-region-action-star.json")
    assert "SCP-REGION-BLOCKS-GLOBAL" in found and "SCP-NO-EXEMPTION" in found
    rc, _, _ = run_main(mod, [str(SCP / "bad-region-action-star.json")])
    assert rc == 1


def test_region_notaction_gaps():
    assert "SCP-REGION-GLOBAL-GAPS" in ids(SCP / "bad-region-gaps.json")
    rc, _, _ = run_main(mod, [str(SCP / "bad-region-gaps.json")])
    assert rc == 0  # warnings only; default --fail-on error
    rc, _, _ = run_main(mod, [str(SCP / "bad-region-gaps.json"), "--fail-on", "warning"])
    assert rc == 1


def test_notaction_principal_duplicate_and_deny_all():
    assert ids(SCP / "bad-notaction-and-principal.json") == {
        "SCP-ALLOW-NOTACTION", "SCP-DENY-NOTACTION-BARE", "SCP-PRINCIPAL", "SCP-DUPLICATE-SID", "SCP-DENY-ALL"}


def test_size_limit(write):
    big = {"Version": "2012-10-17", "Statement": [
        {"Sid": f"Deny{i}", "Effect": "Deny", "Action": [f"ec2:Action{j}" for j in range(20)], "Resource": "*"}
        for i in range(30)]}
    p = write("big.json", json.dumps(big))
    assert "SCP-SIZE" in ids(p)
    small = {"Version": "2012-10-17", "Statement": [big["Statement"][0]]}
    assert mod.lint_policy(small, limit=5120) == []
    assert any(i["id"] == "SCP-SIZE" for i in mod.lint_policy(small, limit=100))


def test_structure_and_version(write):
    assert ids(write("a.json", '{"Version": "2008-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:*"}]}')) == {
        "SCP-VERSION", "SCP-STRUCTURE"}
    assert ids(write("b.json", '{"Statement": [{"Effect": "Maybe", "Action": "*", "Resource": "*"}]}')) >= {"SCP-STRUCTURE"}
    assert ids(write("c.json", '[]')) == {"SCP-STRUCTURE"}


def test_describe_policy_output_and_full_allow_are_clean(write):
    assert ids(SCP / "describe-policy-output.json") == set()
    full = write("full.json", '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}')
    assert ids(full) == set()


def test_bad_input_exit_2(write):
    rc, _, err = run_main(mod, [str(write("x.json", "{oops"))])
    assert rc == 2 and "invalid JSON" in err
    rc, _, _ = run_main(mod, [str(write("y.json", '{"Policy": {"Content": "not json"}}'))])
    assert rc == 2


def test_builder_manifest_is_rejected_with_a_hint(tmp_path):
    # The documented glob used to pick up manifest.json and report it as a broken SCP.
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps({"limit": 5120, "documents": [{"file": "scp-01.json"}], "warnings": [], "lint": []}), encoding="utf-8")
    rc, out, err = run_main(mod, [str(p)])
    assert rc == 2 and out == ""
    assert "manifest" in err and "scp-*.json" in err


def test_pretty_file_over_the_limit_as_written_is_a_warning(tmp_path):
    doc = {"Version": "2012-10-17", "Statement": [{"Sid": "D", "Effect": "Deny", "Action": "ec2:RunInstances", "Resource": "*"}]}
    p = tmp_path / "scp.json"
    p.write_text(json.dumps(doc, indent=8), encoding="utf-8")
    compact_size = len(mod.compact(doc))
    rc, out = run_json(mod, [str(p), "--limit", str(compact_size + 5), "--fail-on", "warning", "--json"])
    assert rc == 1 and [i["id"] for i in out[0]["issues"]] == ["SCP-SIZE-AS-WRITTEN"]
    p.write_text(mod.compact(doc), encoding="utf-8")
    rc, out = run_json(mod, [str(p), "--limit", str(compact_size + 5), "--fail-on", "warning", "--json"])
    assert rc == 0 and out[0]["issues"] == []


def test_allow_with_notaction_is_valid_syntax_so_only_a_warning():
    # SCPs accept NotAction in Allow statements (Organizations SCP syntax page, checked 2026-10-18).
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}
    found = {i["id"]: i["level"] for i in mod.lint_policy(doc)}
    assert found == {"SCP-ALLOW-NOTACTION": "warning"}


def test_allow_with_a_specific_resource_is_an_error():
    # "In statements where the Effect element has a value of Allow, you can specify only * in the Resource element."
    doc = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::example-bucket"}]}
    found = {i["id"]: i["level"] for i in mod.lint_policy(doc, strategy="allow-list")}
    assert found == {"SCP-ALLOW-RESOURCE": "error"}
