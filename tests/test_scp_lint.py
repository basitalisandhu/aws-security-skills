import json

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("scp-guardrails", "scp_lint.py")
SCP = FIXTURES / "scp"


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
