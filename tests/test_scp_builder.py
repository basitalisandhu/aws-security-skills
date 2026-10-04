import json

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("scp-guardrails", "scp_builder.py")
lint = load_script("scp-guardrails", "scp_lint.py")
SPEC = FIXTURES / "scp" / "full-spec.yaml"


def statements(docs):
    return {s["Sid"]: s for d in docs for s in d["Statement"]}


def test_full_spec_builds_valid_documents_under_limit(tmp_path):
    rc, out = run_json(mod, [str(SPEC), "--json", "--out", str(tmp_path)])
    assert rc == 0
    docs = out["documents"]
    for d in docs:
        assert d["Version"] == "2012-10-17"
        assert isinstance(d["Statement"], list) and d["Statement"]
        for st in d["Statement"]:
            assert st["Effect"] == "Deny"
            assert ("Action" in st) != ("NotAction" in st)
            assert "Resource" in st
        assert len(json.dumps(d, separators=(",", ":"))) <= 5120
        assert lint.lint_policy(d) == []
    written = sorted(p.name for p in tmp_path.iterdir())
    assert written == ["manifest.json"] + [f"scp-{i:02d}.json" for i in range(1, len(docs) + 1)]
    assert json.loads((tmp_path / "scp-01.json").read_text()) == docs[0]
    assert out["manifest"]["lint"] == []


def test_guardrail_contents():
    _, out = run_json(mod, [str(SPEC), "--json"])
    st = statements(out["documents"])
    assert set(st) >= {"DenyLeaveOrganization", "DenyRootUser", "ProtectCloudTrail", "ProtectGuardDuty",
                       "ProtectSecurityHub", "ProtectConfig", "DenyOutsideAllowedRegions",
                       "DenyIamUsersOutsideIdentityAccount", "RequireImdsv2OnLaunch", "DenyImdsv1RoleCredentials",
                       "DenyPublicS3CannedAcls"}
    region = st["DenyOutsideAllowedRegions"]
    assert "iam:*" in region["NotAction"] and "sts:*" in region["NotAction"]
    assert region["Condition"]["StringNotEquals"]["aws:RequestedRegion"] == ["ap-southeast-2", "us-east-1"]
    assert region["Condition"]["ArnNotLike"]["aws:PrincipalArn"] == [
        "arn:aws:iam::*:role/OrganizationAccountAccessRole", "arn:aws:iam::*:role/BreakGlassAdmin"]
    assert "ArnNotLike" in st["ProtectCloudTrail"]["Condition"]
    assert st["DenyIamUsersOutsideIdentityAccount"]["Condition"]["StringNotEquals"]["aws:PrincipalAccount"] == ["111122223333"]
    assert st["RequireImdsv2OnLaunch"]["Condition"]["StringNotEquals"]["ec2:MetadataHttpTokens"] == "required"


def test_small_limit_splits_into_several_documents_and_warns():
    docs, manifest = mod.build({**mod.load_spec(SPEC), "max_policy_chars": 1100})
    assert len(docs) > 4
    assert all(m["chars_compact"] <= 1100 for m in manifest["documents"])
    assert any("5 SCPs per target" in w for w in manifest["warnings"])
    # Every statement is placed exactly once.
    sids = [s for m in manifest["documents"] for s in m["statements"]]
    assert len(sids) == len(set(sids)) == len(mod.build_statements(mod.load_spec(SPEC)))


def test_minimal_json_spec_and_missing_exemption_warning():
    rc, out = run_json(mod, [str(FIXTURES / "scp" / "minimal-spec.json"), "--json"])
    assert rc == 0
    assert set(statements(out["documents"])) == {"DenyLeaveOrganization", "DenyOutsideAllowedRegions"}
    assert any("protected_roles" in w for w in out["manifest"]["warnings"])


def test_bad_specs_exit_2(write):
    for name, body in [("unknown.json", '{"deny_everything": true}'),
                       ("empty.json", '{}'),
                       ("acct.json", '{"deny_iam_users_outside": ["12345"]}'),
                       ("arn.json", '{"deny_root_user": true, "protected_roles": ["arn:aws:iam::123456789012:role/x"]}'),
                       ("regions.json", '{"allowed_regions": []}'),
                       ("broken.json", '{"allowed_regions": ')]:
        rc, _, err = run_main(mod, [str(write(name, body))])
        assert rc == 2, name
        assert err.startswith("error:"), name


def test_text_output():
    rc, out, _ = run_main(mod, [str(SPEC)])
    assert rc == 0 and "scp-01.json" in out and "/5120 chars" in out and "non-production OU" in out


def test_statement_larger_than_limit_is_a_spec_error(write):
    rc, _, err = run_main(mod, [str(write("s.json", '{"allowed_regions": ["eu-west-1"], "max_policy_chars": 500}'))])
    assert rc == 2 and "over the 500 limit" in err
