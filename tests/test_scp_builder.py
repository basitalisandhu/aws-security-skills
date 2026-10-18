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
        assert len(json.dumps(d, separators=(",", ":"))) <= 10240
        assert lint.lint_policy(d) == []
    written = sorted(p.name for p in tmp_path.iterdir())
    assert written == ["manifest.json"] + [f"scp-{i:02d}.json" for i in range(1, len(docs) + 1)]
    assert json.loads((tmp_path / "scp-01.json").read_text(encoding="utf-8")) == docs[0]
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
    assert not any("SCPs per target" in w for w in manifest["warnings"])  # 10 fit on one target
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
    assert rc == 0 and "scp-01.json" in out and "/10240 chars" in out and "non-production OU" in out


def test_statement_larger_than_limit_is_a_spec_error(write):
    rc, _, err = run_main(mod, [str(write("s.json", '{"allowed_regions": ["eu-west-1"], "max_policy_chars": 500}'))])
    assert rc == 2 and "over the 500 limit" in err


# Pinned against the AWS sample "Deny-access-to-AWS-based-on-the-requested-AWS-region.json" in
# github.com/aws-samples/service-control-policy-examples (Region-controls), checked 2026-10-18.
AWS_REGION_EXAMPLE_NOT_ACTION = [
    "a4b:*", "acm:*", "aws-marketplace-management:*", "aws-marketplace:*", "aws-portal:*", "budgets:*", "ce:*",
    "chime:*", "cloudfront:*", "config:*", "cur:*", "directconnect:*", "ec2:DescribeRegions",
    "ec2:DescribeTransitGateways", "ec2:DescribeVpnGateways", "fms:*", "globalaccelerator:*", "health:*", "iam:*",
    "importexport:*", "kms:*", "mobileanalytics:*", "networkmanager:*", "organizations:*", "pricing:*", "route53:*",
    "route53domains:*", "route53-recovery-cluster:*", "route53-recovery-control-config:*",
    "route53-recovery-readiness:*", "s3:GetAccountPublic*", "s3:ListAllMyBuckets", "s3:ListMultiRegionAccessPoints",
    "s3:PutAccountPublic*", "shield:*", "sts:*", "support:*", "trustedadvisor:*", "waf-regional:*", "waf:*", "wafv2:*",
    "wellarchitected:*",
]


def test_region_exemptions_match_the_aws_example():
    assert mod.GLOBAL_SERVICE_ACTIONS == AWS_REGION_EXAMPLE_NOT_ACTION


def test_security_hub_guardrail_covers_the_v2_disable_action():
    # securityhub:DisableSecurityHubV2 is in the Service Authorization Reference and in the AWS sample SCP; without it
    # the newer Security Hub could be turned off under the guardrail.
    _, out = run_json(mod, [str(SPEC), "--json"])
    actions = statements(out["documents"])["ProtectSecurityHub"]["Action"]
    assert {"securityhub:DisableSecurityHub", "securityhub:DisableSecurityHubV2"} <= set(actions)


def test_imdsv2_statements_match_the_ec2_user_guide_examples():
    _, out = run_json(mod, [str(SPEC), "--json"])
    st = statements(out["documents"])
    assert st["RequireImdsv2OnLaunch"]["Resource"] == "arn:aws:ec2:*:*:instance/*"
    assert st["DenyImdsv1RoleCredentials"]["Condition"] == {"NumericLessThan": {"ec2:RoleDelivery": "2.0"}}
    assert st["DenyPublicS3CannedAcls"]["Condition"]["StringEquals"]["s3:x-amz-acl"] == [
        "authenticated-read", "public-read", "public-read-write"]


def test_string_booleans_are_rejected_not_treated_as_true(write):
    # "deny_root_user": "no" is a non-empty string and used to switch the guardrail on.
    rc, out, err = run_main(mod, [str(write("b.json", '{"deny_root_user": "no"}'))])
    assert rc == 2 and out == "" and "true or false" in err


def test_region_codes_and_role_names_are_validated(write):
    rc, _, err = run_main(mod, [str(write("r.json", '{"allowed_regions": ["Sydney"]}'))])
    assert rc == 2 and "region code" in err
    rc, _, err = run_main(mod, [str(write("p.json", '{"deny_root_user": true, "protected_roles": ["break glass"]}'))])
    assert rc == 2 and "role name" in err
    rc, _ = run_json(mod, [str(write("ok.json", '{"allowed_regions": ["us-gov-west-1", "ap-southeast-2"], '
                                                 '"protected_roles": ["Admin*"]}')), "--json"])
    assert rc == 0


def test_max_policy_chars_must_be_a_number_within_the_aws_limit(write):
    for value in ('"abc"', "10241", "0", "true"):
        rc, out, err = run_main(mod, [str(write("m.json", '{"deny_root_user": true, "max_policy_chars": ' + value + "}"))])
        assert rc == 2 and out == "" and "max_policy_chars" in err, value


def test_size_and_attachment_quotas_match_the_aws_organizations_quotas_page():
    # Pinned to docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html, checked 2026-10-18:
    # an SCP document can be 10,240 characters (5120 is the RCP limit) and up to 10 SCPs attach to one target.
    assert mod.SCP_LIMIT == 10240 and mod.MAX_ATTACHED == 10
    assert lint.SCP_LIMIT == 10240


def test_more_documents_than_one_target_takes_is_a_warning(monkeypatch):
    monkeypatch.setattr(mod, "MAX_ATTACHED", 3)
    docs, manifest = mod.build({**mod.load_spec(SPEC), "max_policy_chars": 1100})
    assert len(docs) > 2
    assert any("3 SCPs per target" in w for w in manifest["warnings"])
