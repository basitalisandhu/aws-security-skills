import json

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("agent-safe-aws-access", "agent_access.py")
lint = load_script("scp-guardrails", "scp_lint.py")
SPEC = FIXTURES / "agent-access" / "agent-spec.yaml"
AUTH = FIXTURES / "agent-access" / "auth-details.json"
GET_ROLE = FIXTURES / "agent-access" / "get-role-long-session.json"


def plan_spec(**overrides):
    return {**mod.load_spec(SPEC), **overrides}


def ids(findings):
    return {f["id"] for f in findings}


def all_actions(doc):
    return [a for st in doc["Statement"] for a in (st.get("Action") if isinstance(st.get("Action"), list) else [st.get("Action")]) if a]


def test_plan_writes_every_file_and_passes_its_own_review(tmp_path):
    rc, out = run_json(mod, ["plan", "--spec", str(SPEC), "--out", str(tmp_path), "--json"])
    assert rc == 0
    assert out["self_review"] == []
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "commands.md", "permission-policy.json", "permissions-boundary.json", "sandbox-scp.json",
        "trust-policy-123456789012.json", "trust-policy-locked.json"]
    assert json.loads((tmp_path / "permission-policy.json").read_text()) == out["files"]["permission-policy.json"]


def test_permission_policy_never_grants_star_or_service_wildcards():
    result = mod.plan(plan_spec())
    perm = result["files"]["permission-policy.json"]
    actions = all_actions(perm)
    assert "*" not in actions
    assert not [a for a in actions if a.endswith(":*")]
    assert all(st["Effect"] == "Allow" and "NotAction" not in st for st in perm["Statement"])
    # Data reads are only granted on the named prefix, never on every object.
    get_object = [st for st in perm["Statement"] if "s3:GetObject" in json.dumps(st["Action"])]
    assert [st["Resource"] for st in get_object] == ["arn:aws:s3:::example-artifacts/builds/*"]
    assert "secretsmanager:GetSecretValue" not in actions and "ssm:GetParameter" not in actions


def test_tasks_are_scoped_to_their_targets():
    perm = mod.plan(plan_spec())["files"]["permission-policy.json"]
    by_sid = {st["Sid"]: st for st in perm["Statement"]}
    deploy = by_sid["T2DeployStackChangeSets"]
    assert "arn:aws:cloudformation:ap-southeast-2:123456789012:stack/example-app/*" in deploy["Resource"]
    assert "cloudformation:DeleteStack" not in deploy["Action"]
    passrole = by_sid["T2PassExecutionRoleToCloudFormation"]
    assert passrole["Resource"] == ["arn:aws:iam::123456789012:role/example-app-cfn-exec"]
    assert passrole["Condition"]["StringEquals"]["iam:PassedToService"] == "cloudformation.amazonaws.com"
    assert by_sid["T3InvokeFunction"]["Resource"][0] == "arn:aws:lambda:ap-southeast-2:123456789012:function:example-report"
    assert by_sid["T1InventoryEc2"]["Condition"]["StringEquals"]["aws:RequestedRegion"] == ["ap-southeast-2"]
    assert "Condition" not in by_sid["T1InventoryIam"]


def test_trust_policy_requires_tags_source_identity_and_session_name():
    trust = mod.plan(plan_spec())["files"]["trust-policy-123456789012.json"]
    st = trust["Statement"][0]
    assert set(st["Action"]) == {"sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"}
    cond = st["Condition"]
    assert cond["StringEquals"]["aws:RequestTag/agent"] == "claude-code"
    assert cond["StringEquals"]["sts:SourceIdentity"] == ["jane.doe", "sam.lee"]
    assert cond["StringLike"]["sts:RoleSessionName"] == "claude-code@*"
    assert cond["ArnLike"]["aws:PrincipalArn"] == [
        "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_AgentOperators_*"]


def test_boundary_denies_iam_org_tampering_billing_and_deletes():
    boundary = mod.plan(plan_spec())["files"]["permissions-boundary.json"]
    for cat, (_, reps) in mod.CATEGORIES.items():
        for action in reps:
            assert not mod.allowed_by([boundary], action), (cat, action)
    by_sid = {st["Sid"]: st for st in boundary["Statement"]}
    assert by_sid["DenyPassRoleExceptExecutionRoles"]["NotResource"] == ["arn:aws:iam::123456789012:role/example-app-cfn-exec"]
    assert len(json.dumps(boundary, separators=(",", ":"))) <= mod.MANAGED_POLICY_LIMIT


def test_sandbox_scp_is_valid_under_limit_and_keyed_on_the_agent_role():
    scp = mod.plan(plan_spec())["files"]["sandbox-scp.json"]
    assert len(lint.compact(scp)) <= 5120
    assert lint.lint_policy(scp) == []
    by_sid = {st["Sid"]: st for st in scp["Statement"]}
    assert by_sid["AgentDenyIamOrgChanges"]["Condition"]["ArnLike"]["aws:PrincipalArn"] == "arn:aws:iam::*:role/agent-claude-code"
    protect = by_sid["ProtectAgentRole"]
    assert protect["Resource"] == "arn:aws:iam::*:role/agent-claude-code"
    assert "arn:aws:iam::*:role/BreakGlassAdmin" in protect["Condition"]["ArnNotLike"]["aws:PrincipalArn"]


def test_commands_have_session_name_convention_and_kill_switch():
    md = mod.plan(plan_spec())["commands_md"]
    assert "--role-session-name 'claude-code@jane.doe'" in md
    assert "--tags Key=agent,Value=claude-code Key=operator,Value=sam.lee" in md
    assert "--duration-seconds 2700" in md
    assert "AWSRevokeOlderSessions" in md and "aws:TokenIssueTime" in md and "DateLessThan" in md
    assert "aws iam update-assume-role-policy --role-name agent-claude-code --policy-document file://trust-policy-locked.json" in md
    assert "--max-session-duration 3600" in md


def test_bad_specs_exit_2(write):
    base = mod.load_spec(SPEC)
    cases = {
        "star-service": {"tasks": [{"type": "read-only-inventory", "services": ["*"]}]},
        "long-session": {"session_minutes": 240},
        "no-admin": {"admin_roles": []},
        "wide-pattern": {"trust": {"operator_role_arn_patterns": ["arn:aws:iam::*:role/*"]}},
        "unknown-task": {"tasks": [{"type": "run-anything"}]},
        "star-prefix": {"tasks": [{"type": "read-s3-prefix", "bucket": "example-artifacts", "prefix": "*"}]},
        "numeric-account": {"accounts": [123456789012]},
        "unknown-key": {"allow_everything": True},
    }
    for name, override in cases.items():
        spec = write(f"{name}.json", json.dumps({**base, **override}))
        rc, _, err = run_main(mod, ["plan", "--spec", str(spec)])
        assert rc == 2, (name, err)
        assert err.startswith("error:"), name


def test_review_flags_every_planted_problem_in_the_risky_role():
    rc, out = run_json(mod, ["review", "--role-json", str(AUTH), "--role-name", "agent-claude-code",
                             "--get-role", str(GET_ROLE), "--json"])
    assert rc == 1
    found = ids(out["findings"])
    assert {"AGENT-ADMIN", "AGENT-EFFECTIVE-RISK", "AGENT-NO-BOUNDARY", "AGENT-NOTACTION-ALLOW", "AGENT-PASSROLE-ANY",
            "AGENT-SERVICE-WILDCARD", "AGENT-DATA-READ-ANY", "AGENT-LONG-SESSION", "AGENT-ROLE-CHAINING",
            "AGENT-TRUST-ACCOUNT-ROOT", "AGENT-TRUST-NO-SESSION-TAGS", "AGENT-TRUST-NO-SOURCE-IDENTITY",
            "AGENT-WRITE-ON-ANY-RESOURCE"} <= found
    effective = {f["where"] for f in out["findings"] if f["id"] == "AGENT-EFFECTIVE-RISK"}
    assert effective == {"iam-changes", "logging-tampering", "billing", "destructive"}
    assert out["findings"][0]["severity"] == "critical"
    # Only the default policy version is evaluated: v1 of agent-extra (Action "*") is not.
    assert not any(f["id"] == "AGENT-ADMIN" and "agent-extra" in f["where"] for f in out["findings"])


def test_review_reads_url_encoded_trust_and_boundary_gaps():
    rc, out = run_json(mod, ["review", "--role-json", str(AUTH), "--role-name", "agent-ci-oidc", "--json"])
    assert rc == 1
    by_id = {f["id"]: f for f in out["findings"]}
    assert by_id["AGENT-TRUST-OIDC-NO-SUB"]["severity"] == "critical"
    gaps = [f for f in out["findings"] if f["id"] == "AGENT-BOUNDARY-GAP"]
    assert [g["where"] for g in gaps] == ["destructive"]
    assert "AGENT-NO-BOUNDARY" not in by_id and "AGENT-EFFECTIVE-RISK" not in by_id
    assert out["max_session_seconds"] == 3600


def test_review_of_a_planned_role_is_clean(write):
    result = mod.plan(plan_spec())
    files = result["files"]
    export = {"RoleDetailList": [{
        "RoleName": "agent-claude-code", "Arn": "arn:aws:iam::123456789012:role/agent-claude-code", "MaxSessionDuration": 3600,
        "AssumeRolePolicyDocument": files["trust-policy-123456789012.json"], "RolePolicyList": [],
        "AttachedManagedPolicies": [{"PolicyName": "perm", "PolicyArn": "arn:aws:iam::123456789012:policy/perm"}],
        "PermissionsBoundary": {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": "arn:aws:iam::123456789012:policy/bnd"}}],
        "Policies": [
            {"Arn": "arn:aws:iam::123456789012:policy/perm", "PolicyName": "perm",
             "PolicyVersionList": [{"IsDefaultVersion": True, "Document": files["permission-policy.json"]}]},
            {"Arn": "arn:aws:iam::123456789012:policy/bnd", "PolicyName": "bnd",
             "PolicyVersionList": [{"IsDefaultVersion": True, "Document": files["permissions-boundary.json"]}]}]}
    path = write("export.json", json.dumps(export))
    rc, out = run_json(mod, ["review", "--role-json", str(path), "--fail-on", "info", "--json"])
    assert out["findings"] == []
    assert rc == 0


def test_review_input_errors_exit_2(write):
    rc, _, err = run_main(mod, ["review", "--role-json", str(AUTH)])
    assert rc == 2 and "--role-name" in err
    rc, _, err = run_main(mod, ["review", "--role-json", str(AUTH), "--role-name", "missing"])
    assert rc == 2
    rc, _, _ = run_main(mod, ["review", "--role-json", str(write("x.json", "{}"))])
    assert rc == 2


def test_fail_on_threshold_and_text_output():
    rc, out, _ = run_main(mod, ["review", "--role-json", str(AUTH), "--role-name", "agent-ci-oidc", "--fail-on", "critical"])
    assert rc == 1 and "AGENT-TRUST-OIDC-NO-SUB" in out
    rc, out, _ = run_main(mod, ["plan", "--spec", str(SPEC)])
    assert rc == 0 and "must review every generated policy" in out
