import ast
import json
from pathlib import Path

from conftest import FIXTURES, load_script, run_json, run_main, script_path

mod = load_script("sandbox-account-guardrail-pack", "sandbox_pack.py")
lint = load_script("scp-guardrails", "scp_lint.py")
SPEC = FIXTURES / "sandbox" / "sandbox.yaml"


def build(**overrides):
    return mod.build({**mod.load_spec(SPEC), **overrides})


def scps(result):
    return [doc for name, doc in result["files"].items() if name.startswith("scps/scp-")]


def sids(result):
    return {s["Sid"]: s for d in scps(result) for s in d["Statement"]}


def test_pack_writes_every_file(tmp_path):
    rc, _, _ = run_main(mod, ["--spec", str(SPEC), "--out", str(tmp_path)])
    assert rc == 0
    written = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert written == sorted([
        "README-sandbox-users.md", "baseline-checklist.md", "auto-expiry/design.md", "auto-expiry/scheduler-role-policy.json",
        "auto-expiry/sweeper-role-policy.json", "auto-expiry/ttl_sweeper.py", "budget/anomaly-monitor.json",
        "budget/anomaly-subscription.json", "budget/budget-cost.json", "budget/commands.md", "budget/notifications-cost.json",
        "scps/manifest.json", "scps/scp-01.json", "scps/scp-02.json"])


def test_every_scp_is_under_the_limit_and_passes_scp_lint(tmp_path):
    result = build()
    docs = scps(result)
    assert docs
    for doc in docs:
        assert len(lint.compact(doc)) <= 5120
        assert lint.lint_policy(doc) == []
    # The written files lint clean with the scp_lint command line too.
    run_main(mod, ["--spec", str(SPEC), "--out", str(tmp_path)])
    files = sorted(str(p) for p in (tmp_path / "scps").glob("scp-*.json"))
    rc, out = run_json(lint, [*files, "--fail-on", "info", "--json"])
    assert rc == 0 and all(r["issues"] == [] for r in out)


def test_scps_reuse_scp_builder_and_spend_statements():
    builder = load_script("scp-guardrails", "scp_builder.py")
    st = sids(build())
    for sid in ("DenyLeaveOrganization", "DenyRootUser", "ProtectCloudTrail", "ProtectGuardDuty", "ProtectSecurityHub",
                "ProtectConfig", "DenyOutsideAllowedRegions", "RequireImdsv2OnLaunch", "DenyImdsv1RoleCredentials",
                "DenyPublicS3CannedAcls", "ProtectAccountPublicAccessBlock", "DenyIamUserCreation", "RequireOwnerTagOnLaunch",
                "DenyExpensiveInstanceTypes", "DenyHighIopsVolumes", "DenyProvisionedIopsVolumeTypes",
                "DenySageMakerGpuInstanceTypes", "DenyBedrockCustomizationAndThroughput", "DenyExpensiveServices",
                "DenyPurchaseCommitments", "ProtectBudgetsAndAnomalyMonitors"):
        assert sid in st, sid
    assert st["DenyOutsideAllowedRegions"]["NotAction"] == builder.GLOBAL_SERVICE_ACTIONS
    assert st["DenyOutsideAllowedRegions"]["Condition"]["StringNotEquals"]["aws:RequestedRegion"] == ["ap-southeast-2", "us-east-1"]
    exempt = ["arn:aws:iam::*:role/OrganizationAccountAccessRole", "arn:aws:iam::*:role/SandboxAdmin"]
    assert st["DenyIamUserCreation"]["Condition"]["ArnNotLike"]["aws:PrincipalArn"] == exempt
    assert st["ProtectBudgetsAndAnomalyMonitors"]["Condition"]["ArnNotLike"]["aws:PrincipalArn"] == exempt
    assert st["RequireOwnerTagOnLaunch"]["Condition"] == {"Null": {"aws:RequestTag/owner": "true"}}
    # Private copies inside this skill (kept identical to the origin by test_vendored_helpers.py).
    assert Path(mod.scp_builder.__file__).resolve() == script_path("sandbox-account-guardrail-pack", "_scp_builder.py")
    assert Path(mod.spend_guardrails.__file__).resolve() == script_path("sandbox-account-guardrail-pack", "_spend_guardrails.py")


def test_baseline_checklist_covers_the_required_items():
    md = build()["files"]["baseline-checklist.md"]
    assert "log archive account 111122223333" in md
    assert "aws cloudtrail describe-trails --output json" in md
    for region in ("ap-southeast-2", "us-east-1"):
        assert f"aws guardduty list-detectors --region {region} --output json" in md
        assert f"aws ec2 describe-vpcs --region {region} --filters Name=is-default,Values=true --output json" in md
    assert "aws budgets describe-budgets" in md
    assert "TTL sweeper" in md
    assert "To remove one (REQUIRES CONFIRMATION" in md


def test_auto_expiry_design_and_sweeper():
    files = build()["files"]
    design = files["auto-expiry/design.md"]
    assert "aws scheduler create-schedule --region ap-southeast-2 --name sandbox-ttl-sweeper" in design
    assert "--schedule-expression 'cron(0 18 * * ? *)' --schedule-expression-timezone 'Australia/Sydney'" in design
    assert "--flexible-time-window Mode=OFF" in design
    code = files["auto-expiry/ttl_sweeper.py"]
    tree = ast.parse(code)
    assert {n.name for n in tree.body if isinstance(n, ast.FunctionDef)} == {"parse_date", "decide", "handler"}
    assert 'TTL_TAG = "expires-on"' in code and "DEFAULT_TTL_DAYS = 14" in code and "GRACE_DAYS = 3" in code
    assert 'DRY_RUN = os.environ.get("DRY_RUN", "true")' in code


def test_sweeper_decide_rules():
    import datetime

    code = build()["files"]["auto-expiry/ttl_sweeper.py"].replace("import boto3  # provided by the Lambda runtime", "")
    ns: dict = {}
    exec(compile(code, "ttl_sweeper.py", "exec"), ns)  # generated code under test; no AWS client is created
    decide = ns["decide"]
    today = datetime.date(2026, 10, 5)
    assert decide({}, today) == ("tag", datetime.date(2026, 10, 19))
    assert decide({"expires-on": "not-a-date"}, today)[0] == "tag"
    assert decide({"expires-on": "2027-01-01"}, today) == ("tag", datetime.date(2026, 11, 4))
    assert decide({"expires-on": "2026-10-10"}, today)[0] == "keep"
    assert decide({"expires-on": "2026-10-05"}, today)[0] == "stop"
    assert decide({"expires-on": "2026-10-02"}, today)[0] == "delete"


def test_sweeper_role_limits_destruction_to_tagged_resources():
    policy = build()["files"]["auto-expiry/sweeper-role-policy.json"]
    st = {s["Sid"]: s for s in policy["Statement"]}
    assert st["StopAndDeleteOnlyTagged"]["Condition"] == {"Null": {"aws:ResourceTag/expires-on": "false"}}
    assert st["TagExpiry"]["Condition"]["ForAllValues:StringEquals"]["aws:TagKeys"] == ["expires-on"]
    assert all(s["Effect"] == "Allow" and "*" not in json.dumps(s["Action"]) for s in policy["Statement"])


def test_users_readme_matches_the_scps():
    readme = build()["files"]["README-sandbox-users.md"]
    assert readme.startswith("# Using the sandbox accounts")
    assert "`ap-southeast-2`, `us-east-1`" in readme
    assert "`redshift`, `redshift-serverless`" in readme
    assert "200 USD" in readme and "platform-team@example.com" in readme
    minimal = build(spend={"deny_commitments": True}, budget=None)["files"]["README-sandbox-users.md"]
    assert "Reserved capacity" in minimal and "redshift" not in minimal and "GPU" not in minimal


def test_bad_specs_exit_2(write):
    base = mod.load_spec(SPEC)
    cases = {
        "no-regions": {"allowed_regions": []},
        "no-protected": {"protected_roles": []},
        "bad-log-archive": {"log_archive_account": "1234"},
        "ttl-order": {"default_ttl_days": 60, "max_ttl_days": 30},
        "bad-schedule": {"sweep_schedule": "every day"},
        "aws-tag": {"ttl_tag_key": "aws:expiry"},
        "bad-spend": {"spend": {"deny_services": ["iam"]}},
        "spend-roles": {"spend": {"protected_roles": ["Other"]}},
        "unknown": {"nuke_everything": True},
    }
    for name, override in cases.items():
        path = write(f"{name}.json", json.dumps({**base, **override}))
        rc, _, err = run_main(mod, ["--spec", str(path)])
        assert rc == 2, (name, err)


def test_json_output():
    rc, out = run_json(mod, ["--spec", str(SPEC), "--json"])
    assert rc == 0
    assert out["lint_errors"] == [] and out["manifest"]["warnings"] == []
    assert [d["file"] for d in out["manifest"]["documents"]] == ["scp-01.json", "scp-02.json"]
