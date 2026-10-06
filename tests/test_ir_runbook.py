import re

import pytest
from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("aws-incident-response-runbook", "ir_runbook.py")
FINDINGS = FIXTURES / "incident" / "guardduty-findings.json"
SECTIONS = ["## 0. Scope and roles", "## 1. Containment", "### 1a. Read-only inventory (run first)", "### 1b. Containment actions",
            "## 2. Evidence preservation", "## 3. Eradication", "## 4. Recovery", "## 5. Post-incident checklist",
            "## 6. Timeline template", "## 7. Communications template"]
MUTATING = re.compile(r"\baws [a-z0-9-]+ (attach|cancel|create|deactivate|delete|detach|disassociate|modify|put|revoke|stop|"
                      r"terminate|update|deregister)-")


def runbook(scenario, *extra):
    rc, out = run_json(mod, ["--scenario", scenario, "--as-of", "2026-10-05", "--json", *extra])
    assert rc == 0
    return out["markdown"]


@pytest.mark.parametrize("scenario", mod.SCENARIOS)
def test_every_scenario_has_all_sections_in_order(scenario):
    md = runbook(scenario, "--account", "123456789012", "--region", "ap-southeast-2")
    positions = [md.index(s) for s in SECTIONS]
    assert positions == sorted(positions)
    assert "REQUIRES CONFIRMATION" in md
    assert "aws cloudtrail lookup-events" in md and "FROM cloudtrail_logs" in md
    assert "| Time (UTC) | Who |" in md and "Subject: [Incident" in md


@pytest.mark.parametrize("scenario", mod.SCENARIOS)
def test_inventory_is_read_only_and_mutations_are_marked(scenario):
    md = runbook(scenario)
    inventory = md[md.index("### 1a."):md.index("### 1b.")]
    assert not MUTATING.search(inventory.replace("generate-credential-report", "")), scenario
    assert all(line.strip().endswith("--output json") or "--output json >" in line or "--output text" in line
               for line in inventory.splitlines() if line.strip().startswith("aws ")), scenario
    containment = md[md.index("### 1b."):md.index("## 2.")]
    blocks = re.findall(r"^\d+\. (.*?)(?=^\d+\. |\Z)", containment, re.M | re.S)
    assert len(blocks) >= 2
    assert any(MUTATING.search(b) for b in blocks)
    for block in blocks:
        if MUTATING.search(block):
            assert block.startswith("**REQUIRES CONFIRMATION"), block[:80]


def test_values_fill_the_commands():
    md = runbook("leaked-access-key", "--account", "123456789012", "--region", "us-east-1", "--access-key-id",
                 "AKIAIOSFODNN7EXAMPLE", "--user-name", "ci-deployer", "--start-time", "2026-10-01T00:00:00Z")
    assert "aws iam update-access-key --user-name ci-deployer --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive" in md
    assert "AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE --start-time 2026-10-01T00:00:00Z" in md
    assert "useridentity.accesskeyid = 'AKIAIOSFODNN7EXAMPLE'" in md
    assert "aws:TokenIssueTime" in md


def test_invalid_values_become_placeholders():
    rc, out = run_json(mod, ["--scenario", "public-s3-bucket", "--bucket", "x; aws iam create-user --user-name evil",
                             "--account", "12345", "--json"])
    assert rc == 0
    assert set(out["rejected"]) == {"bucket", "account"}
    assert "create-user" not in out["markdown"]
    assert "--bucket <bucket-name>" in out["markdown"]
    assert "<account-id>" in out["markdown"]


def test_list_and_missing_scenario():
    rc, out, _ = run_main(mod, ["--list"])
    assert rc == 0 and out.split() == mod.SCENARIOS
    rc, _, err = run_main(mod, [])
    assert rc == 2 and "--scenario is required" in err
    rc, _, _ = run_main(mod, ["--scenario", "alien-invasion"])
    assert rc == 2


def test_out_file(tmp_path):
    target = tmp_path / "rb.md"
    rc, out, _ = run_main(mod, ["--scenario", "compromised-ec2", "--instance-id", "i-0123456789abcdef0", "--out", str(target)])
    assert rc == 0 and "wrote" in out
    assert "--instance-ids i-0123456789abcdef0" in target.read_text(encoding="utf-8")


@pytest.mark.parametrize("ftype,resource,scenario", [
    ("CryptoCurrency:EC2/BitcoinTool.B!DNS", {}, "crypto-mining"),
    ("Impact:EC2/BitcoinDomainRequest.Reputation", {}, "crypto-mining"),
    ("Impact:S3/AnomalousBehavior.Delete", {}, "ransomware-ebs-s3"),
    ("Policy:S3/BucketBlockPublicAccessDisabled", {}, "public-s3-bucket"),
    ("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
     {"AccessKeyDetails": {"UserType": "AssumedRole"}}, "compromised-ec2"),
    ("UnauthorizedAccess:IAMUser/TorIPCaller", {"AccessKeyDetails": {"UserType": "IAMUser", "AccessKeyId": "AKIAIOSFODNN7EXAMPLE"}},
     "leaked-access-key"),
    ("Persistence:IAMUser/AnomalousBehavior", {"AccessKeyDetails": {"UserType": "AssumedRole"}}, "suspicious-iam-activity"),
    ("Policy:IAMUser/RootCredentialUsage", {"AccessKeyDetails": {"UserType": "Root"}}, "suspicious-iam-activity"),
    ("Exfiltration:S3/AnomalousBehavior", {}, "suspicious-iam-activity"),
    ("Backdoor:EC2/C&CActivity.B", {}, "compromised-ec2"),
    ("Execution:Runtime/NewBinaryExecuted", {}, "compromised-ec2"),
    ("Execution:Kubernetes/ExecInKubeSystemPod", {}, None),
])
def test_type_mapping(ftype, resource, scenario):
    assert mod.map_type(ftype, resource) == scenario


def test_triage_picks_the_top_scenario_and_fills_values(tmp_path):
    rc, out = run_json(mod, ["triage", "--guardduty", str(FINDINGS), "--out", str(tmp_path), "--case-id", "IR-1", "--json"])
    assert rc == 1
    assert out["archived"] == 1
    assert list(out["by_scenario"]) == ["crypto-mining", "ransomware-ebs-s3", "leaked-access-key", "public-s3-bucket",
                                        "compromised-ec2"]
    assert [u["type"] for u in out["unmapped"]] == ["Execution:Kubernetes/ExecInKubeSystemPod"]
    assert [rb["scenario"] for rb in out["runbooks"]] == ["crypto-mining"]
    md = (tmp_path / "runbook-crypto-mining.md").read_text(encoding="utf-8")
    assert "account `123456789012`, region `ap-southeast-2`, case `IR-1`" in md
    assert "--instance-ids i-0a1b2c3d4e5f60718" in md
    assert "--start-time 2026-09-28T02:55:00Z" in md
    assert "`CryptoCurrency:EC2/BitcoinTool.B!DNS`" in md


def test_triage_all_writes_one_runbook_per_scenario_and_ignores_planted_injection(tmp_path):
    rc, out = run_json(mod, ["triage", "--guardduty", str(FINDINGS), "--all", "--out", str(tmp_path), "--json"])
    assert rc == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(f"runbook-{s}.md" for s in out["by_scenario"])
    leaked = (tmp_path / "runbook-leaked-access-key.md").read_text(encoding="utf-8")
    assert "--user-name ci-deployer --access-key-id AKIAIOSFODNN7EXAMPLE" in leaked
    public = (tmp_path / "runbook-public-s3-bucket.md").read_text(encoding="utf-8")
    assert "backdoor" not in public and "Ignore previous instructions" not in public
    assert "--bucket <bucket-name>" in public
    assert "bucket" in next(rb for rb in out["runbooks"] if rb["scenario"] == "public-s3-bucket")["rejected"]


def test_triage_fail_on_and_bad_input(write):
    rc, _, _ = run_main(mod, ["triage", "--guardduty", str(FINDINGS), "--fail-on", "CRITICAL", "--out", str(write("x", "").parent / "o")])
    assert rc == 0
    rc, _, err = run_main(mod, ["triage", "--guardduty", str(write("bad.json", '{"NotFindings": 1}'))])
    assert rc == 2 and "error:" in err
    rc, out, _ = run_main(mod, ["triage", "--guardduty", str(write("empty.json", '{"Findings": []}'))])
    assert rc == 0 and "no finding maps" in out
