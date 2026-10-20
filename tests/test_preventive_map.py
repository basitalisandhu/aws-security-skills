import json
import re

import pytest
from conftest import FIXTURES, ROOT, load_script, run_json, run_main

mod = load_script("preventive-control-mapper", "preventive_map.py")
FD = FIXTURES / "preventive-map"
ASFF = str(FD / "securityhub-findings.json")
OCSF = str(FD / "prowler-ocsf.json")
CSV_ALL = str(FD / "controls.csv")
CSV_MAPPED = str(FD / "mapped-only.csv")
BUNDLED = ROOT / "plugins" / "aws-security" / "skills" / "preventive-control-mapper" / "references" / "preventive-map.json"


def report(*files, extra=()):
    args = []
    for f in files:
        args += ["--findings", f]
    return run_json(mod, [*args, "--json", *extra])


def ids(entries):
    return [e["control"] for e in entries]


def test_asff_keeps_only_failed_active_unsuppressed_findings():
    rc, rep = report(ASFF)
    assert rc == 1  # ECR.1 is not in the table
    kept = {c["control"]: c["findings"] for c in rep["controls"] + rep["detective_only"]}
    assert kept == {"S3.8": 3, "S3.1": 1, "EC2.8": 2, "EC2.19": 1, "IAM.4": 1, "IAM.6": 1, "KMS.4": 1, "EC2.7": 1}
    # PASSED (CloudTrail.1), SUPPRESSED (S3.2), RESOLVED (RDS.3) and the ARCHIVED EC2.7 record are all absent
    assert "CloudTrail.1" not in kept and "S3.2" not in kept and "RDS.3" not in kept
    assert rep["skipped"] == {"not_failed": 1, "suppressed_or_resolved": 2, "not_active": 1, "no_control_id": 1}


def test_asff_reads_control_id_from_product_fields_and_lists_accounts_regions_and_samples():
    _, rep = report(ASFF)
    by = {c["control"]: c for c in rep["controls"]}
    assert by["KMS.4"]["findings"] == 1  # only ProductFields.ControlId was set on that finding
    s3 = by["S3.8"]
    assert s3["accounts"] == ["111122223333", "444455556666"]
    assert s3["regions"] == ["ap-southeast-2", "us-east-1"]
    assert s3["sample_resources"][0] == "arn:aws:s3:::example-public-site"
    assert len(s3["sample_resources"]) <= 5


def test_samples_are_capped_at_five(write):
    rows = "control_id,resource\n" + "".join(f"S3.8,arn:aws:s3:::bucket-{i}\n" for i in range(9))
    rc, rep = report(str(write("many.csv", rows)))
    assert rc == 0
    assert rep["controls"][0]["findings"] == 9
    assert len(rep["controls"][0]["sample_resources"]) == 5


def test_prowler_ocsf_uses_fail_status_event_code_and_skips_muted_findings():
    rc, rep = report(OCSF)
    assert rc == 1
    assert sorted(ids(rep["controls"])) == ["EC2.7", "KMS.4", "RDS.2", "S3.1"]  # bundled Prowler check ids resolved to Security Hub controls
    assert [u["control"] for u in rep["unmapped"]] == ["ec2_elastic_ip_unassigned"]  # unknown check id kept, not dropped
    assert rep["skipped"]["suppressed_or_resolved"] == 1 and rep["skipped"]["not_failed"] == 1


def test_prowler_check_id_falls_back_to_finding_uid(write):
    item = {"status_code": "FAIL", "metadata": {}, "finding_info": {"uid": "prowler-aws-ec2_ebs_default_encryption-111122223333-us-east-1-ebs"},
            "cloud": {"account": {"uid": "111122223333"}, "region": "us-east-1"}, "resources": [{"uid": "ebs", "region": "us-east-1"}]}
    rc, rep = report(str(write("o.json", json.dumps([item]))))
    assert rc == 0 and ids(rep["controls"]) == ["EC2.7"]


def test_csv_needs_a_control_id_column_and_honours_a_status_column():
    rc, rep = report(CSV_ALL)
    assert rc == 0
    assert sorted(ids(rep["controls"])) == ["EC2.13", "EC2.9", "IAM.9", "Lambda.1", "S3.1"]
    rc, rep = report(str(FD / "status-column.csv"))
    assert rc == 0 and sorted(ids(rep["controls"])) == ["KMS.4", "S3.1"]  # the PASSED row is ignored
    rc, _, err = run_main(mod, ["--findings", str(FD / "no-control-column.csv")])
    assert rc == 2 and "control_id" in err


def test_unmapped_control_exits_1_and_is_listed_in_both_formats():
    rc, out, _ = run_main(mod, ["--findings", ASFF])
    assert rc == 1
    section = out.split("## Unmapped controls")[1]
    assert "ECR.1" in section and "arn:aws:ecr" in section
    _, rep = report(ASFF)
    assert ids(rep["unmapped"]) == ["ECR.1"]
    assert rep["summary"] == {"failing_controls": 9, "with_preventive_option": 7, "detective_only": 1, "unmapped": 1}


def test_all_mapped_controls_exit_0():
    rc, out, _ = run_main(mod, ["--findings", CSV_MAPPED])
    assert rc == 0
    assert "None." in out.split("## Unmapped controls")[1]


def test_control_with_no_preventive_option_is_reported_but_does_not_fail(write):
    rc, out, _ = run_main(mod, ["--findings", str(write("a.csv", "control_id\nIAM.6\nRDS.1\n"))])
    assert rc == 0
    assert "## Controls with no preventive option" in out and "IAM.6" in out and "RDS.1" in out
    assert "Continuous detection: managed rule `rds-snapshots-public-prohibited`" in out


def test_no_failing_findings_exits_0():
    rc, out, _ = run_main(mod, ["--findings", str(FD / "empty-findings.json")])
    assert rc == 0 and "No failing findings" in out
    rc, rep = report(str(FD / "empty-findings.json"))
    assert rc == 0 and rep["scp_draft"]["document"] is None and rep["summary"]["failing_controls"] == 0


def test_scp_draft_is_valid_json_merges_statements_and_counts_characters():
    _, rep = report(ASFF)
    draft = rep["scp_draft"]
    doc = draft["document"]
    assert doc["Version"] == "2012-10-17"
    sids = [s["Sid"] for s in doc["Statement"]]
    assert sids == draft["statements"] and len(sids) == len(set(sids))
    assert {"ProtectAccountPublicAccessBlock", "RequireImdsv2OnLaunch", "DenyRootUser", "DenyDisableEbsEncryptionByDefault"} <= set(sids)
    assert draft["chars"] == len(json.dumps(doc, separators=(",", ":"), ensure_ascii=False))
    assert draft["limit"] == 10240 and not draft["over_limit"]
    # the blunt security group statement is an option, not part of the draft
    assert "DenySecurityGroupIngressChanges" not in sids
    rc, out, _ = run_main(mod, ["--findings", ASFF])
    assert "## SCP draft" in out and f"Size: {draft['chars']} characters" in out and "scp-guardrails" in out


def test_break_glass_role_is_added_to_exemptable_statements_only():
    _, rep = report(ASFF, extra=["--break-glass-role", "BreakGlass", "--break-glass-role", "PlatformAdmin"])
    by = {s["Sid"]: s for s in rep["scp_draft"]["document"]["Statement"]}
    cond = by["ProtectAccountPublicAccessBlock"]["Condition"]["ArnNotLike"]["aws:PrincipalArn"]
    assert cond == ["arn:aws:iam::*:role/BreakGlass", "arn:aws:iam::*:role/PlatformAdmin"]
    assert by["DenyRootUser"]["Condition"] == {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}}
    assert rep["scp_draft"]["no_exemption_for"] == []
    _, rep = report(ASFF)
    assert "ProtectAccountPublicAccessBlock" in rep["scp_draft"]["no_exemption_for"]
    rc, _, err = run_main(mod, ["--findings", ASFF, "--break-glass-role", "bad role!"])
    assert rc == 2 and "role name" in err


def test_size_limit_breach_exits_1_with_a_custom_mapping():
    rc, rep = report(CSV_MAPPED, extra=["--mapping", str(FD / "mapping-huge-scp.json")])
    assert rc == 1
    assert rep["scp_draft"]["over_limit"] and rep["scp_draft"]["chars"] > 10240
    assert rep["unmapped"] == []
    rc, out, _ = run_main(mod, ["--findings", CSV_MAPPED, "--mapping", str(FD / "mapping-huge-scp.json")])
    assert rc == 1 and "OVER the limit" in out
    rc, rep = report(CSV_MAPPED, extra=["--scp-limit", "100"])
    assert rc == 1 and rep["scp_draft"]["limit"] == 100


def test_custom_mapping_overrides_and_extends_the_bundled_table():
    rc, rep = report(ASFF, extra=["--mapping", str(FD / "mapping-override.json")])
    assert rc == 0  # ECR.1 is now mapped
    by = {c["control"]: c for c in rep["controls"]}
    assert by["ECR.1"]["options"][0]["name"] == "Scan on push in IaC"
    assert by["S3.1"]["title"].startswith("Custom S3.1 entry")
    assert [o["kind"] for o in by["S3.1"]["options"]] == ["iac-check"]  # replaced, not merged
    assert [o["kind"] for o in by["S3.8"]["options"]][0] == "iac-check"  # untouched bundled entry


@pytest.mark.parametrize("args", [
    ["--findings", str(FD / "malformed.txt")],
    ["--findings", str(FD / "wrong-shape.json")],
    ["--findings", str(FD / "wrong-shape-list.json")],
    ["--findings", str(FD / "empty.txt")],
    ["--findings", str(FD / "does-not-exist.json")],
    ["--findings", ASFF, "--format", "xml"],
    ["--findings", ASFF, "--mapping", str(FD / "mapping-bad.json")],
    ["--findings", ASFF, "--mapping", str(FD / "malformed.txt")],
    ["--findings", ASFF, "--scp-limit", "0"],
    ["--findings", ASFF, "--out", ASFF],
])
def test_bad_input_exits_2_and_names_the_problem(args):
    rc, out, err = run_main(mod, args)
    assert rc == 2 and out == ""
    assert err.startswith("error: ")


def test_error_messages_name_the_file():
    _, _, err = run_main(mod, ["--findings", str(FD / "malformed.txt")])
    assert "malformed.txt" in err and "invalid JSON" in err
    _, _, err = run_main(mod, ["--findings", str(FD / "wrong-shape.json")])
    assert "wrong-shape.json" in err


def test_out_writes_a_file(tmp_path):
    target = tmp_path / "map.md"
    rc, out, _ = run_main(mod, ["--findings", CSV_MAPPED, "--out", str(target)])
    assert rc == 0 and out.strip() == f"wrote {target}"
    assert target.read_text(encoding="utf-8").startswith("# Preventive control map")


def test_untrusted_text_is_cleaned_before_printing(write):
    evil = "arn:aws:s3:::x`\n## Injected | heading"
    rows = f'control_id,resource\nS3.8,"{evil}"\nZZZ.1,"{evil}"\n'
    rc, out, _ = run_main(mod, ["--findings", str(write("evil.csv", rows))])
    assert rc == 1
    assert "\n## Injected" not in out and "x'" in out
    assert "\\|" in out.split("## Unmapped controls")[1]


def test_help_documents_the_exit_codes():
    rc, out, _ = run_main(mod, ["--help"])
    assert rc == 0
    assert "Exit codes" in out and re.search(r"^\s+0\s+every failing control", out, re.M)
    assert re.search(r"^\s+1\s+at least one failing control is not in the table", out, re.M)
    assert re.search(r"^\s+2\s+bad input", out, re.M)


# ---- the bundled table


def load_bundled():
    return json.loads(BUNDLED.read_text(encoding="utf-8"))


def test_bundled_table_passes_its_own_schema_check():
    data = load_bundled()
    assert mod.validate_mapping(data) == []
    assert len(data["controls"]) >= 20


def test_every_bundled_option_has_a_doc_url_a_valid_kind_and_parseable_snippets():
    for cid, entry in load_bundled()["controls"].items():
        assert entry["doc"].startswith("https://docs.aws.amazon.com/securityhub/"), cid
        for opt in entry["options"]:
            assert opt["kind"] in mod.KINDS and opt["doc"].startswith("https://"), cid
            assert opt["caveats"] is not None
            if opt["kind"] == "scp":
                for st in opt["snippet"]:
                    assert st["Effect"] == "Deny" and st["Sid"] and st["Resource"] and (st.get("Action") or st.get("NotAction")), cid
                    json.loads(json.dumps(st))
            if opt["kind"] == "declarative-policy":
                assert "ec2_attributes" in opt["snippet"], cid
            if opt["kind"] == "config-rule":
                rule = opt["config_rule"]
                assert re.fullmatch(r"[A-Z0-9_]+", rule["identifier"]), cid
                assert opt["snippet"]["Source"] == {"Owner": "AWS", "SourceIdentifier": rule["identifier"]}
            if opt["kind"] == "account-setting":
                assert opt["snippet"].startswith("aws "), cid
        # strongest first: detection never comes before a preventive option
        kinds = [o["kind"] for o in entry["options"]]
        if "config-rule" in kinds:
            assert kinds.index("config-rule") == len(kinds) - 1, cid
        assert kinds.count("scp") <= 1, cid


def test_same_sid_means_same_statement_across_the_table():
    seen = {}
    for cid, entry in load_bundled()["controls"].items():
        for opt in entry["options"]:
            if opt["kind"] == "scp":
                for st in opt["snippet"]:
                    assert seen.setdefault(st["Sid"], st) == st, (cid, st["Sid"])


def test_prowler_check_ids_are_unique_across_the_table():
    owners = {}
    for cid, entry in load_bundled()["controls"].items():
        for check in entry["prowler"]:
            assert owners.setdefault(check, cid) == cid, check


def test_validate_mapping_rejects_bad_tables():
    assert mod.validate_mapping([]) != []
    bad_kind = {"controls": {"X.1": {"title": "t", "options": [{"kind": "magic"}]}}}
    assert any("kind must be one of" in e for e in mod.validate_mapping(bad_kind))
    allow = json.loads(BUNDLED.read_text(encoding="utf-8"))
    allow["controls"]["S3.1"]["options"][1]["snippet"][0]["Effect"] = "Allow"
    assert any("Effect Deny" in e for e in mod.validate_mapping(allow))
    nodoc = json.loads(BUNDLED.read_text(encoding="utf-8"))
    nodoc["controls"]["S3.1"]["options"][0]["doc"] = "http://example.com"
    assert any("https URL" in e for e in mod.validate_mapping(nodoc))
    empty = {"controls": {"X.1": {"title": "t", "options": []}}}
    assert any("needs a note" in e for e in mod.validate_mapping(empty))


def test_the_script_is_standard_library_only_and_never_runs_commands():
    src = (ROOT / "plugins" / "aws-security" / "skills" / "preventive-control-mapper" / "scripts" / "preventive_map.py").read_text(encoding="utf-8")
    imports = set(re.findall(r"^(?:import|from) (\w+)", src, re.M))
    assert imports <= {"argparse", "csv", "io", "json", "re", "sys", "pathlib", "__future__"}
    assert "subprocess" not in src and "socket" not in src


def test_scp_out_writes_compact_json_that_the_scp_linter_accepts(tmp_path):
    target = tmp_path / "draft.json"
    rc, _, _ = run_main(mod, ["--findings", CSV_MAPPED, "--scp-out", str(target)])
    assert rc == 0
    text = target.read_text(encoding="utf-8")
    doc = json.loads(text)
    assert text.strip() == json.dumps(doc, separators=(",", ":"))
    lint = load_script("scp-guardrails", "scp_lint.py")
    rc, out, _ = run_main(lint, [str(target)])
    assert rc == 0, out
    rc, _, err = run_main(mod, ["--findings", str(FD / "empty-findings.json"), "--scp-out", str(tmp_path / "none.json")])
    assert rc == 0 and "wrote nothing" in err and not (tmp_path / "none.json").exists()
    rc, _, err = run_main(mod, ["--findings", CSV_MAPPED, "--scp-out", CSV_MAPPED])
    assert rc == 2 and "--scp-out would overwrite" in err
