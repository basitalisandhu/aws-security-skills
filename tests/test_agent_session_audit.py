"""Tests for agent_session_audit.py. Every CloudTrail record is synthetic, built here with account id 123456789012."""

from __future__ import annotations

import gzip
import json

import pytest
from conftest import load_script, run_json, run_main

mod = load_script("aws-agent-session-audit", "agent_session_audit.py")
ACCT = "123456789012"
SESSION = "agent@operator"


def rec(source, name, t, *, session=SESSION, role="AgentRole", error=None, read_only=None, region="ap-southeast-2", params=None, resources=None):
    r = {
        "eventVersion": "1.09",
        "eventSource": f"{source}.amazonaws.com",
        "eventName": name,
        "eventTime": f"2026-10-05T09:{t:02d}:00Z",
        "awsRegion": region,
        "sourceIPAddress": "203.0.113.10",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": f"AROAEXAMPLEROLEID:{session}",
            "arn": f"arn:aws:sts::{ACCT}:assumed-role/{role}/{session}",
            "accessKeyId": "ASIA" + "EXAMPLEEXAMPLE12",
        },
    }
    if error:
        r["errorCode"] = error
    if read_only is not None:
        r["readOnly"] = read_only
    if params:
        r["requestParameters"] = params
    if resources:
        r["resources"] = resources
    return r


def session_records():
    return [
        rec("s3", "ListBuckets", 1, read_only=True),
        rec("s3", "GetObject", 2, read_only=True, params={"bucketName": "app-artifacts", "key": "build.zip"}),
        rec("lambda", "UpdateFunctionCode", 3, params={"functionName": "orders-api"}),
        rec("s3", "DeleteBucket", 4, params={"bucketName": "old-logs"}),
        rec("iam", "AttachRolePolicy", 5, params={"roleName": "AgentRole"}),
        rec("cloudtrail", "StopLogging", 6, resources=[{"ARN": f"arn:aws:cloudtrail:ap-southeast-2:{ACCT}:trail/main"}]),
        rec("ec2", "RunInstances", 7, error="Client.UnauthorizedOperation", region="us-east-1"),
        rec("s3", "ListBuckets", 8, session="someone-else", role="AdminRole"),
    ]


@pytest.fixture
def trail(tmp_path):
    p = tmp_path / "trail.json"
    p.write_text(json.dumps({"Records": session_records()}), encoding="utf-8")
    return p


def ids(rep):
    return [f["id"] for f in rep["findings"]]


def test_findings_window_and_services(trail, tmp_path):
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps(["s3:List*", "s3:GetObject", "lambda:UpdateFunctionCode"]), encoding="utf-8")
    rc, rep = run_json(mod, [str(trail), "--session-name", SESSION, "--allow-list", str(allow), "--regions", "ap-southeast-2", "--json"])
    assert rc == 1
    assert ids(rep) == ["AGENT-LOGGING-TAMPER", "AGENT-DESTRUCTIVE", "AGENT-IAM-WRITE", "AGENT-OUTSIDE-ALLOWLIST", "AGENT-OTHER-REGION"]
    assert rep["window"] == {"first": "2026-10-05T09:01:00Z", "last": "2026-10-05T09:07:00Z", "records": 7, "read_from_input": 8}
    assert rep["services"]["s3"] == {"calls": 3, "reads": 2, "writes": 1}
    assert rep["services"]["ec2"]["errors"] == 1
    outside = next(f for f in rep["findings"] if f["id"] == "AGENT-OUTSIDE-ALLOWLIST")
    assert "ec2:RunInstances x1 (failed)" in outside["evidence"]
    assert "s3:DeleteBucket" in outside["actions"]
    assert "s3:bucketName=old-logs" in rep["resources"]


def test_remove_permissions_from_granted_policy(trail, tmp_path):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:ListBuckets", "dynamodb:Scan", "sqs:SendMessage"], "Resource": "*"},
            {"Effect": "Allow", "Action": "lambda:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
        ],
    }
    granted = tmp_path / "policy.json"
    granted.write_text(json.dumps({"PolicyVersion": {"Document": policy}}), encoding="utf-8")
    _, rep = run_json(mod, [str(trail), "--session-name", SESSION, "--granted", str(granted), "--json"])
    rp = rep["remove_permissions"]
    assert rp["remove"] == ["dynamodb:Scan", "sqs:SendMessage"]
    assert rp["replace_wildcards"] == [{"grant": "lambda:*", "used": ["lambda:UpdateFunctionCode"]}]


def test_without_granted_lists_a_draft_allow_list(trail):
    rc, out, _ = run_main(mod, [str(trail), "--session-name", SESSION])
    assert rc == 1
    assert "Remove these permissions" in out and "draft allow list" in out and "`s3:GetObject`" in out
    assert "ASIA" not in out  # access key ids are never printed


def test_lookup_events_shape_and_gzip_folder(tmp_path):
    inner = rec("ec2", "DescribeInstances", 1, read_only=True)
    lookup = {
        "Events": [
            {"EventId": "e1", "EventName": "DescribeInstances", "Username": SESSION, "CloudTrailEvent": json.dumps(inner)},
            {
                "EventId": "e2",
                "EventName": "GetCallerIdentity",
                "EventSource": "sts.amazonaws.com",
                "Username": SESSION,
                "EventTime": "2026-10-05T09:05:00Z",
                "ReadOnly": "true",
            },
        ]
    }
    folder = tmp_path / "exports"
    folder.mkdir()
    (folder / "lookup.json").write_text(json.dumps(lookup), encoding="utf-8")
    (folder / "log.json.gz").write_bytes(gzip.compress(json.dumps({"Records": [rec("s3", "ListBuckets", 3, read_only=True)]}).encode("utf-8")))
    rc, rep = run_json(mod, [str(folder), "--session-name", SESSION, "--json"])
    assert rc == 0 and rep["findings"] == []
    assert rep["actions"] == {"ec2:DescribeInstances": 1, "s3:ListBuckets": 1, "sts:GetCallerIdentity": 1}
    assert rep["services"]["sts"]["reads"] == 1


def test_denied_burst_and_console(tmp_path):
    records = [rec("iam", "ListRoles", n, error="AccessDenied", read_only=True) for n in range(10)]
    records.append(rec("signin", "GetSigninToken", 20))
    p = tmp_path / "lines.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    rc, rep = run_json(mod, [str(p), "--role-name", "AgentRole", "--json"])
    assert rc == 0
    assert ids(rep) == ["AGENT-CONSOLE", "AGENT-DENIED-BURST"]
    assert rep["errors"] == {"AccessDenied": 10}


def test_redact_and_out(trail, tmp_path):
    out = tmp_path / "report.md"
    rc, printed, _ = run_main(mod, [str(trail), "--session-name", SESSION, "--redact", "--out", str(out)])
    text = out.read_text(encoding="utf-8")
    assert rc == 1 and printed == ""
    assert ACCT not in text and "203.0.113.10" not in text
    assert "acct-" in text and "ip-" in text


def test_secret_shapes_are_masked(tmp_path):
    key = "AKIAIOSFODNN7EXAMPLE"
    p = tmp_path / "t.json"
    p.write_text(json.dumps([rec("s3", "GetObject", 1, read_only=True, params={"bucketName": f"b-{key}"})]), encoding="utf-8")
    _, out, _ = run_main(mod, [str(p)])
    assert key not in out and "[masked secret]" in out


@pytest.mark.parametrize(
    "content,argv",
    [
        ("not json at all", []),
        (json.dumps({"something": 1}), []),
        (json.dumps([{"eventName": "x"}]), []),
        (json.dumps({"Records": [rec("s3", "ListBuckets", 1)]}), ["--session-name", "nobody"]),
        (json.dumps({"Records": [rec("s3", "ListBuckets", 1)]}), ["--denied-burst", "0"]),
    ],
)
def test_bad_input_exits_2(tmp_path, content, argv):
    p = tmp_path / "bad.json"
    p.write_text(content, encoding="utf-8")
    rc, _, err = run_main(mod, [str(p), *argv])
    assert rc == 2 and err.startswith("error:")


def test_missing_path_exits_2(tmp_path):
    rc, _, err = run_main(mod, [str(tmp_path / "nope.json")])
    assert rc == 2 and "not found" in err


def test_help_lists_checks():
    rc, out, _ = run_main(mod, ["--help"])
    assert rc == 0
    for word in ("AGENT-LOGGING-TAMPER", "AGENT-OUTSIDE-ALLOWLIST", "Remove these permissions", "Exit codes", "--json", "--redact"):
        assert word in out
