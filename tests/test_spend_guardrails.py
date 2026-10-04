import json

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("aws-spend-guardrails", "spend_guardrails.py")
lint = load_script("scp-guardrails", "scp_lint.py")
BUDGET = FIXTURES / "spend" / "budget.yaml"
COST = FIXTURES / "spend" / "cost-explorer-daily.json"
EC2 = "Amazon Elastic Compute Cloud - Compute"


def spec(**overrides):
    return {**mod.load_spec(BUDGET), **overrides}


def test_generate_writes_budgets_monitor_scp_and_commands(tmp_path):
    rc, out = run_json(mod, ["--budget", str(BUDGET), "--out", str(tmp_path), "--json"])
    assert rc == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([
        "anomaly-monitor.json", "anomaly-subscription.json", "budget-cost.json", "budget-usage-ec2-hours.json", "commands.md",
        "notifications-cost.json", "notifications-usage-ec2-hours.json", "spend-scp-01.json", "spend-scp-manifest.json"])
    assert out["lint_errors"] == []


def test_cost_budget_and_notifications_shape():
    files = mod.generate(spec())["files"]
    budget = files["budget-cost.json"]
    assert budget == {"BudgetName": "sandbox-monthly-cost", "BudgetType": "COST", "TimeUnit": "MONTHLY",
                      "BudgetLimit": {"Amount": "550", "Unit": "USD"},
                      "CostFilters": {"LinkedAccount": ["123456789012", "111122223333"]}}
    notes = files["notifications-cost.json"]
    assert [(n["Notification"]["NotificationType"], n["Notification"]["Threshold"]) for n in notes] == [
        ("ACTUAL", 50), ("ACTUAL", 80), ("ACTUAL", 100), ("FORECASTED", 100)]
    assert all(n["Notification"]["ThresholdType"] == "PERCENTAGE" for n in notes)
    assert notes[0]["Subscribers"] == [{"SubscriptionType": "EMAIL", "Address": "cloud-team@example.com"}]
    usage = files["budget-usage-ec2-hours.json"]
    assert usage["BudgetType"] == "USAGE" and usage["CostFilters"] == {"UsageTypeGroup": ["EC2: Running Hours"]}
    assert "aws budgets create-budget --account-id 123456789012 --budget file://budget-cost.json" in files["commands.md"]


def test_anomaly_monitor_and_subscription():
    files = mod.generate(spec())["files"]
    assert files["anomaly-monitor.json"] == {"MonitorName": "sandbox-services", "MonitorType": "DIMENSIONAL",
                                             "MonitorDimension": "SERVICE"}
    sub = files["anomaly-subscription.json"]
    assert sub["Frequency"] == "DAILY"
    keys = [e["Dimensions"]["Key"] for e in sub["ThresholdExpression"]["Or"]]
    assert keys == ["ANOMALY_TOTAL_IMPACT_ABSOLUTE", "ANOMALY_TOTAL_IMPACT_PERCENTAGE"]
    single = mod.generate(spec(anomaly={"monitor": "linked-accounts", "threshold_absolute": 50}))["files"]
    assert single["anomaly-monitor.json"]["MonitorSpecification"]["Dimensions"]["Key"] == "LINKED_ACCOUNT"
    assert single["anomaly-subscription.json"]["ThresholdExpression"]["Dimensions"]["Values"] == ["50"]


def test_spend_scp_contents_lint_clean_and_under_limit():
    files = mod.generate(spec())["files"]
    doc = files["spend-scp-01.json"]
    assert len(lint.compact(doc)) <= 5120
    assert lint.lint_policy(doc) == []
    st = {s["Sid"]: s for s in doc["Statement"]}
    assert set(st) == {"DenyExpensiveInstanceTypes", "DenyHighIopsVolumes", "DenyProvisionedIopsVolumeTypes",
                       "DenySageMakerGpuInstanceTypes", "DenyBedrockCustomizationAndThroughput", "DenyExpensiveServices",
                       "DenyPurchaseCommitments", "ProtectBudgetsAndAnomalyMonitors"}
    assert "g*" in st["DenyExpensiveInstanceTypes"]["Condition"]["StringLike"]["ec2:InstanceType"]
    assert st["DenyHighIopsVolumes"]["Condition"]["NumericGreaterThan"]["ec2:VolumeIops"] == "3000"
    assert st["DenyExpensiveServices"]["Action"] == ["redshift:*", "redshift-serverless:*"]
    assert "budgets:DeleteBudgetAction" in st["ProtectBudgetsAndAnomalyMonitors"]["Action"]
    assert st["ProtectBudgetsAndAnomalyMonitors"]["Condition"]["ArnNotLike"]["aws:PrincipalArn"] == [
        "arn:aws:iam::*:role/OrganizationAccountAccessRole"]


def test_allow_list_instance_types_and_missing_exemption_warning():
    result = mod.generate({"sandbox_scp": {"allowed_instance_types": ["t3.*", "t4g.*"]}})
    doc = result["files"]["spend-scp-01.json"]
    assert doc["Statement"][0]["Condition"]["StringNotLike"]["ec2:InstanceType"] == ["t3.*", "t4g.*"]
    assert any("protected_roles" in w for w in result["warnings"])


def test_bad_budget_specs_exit_2(write):
    base = mod.load_spec(BUDGET)
    cases = {
        "too-many-notifications": {"thresholds": [10, 20, 30, 40, 50], "forecast_thresholds": [100]},
        "immediate-email-only": {"anomaly": {"monitor": "services", "threshold_absolute": 10, "frequency": "IMMEDIATE"}},
        "both-instance-lists": {"sandbox_scp": {"deny_instance_types": ["p*"], "allowed_instance_types": ["t3.*"]}},
        "deny-iam-service": {"sandbox_scp": {"deny_services": ["iam"]}},
        "no-recipients": {"notify_emails": []},
        "bad-email": {"notify_emails": ["not-an-address"]},
        "unknown": {"spend_everything": True},
    }
    for name, override in cases.items():
        path = write(f"{name}.json", json.dumps({**base, **override}))
        rc, _, err = run_main(mod, ["--budget", str(path)])
        assert rc == 2, (name, err)


def test_review_flags_the_planted_spike_and_new_service():
    rc, out = run_json(mod, ["review", "--cost-explorer", str(COST), "--json"])
    assert rc == 1
    assert (out["first_day"], out["last_day"], out["days"], out["unit"]) == ("2026-09-10", "2026-09-30", 21, "USD")
    assert out["estimated_days"] == 2
    series = {(f["series"], f["date"]): f for f in out["findings"] if f["id"] == "SPEND-ANOMALY"}
    spike = series[(f"{EC2} / 123456789012", "2026-09-27")]
    assert spike["severity"] == "high" and spike["amount"] == 86.4 and spike["median_prior"] == 10.08
    new = series[("Amazon SageMaker / 111122223333", "2026-09-29")]
    assert new["median_prior"] == 0 and new["ratio"] is None
    # No steady series is flagged.
    assert not [k for k in series if k[0].startswith(("Amazon Simple Storage", "AWS Lambda", f"{EC2} / 111122223333"))]


def test_review_totals_by_service_account_and_month():
    _, out = run_json(mod, ["review", "--cost-explorer", str(COST), "--json"])
    assert out["by_service"][0] == {"service": EC2, "total": 372.57}
    assert {r["account"]: r["total"] for r in out["by_account"]} == {"123456789012": 320.27, "111122223333": 168.01}
    assert out["by_month"] == [{"month": "2026-09", "total": 488.28, "days": 21, "last_day": "2026-09-30"}]


def test_review_against_budget_threshold_and_over_budget(write):
    _, out = run_json(mod, ["review", "--cost-explorer", str(COST), "--budget", str(BUDGET), "--json"])
    month = out["by_month"][0]
    assert month["percent_of_limit"] == 88.8 and "forecast" not in month
    assert any(f["id"] == "SPEND-THRESHOLD" and "80%" in f["message"] for f in out["findings"])
    over = write("over.json", json.dumps({**mod.load_spec(BUDGET), "monthly_limit": 450}))
    _, out = run_json(mod, ["review", "--cost-explorer", str(COST), "--budget", str(over), "--json"])
    assert any(f["id"] == "SPEND-OVER-BUDGET" and f["severity"] == "high" for f in out["findings"])


def test_review_account_filter_and_factor(write):
    only_a = write("a.json", json.dumps({**mod.load_spec(BUDGET), "accounts": ["123456789012"]}))
    _, out = run_json(mod, ["review", "--cost-explorer", str(COST), "--budget", str(only_a), "--json"])
    assert [r["account"] for r in out["by_account"]] == ["123456789012"]
    assert not any("SageMaker" in f["series"] for f in out["findings"])
    rc, out = run_json(mod, ["review", "--cost-explorer", str(COST), "--factor", "5", "--min-amount", "50", "--json"])
    assert [f["series"] for f in out["findings"]] == [f"{EC2} / 123456789012", "total"]


def test_review_forecast_for_a_partial_month(write):
    data = json.loads(COST.read_text())
    data["ResultsByTime"] = data["ResultsByTime"][:12]
    part = write("part.json", json.dumps(data))
    budget = write("b.json", json.dumps({**mod.load_spec(BUDGET), "monthly_limit": 400}))
    _, out = run_json(mod, ["review", "--cost-explorer", str(part), "--budget", str(budget), "--json"])
    assert out["by_month"][0]["forecast"] > 400
    assert any(f["id"] == "SPEND-FORECAST" for f in out["findings"])


def test_review_bad_input_and_pagination_warning(write):
    rc, _, err = run_main(mod, ["review", "--cost-explorer", str(write("x.json", '{"Nope": []}'))])
    assert rc == 2 and "ResultsByTime" in err
    monthly = {"ResultsByTime": [{"TimePeriod": {"Start": "2026-09", "End": "2026-10"}, "Groups": []}]}
    rc, _, _ = run_main(mod, ["review", "--cost-explorer", str(write("m.json", json.dumps(monthly)))])
    assert rc == 2
    data = json.loads(COST.read_text())
    data["NextPageToken"] = "example-token"
    rc, out, _ = run_main(mod, ["review", "--cost-explorer", str(write("p.json", json.dumps(data))), "--fail-on", "high"])
    assert rc == 1 and "NextPageToken" in out
