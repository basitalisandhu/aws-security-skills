from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("landing-zone-blast-radius", "blast_radius.py")
BR = FIXTURES / "blast-radius"


def design():
    rc, d = run_json(mod, [str(BR / "workloads.yaml"), "--json"])
    assert rc == 0
    return d


def test_one_account_per_workload_and_environment_plus_foundation():
    names = [a["name"] for a in design()["accounts"]]
    assert names[:5] == ["acme-management", "acme-log-archive", "acme-security-tooling", "acme-shared-services",
                         "acme-network"]
    assert {"acme-payments-prod", "acme-payments-dev", "acme-identity-api-prod", "acme-marketing-site-prod",
            "acme-data-lab-sandbox"} <= set(names)
    assert len(names) == len(set(names)) == 10


def test_ou_placement_follows_environment_and_classification():
    tree = design()["ou_tree"]
    assert tree["Workloads/Prod-Restricted"] == ["acme-payments-prod", "acme-identity-api-prod"]
    assert tree["Workloads/Prod"] == ["acme-marketing-site-prod"]
    assert tree["Workloads/NonProd"] == ["acme-payments-dev"]
    assert tree["Sandbox"] == ["acme-data-lab-sandbox"]
    assert tree["Security"] == ["acme-log-archive", "acme-security-tooling"]
    assert tree["Suspended"] == []


def test_blast_radius_rows():
    rows = {r["account"]: r for r in design()["blast_radius"]}
    assert rows["acme-management"]["impact_if_compromised"] == "critical"
    assert rows["acme-payments-prod"]["impact_if_compromised"] == "critical"
    assert any("acme-identity-api-prod" in r for r in rows["acme-payments-prod"]["can_reach"])
    assert "called by acme-payments-prod" in rows["acme-identity-api-prod"]["why"]
    assert rows["acme-payments-dev"]["impact_if_compromised"] == "low"
    assert rows["acme-marketing-site-prod"]["impact_if_compromised"] == "low"
    assert "acme-data-lab-sandbox" not in rows["acme-shared-services"]["can_reach"]
    assert "acme-payments-prod" in rows["acme-shared-services"]["can_reach"]


def test_scp_attachments_use_guardrail_names():
    scps = design()["scp_attachments"]
    assert "deny_leave_organization" in scps["Root"]
    assert "allowed_regions" in scps["Workloads"]
    assert scps["Workloads/Prod"] == []


def test_no_network_account_without_internet_facing_workloads():
    _, d = run_json(mod, [str(BR / "internal-only.json"), "--json"])
    assert "acme-network" not in [a["name"] for a in d["accounts"]]
    assert d["accounts"][0]["root_email"] == "aws+acme-management@example.com"


def test_markdown_output():
    rc, out, _ = run_main(mod, [str(BR / "workloads.yaml")])
    assert rc == 0
    assert "## Blast radius" in out and "Prod-Restricted/" in out and "| acme-payments-prod |" in out


def test_bad_inputs_exit_2(write):
    for f in ("duplicate.json", "bad-environment.json", "unknown-dependency.json"):
        rc, _, err = run_main(mod, [str(BR / f)])
        assert rc == 2 and err.startswith("error:"), f
    rc, _, _ = run_main(mod, [str(write("x.json", '{"organization": "Acme Corp", "workloads": []}'))])
    assert rc == 2
    long = "a" * 45
    body = '{"organization": "acme", "workloads": [{"name": "' + long + '", "environment": "prod"}]}'
    rc, _, err = run_main(mod, [str(write("y.json", body))])
    assert rc == 2 and "50 characters" in err
