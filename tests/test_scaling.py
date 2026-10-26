"""Scaling guards: a large but plausible input must not take quadratic time.

blast_radius.py used to find each account's callers by scanning every workload account, so 12,000 workloads took
4.8 s; the callers are indexed once now (0.2 s). The test compares two sizes in one process: from 1,000 to 8,000
workloads linear work grows about eight times, the old scan about sixty times.
"""
from __future__ import annotations

import time

from conftest import load_script

blast = load_script("landing-zone-blast-radius", "blast_radius.py")


def spec(n: int) -> dict:
    names = [f"w{i}" for i in range(n)]
    return {"organization": "acme", "workloads": [
        {"name": w, "environment": "prod", "data_classification": "internal", **({"depends_on": [names[i - 1]]} if i else {})}
        for i, w in enumerate(names)]}


def timed(n: int) -> tuple[float, dict]:
    data = spec(n)
    start = time.perf_counter()
    out = blast.design(data)
    return time.perf_counter() - start, out


def test_blast_radius_scales_linearly_with_workloads():
    small, _ = min((timed(1000) for _ in range(2)), key=lambda r: r[0])
    large, out = min((timed(8000) for _ in range(2)), key=lambda r: r[0])
    rows = {r["account"]: r for r in out["blast_radius"]}
    assert "called by acme-w2-prod" in rows["acme-w1-prod"]["why"]
    assert "called by" not in rows["acme-w7999-prod"]["why"]
    assert large < max(small, 0.005) * 20, f"1,000 workloads {small:.3f}s, 8,000 workloads {large:.3f}s"
