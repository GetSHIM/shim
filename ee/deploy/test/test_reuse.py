"""Rejected reuse must never reach cleanup, including workloads outside default."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location(
    "smoke_runner", Path(__file__).with_name("run.py")
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_rejected_cluster_reuse_never_deletes(monkeypatch, tmp_path):
    calls = []
    workload = {
        "kind": "Deployment",
        "metadata": {"namespace": "customer", "name": "database-ui"},
    }

    def command(*args, **kwargs):
        calls.append(args)
        if args[:3] == ("kind", "get", "clusters"):
            return "existing"
        if args[:3] == ("kind", "get", "kubeconfig"):
            return "disposable config"
        if args[0] == "kubectl":
            assert "--all-namespaces" in args
            return json.dumps({"items": [workload]})
        return "test-image"

    monkeypatch.setattr(runner, "command", command)
    monkeypatch.setattr(runner, "certificates", lambda _: None)
    monkeypatch.setattr(runner, "test_license", lambda _: "test-token")
    monkeypatch.setattr(runner.tempfile, "mkdtemp", lambda **_: str(tmp_path))
    monkeypatch.setattr(
        runner.subprocess, "run", lambda *_, **__: SimpleNamespace(returncode=0)
    )
    chart = tmp_path / "chart"
    chart.mkdir()
    (chart / "values.yaml").write_text("{}")
    args = SimpleNamespace(
        chart=chart,
        gateway_image="gateway",
        dashboard_image="dashboard",
        node_image="node",
        cluster="existing",
        reuse_empty_cluster=True,
        keep=False,
    )
    with pytest.raises(SystemExit, match="application workloads"):
        runner.run(args)
    assert not any("delete" in args or "rm" in args for args in calls)
    assert runner.kind_system_workload(
        {
            "kind": "Deployment",
            "metadata": {"namespace": "kube-system", "name": "coredns"},
        },
        "existing",
    )
    assert not runner.kind_system_workload(
        {"kind": "Pod", "metadata": {"namespace": "kube-system", "name": "unrelated"}},
        "existing",
    )
