"""Kubernetes rules, asserted in both directions against real manifests.

Manifests arrive as multi-document YAML from a repository, which means a file holds whatever
someone committed: comments, an empty document between two real ones, a list where a mapping
belongs. The reader has to walk past all of it and still see the workload -- and a rule that
silently never sees a workload reports a clean cluster.

So each rule gets a manifest that must trip it and one that must not, and the container walk is
exercised across all three places containers live. `initContainers` is the one worth naming:
an init container runs with the same privileges as any other and is the classic place to hide
one, so a walk that only read `containers` would miss it entirely.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.infrastructure.k8s.scanner import run_scan


def _scan(root: Path, body: str) -> set[str]:
    (root / "manifest.yaml").write_text(body, encoding="utf-8")
    return {f.rule_id for f in run_scan(root).findings}


def _deployment(pod_spec: str, *, namespace: str = "default", name: str = "web") -> str:
    indented = "\n".join(f"      {line}" if line.strip() else line for line in pod_spec.strip().splitlines())
    return (
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        f"  name: {name}\n"
        f"  namespace: {namespace}\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        f"{indented}\n"
    )


_PLAIN_CONTAINER = "containers:\n  - name: app\n    image: app:1.0\n"


# --------------------------------------------------------------------------- #
# What the reader picks up out of a real file
# --------------------------------------------------------------------------- #


def test_documents_that_are_not_manifests_are_walked_past(tmp_path: Path) -> None:
    """An empty document, a list, and a scalar all appear in real repositories."""

    body = "---\n# just a comment\n---\n[]\n---\n42\n---\n" + _deployment("hostNetwork: true\n" + _PLAIN_CONTAINER)

    assert "K8S-PSS-003" in _scan(tmp_path, body)


@pytest.mark.parametrize("key", ["containers", "initContainers", "ephemeralContainers"])
def test_a_privileged_container_is_found_wherever_it_is_declared(key: str, tmp_path: Path) -> None:
    """An init container runs with the same privileges, and is the classic place to hide one."""

    pod_spec = f"{key}:\n  - name: app\n    image: app:1.0\n    securityContext:\n      privileged: true\n"
    assert "K8S-PSS-001" in _scan(tmp_path, _deployment(pod_spec))


def test_a_container_list_holding_something_that_is_not_a_container_is_walked_past(tmp_path: Path) -> None:
    pod_spec = (
        "containers:\n"
        "  - just-a-string\n"
        "  - name: app\n    image: app:1.0\n    securityContext:\n      privileged: true\n"
    )
    assert "K8S-PSS-001" in _scan(tmp_path, _deployment(pod_spec))


# --------------------------------------------------------------------------- #
# K8S-PSS-004 -- hostPath volumes
# --------------------------------------------------------------------------- #


def test_a_host_path_volume_is_reported(tmp_path: Path) -> None:
    """It is the shortest route from a container to the node's filesystem."""

    pod_spec = _PLAIN_CONTAINER + "volumes:\n  - name: docker-socket\n    hostPath:\n      path: /var/run/docker.sock\n"
    assert "K8S-PSS-004" in _scan(tmp_path, _deployment(pod_spec))


@pytest.mark.parametrize(
    ("label", "volume"),
    [
        ("an emptyDir", "  - name: cache\n    emptyDir: {}\n"),
        ("a config map", "  - name: cfg\n    configMap:\n      name: app-config\n"),
        ("a hostPath key that is not a mapping", "  - name: odd\n    hostPath: /var/run\n"),
        ("an entry that is not a mapping", "  - just-a-string\n"),
    ],
)
def test_volumes_that_are_not_host_paths_are_not_reported(label: str, volume: str, tmp_path: Path) -> None:
    pod_spec = _PLAIN_CONTAINER + "volumes:\n" + volume
    assert "K8S-PSS-004" not in _scan(tmp_path, _deployment(pod_spec)), label


# --------------------------------------------------------------------------- #
# K8S-RBAC-002 -- cluster-admin bindings
# --------------------------------------------------------------------------- #


def _binding(role_name: str) -> str:
    return (
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRoleBinding\n"
        "metadata:\n"
        "  name: app-binding\n"
        "roleRef:\n"
        "  apiGroup: rbac.authorization.k8s.io\n"
        "  kind: ClusterRole\n"
        f"  name: {role_name}\n"
    )


def test_a_binding_to_cluster_admin_is_reported(tmp_path: Path) -> None:
    assert "K8S-RBAC-002" in _scan(tmp_path, _binding("cluster-admin"))


@pytest.mark.parametrize("role_name", ["view", "edit", "cluster-admin-readonly"])
def test_a_binding_to_any_other_role_is_not_reported(role_name: str, tmp_path: Path) -> None:
    """Exact match on purpose: `cluster-admin-readonly` is somebody's custom narrow role."""

    assert "K8S-RBAC-002" not in _scan(tmp_path, _binding(role_name))


def test_a_role_ref_that_is_not_a_mapping_is_walked_past(tmp_path: Path) -> None:
    body = (
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRoleBinding\n"
        "metadata:\n"
        "  name: app-binding\n"
        "roleRef: cluster-admin\n"
    )
    assert "K8S-RBAC-002" not in _scan(tmp_path, body)


# --------------------------------------------------------------------------- #
# K8S-NETPOL-001 -- namespaces with workloads and no NetworkPolicy
# --------------------------------------------------------------------------- #


def test_a_namespace_with_workloads_and_no_network_policy_is_reported(tmp_path: Path) -> None:
    assert "K8S-NETPOL-001" in _scan(tmp_path, _deployment(_PLAIN_CONTAINER, namespace="payments"))


def test_a_namespace_with_a_network_policy_is_not_reported(tmp_path: Path) -> None:
    body = (
        _deployment(_PLAIN_CONTAINER, namespace="payments") + "---\n" + "apiVersion: networking.k8s.io/v1\n"
        "kind: NetworkPolicy\n"
        "metadata:\n"
        "  name: default-deny\n"
        "  namespace: payments\n"
        "spec:\n"
        "  podSelector: {}\n"
        "  policyTypes: [Ingress]\n"
    )
    assert "K8S-NETPOL-001" not in _scan(tmp_path, body)


def test_a_policy_in_another_namespace_does_not_cover_this_one(tmp_path: Path) -> None:
    """The counterpart that matters: NetworkPolicy is namespaced, and the rule must be too."""

    body = (
        _deployment(_PLAIN_CONTAINER, namespace="payments") + "---\n" + "apiVersion: networking.k8s.io/v1\n"
        "kind: NetworkPolicy\n"
        "metadata:\n"
        "  name: default-deny\n"
        "  namespace: frontend\n"
        "spec:\n"
        "  podSelector: {}\n"
    )
    (tmp_path / "manifest.yaml").write_text(body, encoding="utf-8")
    findings = [f for f in run_scan(tmp_path).findings if f.rule_id == "K8S-NETPOL-001"]

    assert len(findings) == 1
    assert "payments" in findings[0].message
