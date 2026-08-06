"""Heuristics for suggesting bundled profiles from repository layout."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

GITHUB_EVIDENCE_FILENAMES: frozenset[str] = frozenset(
    {
        "branch-protection.json",
        "github-rulesets.json",
        "github-environment-protection.json",
        "github-secret-scanning.json",
        "github-provenance-artifact.json",
        "org-mfa-posture.json",
        "runner-groups.json",
    }
)
GITLAB_EVIDENCE_FILENAMES: frozenset[str] = frozenset(
    {
        # GitLab-distinctive evidence. branch-protection.json and org-mfa-posture.json
        # are platform-agnostic (also emitted by the GitHub/GitLab collectors) and stay
        # classified under the GitHub bucket to preserve historical partition behavior.
        "gitlab-mr-rules.json",
    }
)
AZURE_EVIDENCE_FILENAMES: frozenset[str] = frozenset(
    {
        "azure-branch-policies.json",
        "azure-pipeline-governance.json",
        "azure-sbom-artifact.json",
        "azure-provenance-artifact.json",
    }
)
AWS_EVIDENCE_FILENAMES: frozenset[str] = frozenset(
    {
        "aws-codebuild-project.json",
        "aws-codepipeline.json",
        "aws-sbom-artifact.json",
        "aws-provenance-artifact.json",
    }
)
# Platform-agnostic evidence filenames bundled with the kit. These are consumed
# by controls that apply across GitHub/Azure/AWS (governance, IaC, K8s, etc.).
# Keep this set in sync with the schemas in src/oss_policy_kit/data/schema/.
GENERIC_EVIDENCE_FILENAMES: frozenset[str] = frozenset(
    {
        "audit-log-streaming.json",
        "disclosure-policy.json",
        "k8s-baseline.json",
        "release-archival-policy.json",
        "iac-terraform.json",
        "iac-bicep.json",
        "iac-cfn.json",
        "iac-pulumi.json",
        # Written by `scan-sast`, read back by SAST-SEMGREP-064 and the finding
        # normalization layer. Omitting it told adopters to delete evidence the
        # kit had just produced, flipping that control from PASS to UNKNOWN.
        "sast-semgrep.json",
    }
)


# M-003 (v6.0.0, ADR-008): schema_version becomes an absolute URL.
# The legacy shorthand is accepted by internal consumers for one minor
# (v6.0.x) so adopters that string-match the value have time to migrate.
PROFILE_RECOMMENDATION_V2_SCHEMA_URL = "https://schemas.lucashgrifoni.io/oss-policy-kit/recommend-profile/v2.json"
PROFILE_RECOMMENDATION_V2_LEGACY_SHORTHAND = "oss-policy-kit/profile-recommendation/v2"


@dataclass(slots=True)
class ProfileRecommendation:
    """Structured profile hints for CLI and automation."""

    schema_version: str = PROFILE_RECOMMENDATION_V2_SCHEMA_URL
    signals_detected: list[dict[str, str]] = field(default_factory=list)
    suggestions: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_json_dict(self) -> dict[str, Any]:
        """Serialize for JSON stdout (includes schema_version and nested structures)."""

        return asdict(self)


def _workflow_yaml_paths(repo_root: Path) -> list[Path]:
    root = repo_root.resolve()
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    paths: list[Path] = []
    for p in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
        try:
            resolved = p.resolve()
        except OSError:
            continue
        if not resolved.is_file():
            continue
        if not resolved.is_relative_to(root):
            # Guard against symlink escapes that would leak signals from outside --target.
            continue
        paths.append(resolved)
    return paths


def _gitlab_ci_paths(repo_root: Path) -> list[Path]:
    """Return GitLab CI definition paths (root ``.gitlab-ci.yml`` or under ``.gitlab/``)."""

    seen: set[Path] = set()
    paths: list[Path] = []
    for parent in (repo_root, repo_root / ".gitlab"):
        for name in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
            p = parent / name
            if p.is_file() and p not in seen:
                seen.add(p)
                paths.append(p)
    return paths


def _azure_pipeline_paths(repo_root: Path) -> list[Path]:
    patterns = [
        "azure-pipelines*.yml",
        "azure-pipelines*.yaml",
        "pipelines/azure/*.yml",
        "pipelines/azure/*.yaml",
        ".azure-pipelines/*.yml",
        ".azure-pipelines/*.yaml",
    ]
    seen: set[Path] = set()
    paths: list[Path] = []
    for pattern in patterns:
        for p in sorted(repo_root.glob(pattern)):
            if p not in seen:
                seen.add(p)
                paths.append(p)
    return paths


def _evidence_json_paths(repo_root: Path) -> list[Path]:
    ev = repo_root / ".oss-policy-kit" / "evidence"
    if not ev.is_dir():
        return []
    return sorted(p for p in ev.glob("*.json") if p.is_file())


def _partition_evidence_json(
    ev_json: list[Path],
) -> tuple[list[Path], list[Path], list[Path], list[Path], list[Path]]:
    """Partition discovered evidence JSON paths into (github, gitlab, azure, aws, unrecognized).

    Generic / cross-platform bundled filenames (disclosure-policy.json,
    audit-log-streaming.json, release-archival-policy.json, iac-*.json,
    k8s-baseline.json) are RECOGNIZED as bundled and therefore do NOT land
    in the unrecognized bucket — they are consumed by controls that aren't
    tied to a specific CI platform.
    """
    github: list[Path] = []
    gitlab: list[Path] = []
    azure: list[Path] = []
    aws: list[Path] = []
    other: list[Path] = []
    for p in ev_json:
        name = p.name
        if name in GITHUB_EVIDENCE_FILENAMES:
            github.append(p)
        elif name in GITLAB_EVIDENCE_FILENAMES:
            gitlab.append(p)
        elif name in AZURE_EVIDENCE_FILENAMES:
            azure.append(p)
        elif name in AWS_EVIDENCE_FILENAMES:
            aws.append(p)
        elif name in GENERIC_EVIDENCE_FILENAMES:
            # Bundled & cross-platform; skip the unrecognized signal entirely.
            continue
        else:
            other.append(p)
    return github, gitlab, azure, aws, other


def _append_signal(signals: list[dict[str, str]], sig_id: str, detail: str) -> None:
    signals.append({"id": sig_id, "detail": detail})


def _detect_container_stack(repo_root: Path, found: list[dict[str, str]]) -> bool:
    """Append a container signal when a Dockerfile/compose is present; return prefer-L2 flag."""

    if (
        (repo_root / "Dockerfile").is_file()
        or (repo_root / "docker-compose.yml").is_file()
        or (repo_root / "docker-compose.yaml").is_file()
    ):
        _append_signal(
            found,
            "container_docker",
            "Container workload detected via Dockerfile or docker-compose.",
        )
        return True
    return False


# How strongly a marker file says "this repository *is* this stack". A manifest that
# declares the project outranks one that is as often a sidecar: a bare package.json
# belongs to a docs site or a tooling folder at least as often as to the project
# itself, which is how a Python repository used to be reported as "your Node.js
# project". A committed lockfile is what proves the tree is really installed as Node.
_STACK_WEIGHT_DECLARES_PROJECT = 3
_STACK_WEIGHT_MAY_BE_SIDECAR = 2

# Stable display order for stacks tied on weight, so the rationale is deterministic.
_STACK_LABEL_ORDER: tuple[str, ...] = (
    "Python",
    "Node.js",
    "Go",
    "Java/Maven",
    "Java/Kotlin (Gradle)",
    "Rust",
    "C#/.NET",
)

_NODE_LOCKFILE_NOTE = "Add package-lock.json or yarn.lock to enable reproducible builds."


def _detect_node_stack(
    repo_root: Path, found: list[dict[str, str]], weights: dict[str, int] | None = None
) -> str | None:
    """Append Node.js signals; return the stack label or None. Records its weight in *weights*."""

    if not (repo_root / "package.json").is_file():
        return None
    _append_signal(found, "node_js", "Node.js project detected via package.json")
    has_lockfile = any((repo_root / name).is_file() for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"))
    if has_lockfile:
        _append_signal(found, "node_lockfile", "Node lockfile present (reproducible installs).")
    if weights is not None:
        weights["Node.js"] = _STACK_WEIGHT_DECLARES_PROJECT if has_lockfile else _STACK_WEIGHT_MAY_BE_SIDECAR
    return "Node.js"


def _detect_python_stack(
    repo_root: Path,
    found: list[dict[str, str]],
    notes: list[str],
    weights: dict[str, int] | None = None,
) -> str | None:
    """Append Python signals/notes; return the stack label or None. Records its weight in *weights*."""

    if (repo_root / "pyproject.toml").is_file():
        _append_signal(found, "python_pyproject", "Python project detected via pyproject.toml")
        if weights is not None:
            weights["Python"] = _STACK_WEIGHT_DECLARES_PROJECT
        try:
            body = (repo_root / "pyproject.toml").read_text(encoding="utf-8", errors="replace")
        except OSError:
            body = ""
        bl = body.lower()
        if "[tool.ruff]" in body or "[tool.ruff." in body or "ruff>" in bl:
            notes.append("Ruff is configured under pyproject.toml - align CI quality gates with the same rules.")
        if "[tool.mypy]" in body or "python -m mypy" in bl:
            notes.append("Mypy is referenced - keep static type checks in CI for stronger supply-chain posture.")
        return "Python"
    if (repo_root / "requirements.txt").is_file():
        _append_signal(found, "python_requirements", "Python project detected via requirements.txt")
        if weights is not None:
            # Pinned dependencies alone; the file is often vendored beside another stack.
            weights["Python"] = _STACK_WEIGHT_MAY_BE_SIDECAR
        return "Python"
    if (repo_root / "setup.py").is_file() or (repo_root / "setup.cfg").is_file():
        _append_signal(found, "python_setup", "Python project detected via setup.py/setup.cfg")
        if weights is not None:
            weights["Python"] = _STACK_WEIGHT_DECLARES_PROJECT
        return "Python"
    return None


# (marker filenames, primary label, signal id, signal detail) for single-file stacks.
_SIMPLE_STACK_MARKERS: tuple[tuple[tuple[str, ...], str, str, str], ...] = (
    (("go.mod",), "Go", "go_module", "Go module detected via go.mod"),
    (("pom.xml",), "Java/Maven", "java_maven", "Java/Maven project detected via pom.xml"),
    (
        ("build.gradle", "build.gradle.kts"),
        "Java/Kotlin (Gradle)",
        "java_gradle",
        "Java/Kotlin project detected via build.gradle",
    ),
    (("Cargo.toml",), "Rust", "rust_cargo", "Rust project detected via Cargo.toml"),
)


def _detect_simple_stacks(
    repo_root: Path,
    found: list[dict[str, str]],
    primary: str | None,
    weights: dict[str, int] | None = None,
) -> str | None:
    """Append signals for single-file language markers; return the first primary label seen."""

    for markers, label, sig_id, detail in _SIMPLE_STACK_MARKERS:
        if any((repo_root / m).is_file() for m in markers):
            primary = primary or label
            _append_signal(found, sig_id, detail)
            if weights is not None:
                weights[label] = _STACK_WEIGHT_DECLARES_PROJECT
    if list(repo_root.glob("*.csproj")) or list(repo_root.glob("*.sln")):
        primary = primary or "C#/.NET"
        _append_signal(found, "dotnet_csproj", "C#/.NET project detected via .csproj or .sln")
        if weights is not None:
            weights["C#/.NET"] = _STACK_WEIGHT_DECLARES_PROJECT
    return primary


def _primary_stacks(weights: dict[str, int]) -> list[str]:
    """Return every stack tied for the strongest signal, in a stable display order."""

    if not weights:
        return []
    strongest = max(weights.values())
    tied = {label for label, weight in weights.items() if weight == strongest}
    ordered = [label for label in _STACK_LABEL_ORDER if label in tied]
    # A label missing from the display order must still surface, never be dropped silently.
    return ordered + sorted(tied.difference(ordered))


def _collect_tech_stack_signals(
    repo_root: Path,
) -> tuple[list[dict[str, str]], list[str], bool, str | None]:
    """Detect common language/runtime markers; returns signals, notes, Dockerfile->L2 flag, primary stack label."""

    found: list[dict[str, str]] = []
    notes: list[str] = []
    weights: dict[str, int] = {}
    prefer_l2 = _detect_container_stack(repo_root, found)
    _detect_node_stack(repo_root, found, weights)
    # Every detector runs: first-match-wins used to short-circuit the rest, so a repo
    # with both markers lost the weaker-listed stack from signals_detected entirely.
    _detect_python_stack(repo_root, found, notes, weights)
    _detect_simple_stacks(repo_root, found, None, weights)

    primary_stacks = _primary_stacks(weights)
    signal_ids = {s["id"] for s in found}
    if "Node.js" in primary_stacks and "node_lockfile" not in signal_ids:
        # Only advise a lockfile when Node is what the repository actually is; on a
        # sidecar package.json this reads as advice for somebody else's project.
        notes.append(_NODE_LOCKFILE_NOTE)
    return found, notes, prefer_l2, " / ".join(primary_stacks) or None


def _platform_order(
    *,
    wf_paths: list[Path],
    gl_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    github_ev: list[Path],
    gitlab_ev: list[Path],
    azure_ev: list[Path],
    aws_ev: list[Path],
) -> list[str]:
    """Return github, gitlab, azure, aws ordered with the most strongly indicated platform first."""

    def weight(name: str) -> int:
        if name == "github":
            return 100 * len(github_ev) + 40 * bool(wf_paths)
        if name == "gitlab":
            return 100 * len(gitlab_ev) + 40 * bool(gl_paths)
        if name == "azure":
            return 100 * len(azure_ev) + 40 * bool(az_paths)
        return 100 * len(aws_ev) + 40 * bool(buildspec)

    present = [p for p in ("github", "gitlab", "azure", "aws") if weight(p) > 0]
    return sorted(present, key=lambda n: (-weight(n), n))


def _collect_signals(
    wf_paths: list[Path],
    gl_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    ev_dir: Path,
    ev_json: list[Path],
    github_ev: list[Path],
    gitlab_ev: list[Path],
    azure_ev: list[Path],
    aws_ev: list[Path],
    other_ev: list[Path],
) -> list[dict[str, str]]:
    signals: list[dict[str, str]] = []
    if wf_paths:
        _append_signal(
            signals,
            "github_actions_workflows",
            f"Found {len(wf_paths)} workflow file(s) under .github/workflows/.",
        )
    if gl_paths:
        _append_signal(
            signals,
            "gitlab_ci_yaml",
            f"Found {len(gl_paths)} GitLab CI file(s) (.gitlab-ci.yml at root or under .gitlab/).",
        )
    if az_paths:
        _append_signal(
            signals,
            "azure_pipelines_yaml",
            f"Found {len(az_paths)} Azure Pipelines file(s) in supported paths.",
        )
    if buildspec:
        _append_signal(signals, "aws_codebuild_buildspec", "Found buildspec.yml / buildspec.yaml at root.")

    if ev_dir.is_dir() and not ev_json:
        _append_signal(
            signals,
            "evidence_dir_empty",
            ".oss-policy-kit/evidence/ exists but no *.json files yet.",
        )

    if github_ev:
        names = ", ".join(sorted(p.name for p in github_ev))
        _append_signal(
            signals,
            "github_evidence_json_files",
            f"Found {len(github_ev)} GitHub-shaped evidence JSON file(s): {names}",
        )
    if azure_ev:
        names = ", ".join(sorted(p.name for p in azure_ev))
        _append_signal(
            signals,
            "azure_evidence_json_files",
            f"Found {len(azure_ev)} Azure-shaped evidence JSON file(s): {names}",
        )
    if gitlab_ev:
        names = ", ".join(sorted(p.name for p in gitlab_ev))
        _append_signal(
            signals,
            "gitlab_evidence_json_files",
            f"Found {len(gitlab_ev)} GitLab-shaped evidence JSON file(s): {names}",
        )
    if aws_ev:
        names = ", ".join(sorted(p.name for p in aws_ev))
        _append_signal(
            signals,
            "aws_evidence_json_files",
            f"Found {len(aws_ev)} AWS-shaped evidence JSON file(s): {names}",
        )
    if other_ev:
        names = ", ".join(sorted(p.name for p in other_ev[:5]))
        extra = "" if len(other_ev) <= 5 else f" (+{len(other_ev) - 5} more)"
        _append_signal(
            signals,
            "evidence_json_unrecognized_filenames",
            (
                f"Unrecognized JSON under .oss-policy-kit/evidence/ — these files do not "
                f"match any bundled schema and will be ignored by `evaluate`: {names}{extra}. "
                f"Rename to a bundled template (see `scaffold-evidence --help`) or remove them."
            ),
        )
    return signals


def _append_gh_release_hardening(
    out: list[tuple[int, str, str, list[str]]],
    *,
    can_rh2: bool,
    can_rh1: bool,
    wf_paths: list[Path],
    github_ev: list[Path],
) -> None:
    """Append the GitHub release-hardening-2/-1 suggestion when its signals are present."""

    if can_rh2:
        gh_keys = ("github_actions_workflows", "github_evidence_json_files")
        bo = [x for x in gh_keys if _bo_hit(x, wf_paths, github_ev)]
        if not bo:
            bo = ["github_actions_workflows"] if wf_paths else ["github_evidence_json_files"]
        out.append(
            (
                300,
                "github-release-hardening-2",
                (
                    "GitHub Actions workflows AND GitHub-shaped release evidence JSON are both "
                    "present; evaluate declared release posture with github-release-hardening-2 "
                    "(verify evidence JSONs are filled, not templates)."
                ),
                _normalize_based_on(bo, wf_paths, github_ev),
            )
        )
    elif can_rh1:
        out.append(
            (
                290,
                "github-release-hardening-1",
                (
                    "Evidence directory is empty but GitHub workflows exist; "
                    "add GitHub evidence JSON, then use release-hardening-1 as a starting ladder."
                ),
                ["evidence_dir_empty", "github_actions_workflows"],
            )
        )


def _suggestions_github(
    *,
    wf_paths: list[Path],
    github_ev: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    empty_evidence_dir: bool,
) -> list[tuple[int, str, str, list[str]]]:
    """GitHub-platform profile suggestions (see _suggestions_for_platform)."""

    out: list[tuple[int, str, str, list[str]]] = []
    # release-hardening-2 requires BOTH a CI signal AND release-shaped evidence
    # (M-005): a single intentionally-unsafe workflow alone is not justification
    # to recommend a release-track profile.
    can_rh2 = bool(wf_paths) and bool(github_ev)
    can_rh1 = empty_evidence_dir and bool(wf_paths) and not github_ev
    if wf_paths and not github_ev:
        out.append(
            (
                320,
                "github-level-1",
                (
                    "GitHub workflows are visible but release evidence is not present yet; "
                    "start with github-level-1 and escalate after evidence maturity."
                ),
                ["github_actions_workflows"],
            )
        )
    _append_gh_release_hardening(out, can_rh2=can_rh2, can_rh1=can_rh1, wf_paths=wf_paths, github_ev=github_ev)
    if wf_paths and github_ev:
        tier = "github-level-2" if len(wf_paths) >= 2 else "github-level-1"
        out.append(
            (
                200,
                tier,
                (
                    "GitHub Actions workflows are visible in the clone; pick a GitHub ladder profile "
                    "that matches your desired strictness."
                ),
                ["github_actions_workflows"],
            )
        )
    # MELHORIA-001 / F-001: evidence files for GitHub exist but NO CI signal
    # in the clone (and no other platform's CI either). Surface a weak
    # suggestion + explicit rationale. If another platform (Azure / AWS) has
    # CI signals, suppress this fallback — the adopter is clearly on that
    # platform, and a GitHub recommendation would be misleading.
    no_other_ci = not az_paths and not buildspec
    if github_ev and not wf_paths and no_other_ci:
        # Suggest the starter ladder (github-level-1), not release-hardening:
        # the adopter clearly lacks CI altogether, so release-track guidance
        # would be misleading. The rationale explains that the evidence is
        # currently unused. Keeps consistency with M-005 (no release-hardening
        # without CI signal).
        out.append(
            (
                150,
                "github-level-1",
                (
                    "GitHub-shaped evidence JSON files were found but no .github/workflows/ "
                    "files exist in this clone. The evidence is currently unused — start "
                    "from github-level-1 and add a workflow first (or confirm you are "
                    "pointing --target at the correct repository root), then re-run "
                    "recommend-profile to graduate to a release-hardening profile."
                ),
                ["github_evidence_json_files"],
            )
        )
    return out


def _suggestions_gitlab(
    *,
    gl_paths: list[Path],
    gitlab_ev: list[Path],
    wf_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    empty_evidence_dir: bool,
) -> list[tuple[int, str, str, list[str]]]:
    """GitLab-platform profile suggestions (see _suggestions_for_platform)."""

    out: list[tuple[int, str, str, list[str]]] = []
    # BOTH a CI signal AND release-shaped evidence required for release-hardening-2 (M-005).
    can_rh2 = bool(gl_paths) and bool(gitlab_ev)
    can_rh1 = empty_evidence_dir and bool(gl_paths) and not gitlab_ev
    if can_rh2:
        gl_keys = ("gitlab_ci_yaml", "gitlab_evidence_json_files")
        bo = [x for x in gl_keys if _bo_hit_gl(x, gl_paths, gitlab_ev)]
        if not bo:
            bo = ["gitlab_ci_yaml"] if gl_paths else ["gitlab_evidence_json_files"]
        out.append(
            (
                300,
                "gitlab-release-hardening-2",
                (
                    "GitLab CI pipelines AND GitLab-shaped release evidence JSON are both present; "
                    "evaluate declared release posture with gitlab-release-hardening-2 "
                    "(verify evidence JSONs are filled, not templates)."
                ),
                _normalize_based_on_gl(bo, gl_paths, gitlab_ev),
            )
        )
    elif can_rh1:
        out.append(
            (
                290,
                "gitlab-release-hardening-1",
                (
                    "Evidence directory is empty but GitLab CI pipelines exist; "
                    "add GitLab evidence JSON, then use gitlab-release-hardening-1 as a starting ladder."
                ),
                ["evidence_dir_empty", "gitlab_ci_yaml"],
            )
        )
    if gl_paths:
        tier = "gitlab-level-2" if len(gl_paths) >= 2 else "gitlab-level-1"
        out.append(
            (
                200,
                tier,
                "GitLab CI pipelines are present; evaluate clone-visible GitLab CI governance.",
                ["gitlab_ci_yaml"],
            )
        )
    # GitLab evidence without GitLab CI (and no other platform's CI): surface a weak fallback.
    no_other_ci = not wf_paths and not az_paths and not buildspec
    if gitlab_ev and not gl_paths and no_other_ci:
        out.append(
            (
                150,
                "gitlab-level-1",
                (
                    "GitLab-shaped evidence JSON files were found but no .gitlab-ci.yml exists in this "
                    "clone. The evidence is currently unused — start from gitlab-level-1 and add a "
                    "pipeline first (or confirm you are pointing --target at the correct repository "
                    "root), then re-run recommend-profile to graduate to a release-hardening profile."
                ),
                ["gitlab_evidence_json_files"],
            )
        )
    return out


def _suggestions_azure(
    *,
    az_paths: list[Path],
    azure_ev: list[Path],
    wf_paths: list[Path],
    buildspec: bool,
    empty_evidence_dir: bool,
) -> list[tuple[int, str, str, list[str]]]:
    """Azure-platform profile suggestions (see _suggestions_for_platform)."""

    out: list[tuple[int, str, str, list[str]]] = []
    # See github branch above: BOTH signals required for release-hardening-2 (M-005).
    can_rh2 = bool(az_paths) and bool(azure_ev)
    can_rh1 = empty_evidence_dir and bool(az_paths) and not azure_ev
    if can_rh2:
        az_keys = ("azure_pipelines_yaml", "azure_evidence_json_files")
        bo = [x for x in az_keys if _bo_hit_az(x, az_paths, azure_ev)]
        if not bo:
            bo = ["azure_pipelines_yaml"] if az_paths else ["azure_evidence_json_files"]
        out.append(
            (
                300,
                "azure-release-hardening-2",
                (
                    "Azure Pipelines YAML AND Azure-shaped release evidence JSON are both "
                    "present; evaluate declared release posture with azure-release-hardening-2 "
                    "(verify evidence JSONs are filled, not templates)."
                ),
                _normalize_based_on_az(bo, az_paths, azure_ev),
            )
        )
    elif can_rh1:
        out.append(
            (
                290,
                "azure-release-hardening-1",
                (
                    "Evidence directory is empty but Azure Pipelines YAML exists; "
                    "add Azure evidence JSON, then use azure-release-hardening-1 as a starting ladder."
                ),
                ["evidence_dir_empty", "azure_pipelines_yaml"],
            )
        )
    if az_paths:
        out.append(
            (
                200,
                "azure-level-1",
                "Azure Pipelines definitions are present; evaluate clone-visible Azure CI governance.",
                ["azure_pipelines_yaml"],
            )
        )
    # MELHORIA-001 / F-001: Azure evidence without Azure Pipelines (and
    # no other platform's CI), see the GitHub branch above.
    no_other_ci = not wf_paths and not buildspec
    if azure_ev and not az_paths and no_other_ci:
        out.append(
            (
                150,
                "azure-level-1",
                (
                    "Azure-shaped evidence JSON files were found but no Azure Pipelines YAML "
                    "exists in this clone. The evidence is currently unused — start from "
                    "azure-level-1 and add a pipeline first (or confirm you are pointing "
                    "--target at the correct repository root), then re-run recommend-profile "
                    "to graduate to a release-hardening profile."
                ),
                ["azure_evidence_json_files"],
            )
        )
    return out


def _suggestions_aws(
    *,
    buildspec: bool,
    aws_ev: list[Path],
    wf_paths: list[Path],
    az_paths: list[Path],
    empty_evidence_dir: bool,
) -> list[tuple[int, str, str, list[str]]]:
    """AWS-platform profile suggestions (see _suggestions_for_platform)."""

    out: list[tuple[int, str, str, list[str]]] = []
    # See github branch above: BOTH signals required for release-hardening-2 (M-005).
    can_rh2 = bool(buildspec) and bool(aws_ev)
    can_rh1 = empty_evidence_dir and bool(buildspec) and not aws_ev
    if can_rh2:
        aws_keys = ("aws_codebuild_buildspec", "aws_evidence_json_files")
        bo = [x for x in aws_keys if _bo_hit_aws(x, buildspec, aws_ev)]
        if not bo:
            bo = ["aws_codebuild_buildspec"] if buildspec else ["aws_evidence_json_files"]
        out.append(
            (
                300,
                "aws-release-hardening-2",
                (
                    "A buildspec AND AWS-shaped release evidence JSON are both present; "
                    "evaluate declared release posture with aws-release-hardening-2 "
                    "(verify evidence JSONs are filled, not templates)."
                ),
                _normalize_based_on_aws(bo, buildspec, aws_ev),
            )
        )
    elif can_rh1:
        out.append(
            (
                290,
                "aws-release-hardening-1",
                (
                    "Evidence directory is empty but buildspec.yml exists; "
                    "add AWS evidence JSON, then use aws-release-hardening-1 as a starting ladder."
                ),
                ["evidence_dir_empty", "aws_codebuild_buildspec"],
            )
        )
    if buildspec:
        out.append(
            (
                200,
                "aws-level-1",
                "A CodeBuild buildspec is present; evaluate clone-visible AWS CI signals.",
                ["aws_codebuild_buildspec"],
            )
        )
    # MELHORIA-001 / F-001: AWS evidence without buildspec (and no other
    # platform's CI), see the GitHub branch above.
    no_other_ci = not wf_paths and not az_paths
    if aws_ev and not buildspec and no_other_ci:
        out.append(
            (
                150,
                "aws-level-1",
                (
                    "AWS-shaped evidence JSON files were found but no buildspec.yml / "
                    "buildspec.yaml exists in this clone. The evidence is currently unused — "
                    "start from aws-level-1 and add a buildspec first (or confirm you are "
                    "pointing --target at the correct repository root), then re-run "
                    "recommend-profile to graduate to a release-hardening profile."
                ),
                ["aws_evidence_json_files"],
            )
        )
    return out


def _suggestions_for_platform(
    platform: str,
    *,
    wf_paths: list[Path],
    gl_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    ev_dir: Path,
    ev_json: list[Path],
    github_ev: list[Path],
    gitlab_ev: list[Path],
    azure_ev: list[Path],
    aws_ev: list[Path],
) -> list[tuple[int, str, str, list[str]]]:
    """Return (priority, profile_id, rationale, based_on) for one platform, in user-facing order."""

    empty_evidence_dir = ev_dir.is_dir() and not ev_json
    if platform == "github":
        return _suggestions_github(
            wf_paths=wf_paths,
            github_ev=github_ev,
            az_paths=az_paths,
            buildspec=buildspec,
            empty_evidence_dir=empty_evidence_dir,
        )
    if platform == "gitlab":
        return _suggestions_gitlab(
            gl_paths=gl_paths,
            gitlab_ev=gitlab_ev,
            wf_paths=wf_paths,
            az_paths=az_paths,
            buildspec=buildspec,
            empty_evidence_dir=empty_evidence_dir,
        )
    if platform == "azure":
        return _suggestions_azure(
            az_paths=az_paths,
            azure_ev=azure_ev,
            wf_paths=wf_paths,
            buildspec=buildspec,
            empty_evidence_dir=empty_evidence_dir,
        )
    return _suggestions_aws(
        buildspec=buildspec,
        aws_ev=aws_ev,
        wf_paths=wf_paths,
        az_paths=az_paths,
        empty_evidence_dir=empty_evidence_dir,
    )


def _bo_hit(name: str, wf_paths: list[Path], github_ev: list[Path]) -> bool:
    if name == "github_actions_workflows":
        return bool(wf_paths)
    if name == "github_evidence_json_files":
        return bool(github_ev)
    return False


def _normalize_based_on(bo: list[str], wf_paths: list[Path], github_ev: list[Path]) -> list[str]:
    out = list(bo)
    if "github_actions_workflows" not in out and wf_paths:
        out.insert(0, "github_actions_workflows")
    if "github_evidence_json_files" not in out and github_ev:
        out.append("github_evidence_json_files")
    return out


def _bo_hit_gl(name: str, gl_paths: list[Path], gitlab_ev: list[Path]) -> bool:
    if name == "gitlab_ci_yaml":
        return bool(gl_paths)
    if name == "gitlab_evidence_json_files":
        return bool(gitlab_ev)
    return False


def _normalize_based_on_gl(bo: list[str], gl_paths: list[Path], gitlab_ev: list[Path]) -> list[str]:
    out = list(bo)
    if "gitlab_ci_yaml" not in out and gl_paths:
        out.insert(0, "gitlab_ci_yaml")
    if "gitlab_evidence_json_files" not in out and gitlab_ev:
        out.append("gitlab_evidence_json_files")
    return out


def _bo_hit_az(name: str, az_paths: list[Path], azure_ev: list[Path]) -> bool:
    if name == "azure_pipelines_yaml":
        return bool(az_paths)
    if name == "azure_evidence_json_files":
        return bool(azure_ev)
    return False


def _normalize_based_on_az(bo: list[str], az_paths: list[Path], azure_ev: list[Path]) -> list[str]:
    out = list(bo)
    if "azure_pipelines_yaml" not in out and az_paths:
        out.insert(0, "azure_pipelines_yaml")
    if "azure_evidence_json_files" not in out and azure_ev:
        out.append("azure_evidence_json_files")
    return out


def _bo_hit_aws(name: str, buildspec: bool, aws_ev: list[Path]) -> bool:
    if name == "aws_codebuild_buildspec":
        return buildspec
    if name == "aws_evidence_json_files":
        return bool(aws_ev)
    return False


def _normalize_based_on_aws(bo: list[str], buildspec: bool, aws_ev: list[Path]) -> list[str]:
    out = list(bo)
    if "aws_codebuild_buildspec" not in out and buildspec:
        out.insert(0, "aws_codebuild_buildspec")
    if "aws_evidence_json_files" not in out and aws_ev:
        out.append("aws_evidence_json_files")
    return out


def _merge_platform_suggestions(
    order: list[str],
    *,
    wf_paths: list[Path],
    gl_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    ev_dir: Path,
    ev_json: list[Path],
    github_ev: list[Path],
    gitlab_ev: list[Path],
    azure_ev: list[Path],
    aws_ev: list[Path],
) -> list[dict[str, Any]]:
    """Collect, rank, and de-duplicate per-platform suggestions (top 3)."""

    merged: list[tuple[int, int, str, str, list[str]]] = []
    for order_idx, plat in enumerate(order):
        for prio, pid, rationale, based_on in _suggestions_for_platform(
            plat,
            wf_paths=wf_paths,
            gl_paths=gl_paths,
            az_paths=az_paths,
            buildspec=buildspec,
            ev_dir=ev_dir,
            ev_json=ev_json,
            github_ev=github_ev,
            gitlab_ev=gitlab_ev,
            azure_ev=azure_ev,
            aws_ev=aws_ev,
        ):
            merged.append((prio, order_idx, pid, rationale, based_on))

    merged.sort(key=lambda t: (-t[0], t[1]))
    suggestions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for _prio, _order_idx, pid, rationale, based_on in merged:
        if pid in seen or len(suggestions) >= 3:
            continue
        suggestions.append({"profile_id": pid, "rationale": rationale, "based_on": list(dict.fromkeys(based_on))})
        seen.add(pid)
    return suggestions


def _multi_platform_notes(order: list[str]) -> list[str]:
    """Notes explaining ranked multi-platform CI detection (empty for 0/1 platform)."""

    if len(order) <= 1:
        return []
    primary = order[0]
    pretty = {
        "github": "GitHub Actions",
        "gitlab": "GitLab CI",
        "azure": "Azure Pipelines",
        "aws": "AWS CodeBuild",
    }.get(primary, primary)
    tail = ", ".join(
        {"github": "GitHub", "gitlab": "GitLab", "azure": "Azure", "aws": "AWS"}.get(p, p) for p in order[1:]
    )
    return [
        (
            f"Multiple CI platforms detected in this clone (primary ranked: {pretty}; also: {tail}). "
            "Profile suggestions prioritize the strongest platform signals first."
        ),
        (
            "Pass --platform github | gitlab | azure | aws (on `init`) or --profile <id> (on `evaluate`) "
            "to override and fix the platform family yourself."
        ),
    ]


def _no_platform_fallback(
    *,
    other_ev: list[Path],
    wf_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    github_ev: list[Path],
    azure_ev: list[Path],
    aws_ev: list[Path],
    ev_dir: Path,
    ev_json: list[Path],
    prefer_l2_container: bool,
    tech_ids: set[str],
    tech_primary: str | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Suggestions + notes when no CI platform was detected at all."""

    notes: list[str] = []
    suggestions: list[dict[str, Any]] = []
    if other_ev and not (wf_paths or az_paths or buildspec or github_ev or azure_ev or aws_ev):
        notes.append(
            "Evidence JSON uses non-bundled filenames; add platform-specific template names "
            "(or CI signals) so release-hardening suggestions can align to GitHub, Azure, or AWS."
        )
    if ev_dir.is_dir() and not ev_json and not (wf_paths or az_paths or buildspec):
        notes.append(
            "An empty .oss-policy-kit/evidence/ directory was found without CI signals; "
            "run scaffold-evidence for the correct platform or remove the folder if unused."
        )
    if prefer_l2_container or "container_docker" in tech_ids:
        notes.append(
            "Container workloads benefit from stricter workflow and supply-chain controls "
            "(image provenance, pinned actions, SBOM signals) - github-level-2 is a stronger starting point."
        )
        suggestions.append(
            {
                "profile_id": "github-level-2",
                "rationale": (
                    "Container signals detected (Dockerfile / compose). github-level-2 is recommended "
                    "as a baseline because it emphasizes CI workflow hardening and supply-chain adjacent "
                    "checks relevant to container build and publish paths."
                ),
                "based_on": (["container_docker"] if "container_docker" in tech_ids else sorted(tech_ids)),
            }
        )
    elif tech_ids:
        stack = tech_primary or "application"
        suggestions.append(
            {
                "profile_id": "github-level-1",
                "rationale": (
                    f"github-level-1 is recommended as a starting baseline for your {stack} project; "
                    "it covers SAST, dependency audit, and governance signals relevant to typical CI pipelines."
                ),
                "based_on": sorted(tech_ids),
            }
        )
    else:
        notes.append("Few strong platform signals were detected; defaulting to a conservative GitHub baseline profile.")
        suggestions.append(
            {
                "profile_id": "github-level-1",
                "rationale": (
                    "No GitHub/Azure/AWS CI or bundled-shaped evidence JSON detected; "
                    "github-level-1 is the safest default ladder."
                ),
                "based_on": [],
            }
        )
    return suggestions, notes


def build_profile_recommendation(repo_root: Path) -> ProfileRecommendation:
    """Inspect *repo_root* and return up to three profile suggestions with rationale."""

    wf_paths = _workflow_yaml_paths(repo_root)
    gl_paths = _gitlab_ci_paths(repo_root)
    az_paths = _azure_pipeline_paths(repo_root)
    buildspec = (repo_root / "buildspec.yml").is_file() or (repo_root / "buildspec.yaml").is_file()
    ev_dir = repo_root / ".oss-policy-kit" / "evidence"
    ev_json = _evidence_json_paths(repo_root)
    github_ev, gitlab_ev, azure_ev, aws_ev, other_ev = _partition_evidence_json(ev_json)

    signals = _collect_signals(
        wf_paths, gl_paths, az_paths, buildspec, ev_dir, ev_json, github_ev, gitlab_ev, azure_ev, aws_ev, other_ev
    )

    tech_signals, tech_notes, prefer_l2_container, tech_primary = _collect_tech_stack_signals(repo_root)
    signals.extend(tech_signals)

    order = _platform_order(
        wf_paths=wf_paths,
        gl_paths=gl_paths,
        az_paths=az_paths,
        buildspec=buildspec,
        github_ev=github_ev,
        gitlab_ev=gitlab_ev,
        azure_ev=azure_ev,
        aws_ev=aws_ev,
    )

    suggestions = _merge_platform_suggestions(
        order,
        wf_paths=wf_paths,
        gl_paths=gl_paths,
        az_paths=az_paths,
        buildspec=buildspec,
        ev_dir=ev_dir,
        ev_json=ev_json,
        github_ev=github_ev,
        gitlab_ev=gitlab_ev,
        azure_ev=azure_ev,
        aws_ev=aws_ev,
    )

    notes = _multi_platform_notes(order)
    tech_ids = {s["id"] for s in tech_signals}
    if tech_notes:
        notes.extend(tech_notes)

    if not order:
        fb_suggestions, fb_notes = _no_platform_fallback(
            other_ev=other_ev,
            wf_paths=wf_paths,
            az_paths=az_paths,
            buildspec=buildspec,
            github_ev=github_ev,
            azure_ev=azure_ev,
            aws_ev=aws_ev,
            ev_dir=ev_dir,
            ev_json=ev_json,
            prefer_l2_container=prefer_l2_container,
            tech_ids=tech_ids,
            tech_primary=tech_primary,
        )
        suggestions.extend(fb_suggestions)
        notes.extend(fb_notes)

    return ProfileRecommendation(signals_detected=signals, suggestions=suggestions, notes=notes)


def recommend_profiles(repo_root: Path) -> list[tuple[str, str]]:
    """Backward-compatible (profile_id, rationale) pairs, up to three entries."""

    rec = build_profile_recommendation(repo_root)
    return [(s["profile_id"], str(s["rationale"])) for s in rec.suggestions]
