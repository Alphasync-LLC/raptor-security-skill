"""``.pre-commit-config.yaml`` parser.

Pre-commit (https://pre-commit.com) declares hooks per repository:

    repos:
      - repo: https://github.com/astral-sh/ruff-pre-commit
        rev: v0.6.9
        hooks:
          - id: ruff
      - repo: https://github.com/psf/black
        rev: 24.10.0
        hooks:
          - id: black
      - repo: local
        hooks:
          - id: my-script
            entry: scripts/check.sh

Each entry pins a git ``rev`` of the hook-providing repo. Pre-commit
will fetch + run the hook on every commit, so a compromised hook
provider runs code on developer machines and in CI.

This parser:

  * Walks the YAML's ``repos`` array.
  * For each entry, resolves the ``repo:`` URL through a curated
    ``repo: → registry`` map (``data/precommit_repo_map.json``)
    so well-known hooks (ruff, black, mypy, etc.) get classified
    against their actual ecosystem (PyPI / npm / RubyGems) — OSV
    CVE matching then fires against the underlying tool, not just
    the GitHub repo name.
  * Falls back to ecosystem ``"GitHub"`` for unmapped repos
    (visibility in the SBOM; OSV won't match).
  * Skips ``repo: local`` entries (no version, no external code
    to scan).
  * Skips ``repo: meta`` entries (pre-commit's own pseudo-repo
    for built-in hooks).

Each repo emits ONE Dependency row regardless of how many ``hooks:``
entries it has — ``rev:`` pins the whole repository, so the per-
hook rows would all carry the same version. The hook IDs are
captured in ``source_extra.hook_ids`` for SBOM context.

Versions for unmapped (GitHub-purled) entries follow the
``.gitmodules`` model: emit with ``ecosystem="GitHub"`` and
``version=<rev>``. CVE matching won't fire (no GitHub OSV
ecosystem), but the SBOM has the entry for triage.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


_REPO_MAP_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "precommit_repo_map.json"
)

_GITHUB_FALLBACK_ECOSYSTEM = "GitHub"


# ---------------------------------------------------------------------------
# Parser registration
# ---------------------------------------------------------------------------


@register(filenames=[".pre-commit-config.yaml", ".pre-commit-config.yml"])
def parse(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning(
            "sca.parsers.precommit: read failed for %s: %s", path, e,
        )
        return []
    try:
        import yaml                 # type: ignore[import-untyped]
    except ImportError:
        logger.debug(
            "sca.parsers.precommit: PyYAML not installed; skipping %s",
            path,
        )
        return []
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        logger.warning(
            "sca.parsers.precommit: YAML parse failed for %s: %s",
            path, e,
        )
        return []
    if not isinstance(data, dict):
        return []

    repo_map = _load_repo_map()

    repos = data.get("repos") or []
    if not isinstance(repos, list):
        return []

    out: List[Dependency] = []
    for entry in repos:
        dep = _build_dep(entry, declared_in=path, repo_map=repo_map)
        if dep is not None:
            out.append(dep)
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _load_repo_map() -> Dict[str, Dict[str, str]]:
    """Load the curated repo→registry map. Per-call rather than
    module-level so a future test injection point stays simple."""
    try:
        text = _REPO_MAP_PATH.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    out: Dict[str, Dict[str, str]] = {}
    for key, val in data.items():
        if key.startswith("_"):
            continue
        if not isinstance(val, dict):
            continue
        eco = val.get("ecosystem")
        name = val.get("name")
        if isinstance(eco, str) and isinstance(name, str):
            out[key] = {"ecosystem": eco, "name": name}
    return out


def _build_dep(
    entry: Any,
    *,
    declared_in: Path,
    repo_map: Dict[str, Dict[str, str]],
) -> Optional[Dependency]:
    if not isinstance(entry, dict):
        return None
    repo = entry.get("repo")
    if not isinstance(repo, str) or not repo.strip():
        return None
    repo = repo.strip()
    if repo in ("local", "meta"):
        return None

    rev = entry.get("rev")
    if not isinstance(rev, str) or not rev.strip():
        return None
    rev = rev.strip()

    canonical = _canonicalise_repo(repo)
    if not canonical:
        return None

    hooks_raw = entry.get("hooks") or []
    hook_ids: List[str] = []
    if isinstance(hooks_raw, list):
        for h in hooks_raw:
            if isinstance(h, dict):
                hid = h.get("id")
                if isinstance(hid, str):
                    hook_ids.append(hid)

    mapping = repo_map.get(canonical)
    pin_style = _classify_rev(rev)

    if mapping is not None:
        eco = mapping["ecosystem"]
        name = mapping["name"]
        purl_type = _eco_to_purl(eco)
        purl = f"pkg:{purl_type}/{name}@{rev}"
    else:
        # Unmapped repo — fall back to GitHub purl for visibility.
        eco = _GITHUB_FALLBACK_ECOSYSTEM
        name = canonical[len("github.com/"):] if canonical.startswith(
            "github.com/",
        ) else canonical
        purl = f"pkg:github/{name}@{rev}"

    return Dependency(
        ecosystem=eco,
        name=name,
        version=rev,
        declared_in=declared_in,
        scope="dev",
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            "high" if mapping is not None else "medium",
            reason=(
                f"pre-commit repo {repo} mapped to {eco}:{name}"
                if mapping is not None
                else f"pre-commit repo {repo} unmapped — emitted as "
                     f"GitHub purl"
            ),
        ),
        source_kind="precommit",
        source_extra={
            "repo": repo,
            "canonical": canonical,
            "hook_ids": hook_ids,
        },
    )


def _canonicalise_repo(url: str) -> Optional[str]:
    """Normalise a pre-commit ``repo:`` URL to a lookup key.

    ``https://github.com/astral-sh/ruff-pre-commit.git`` →
    ``github.com/astral-sh/ruff-pre-commit``.
    SSH form ``git@github.com:org/repo.git`` is normalised.
    Strips trailing ``.git`` and lowercases for case-insensitive
    map lookup.
    """
    url = url.strip().rstrip("/")
    if url.startswith("git@") and ":" in url:
        host, _, path = url[len("git@"):].partition(":")
        url = f"https://{host}/{path}"
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lstrip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    if not host or not path:
        return None
    return f"{host}/{path}".lower()


def _classify_rev(rev: str) -> PinStyle:
    """Classify a pre-commit ``rev:`` string."""
    import re
    if re.fullmatch(r"[0-9a-fA-F]{40}", rev):
        return PinStyle.GIT
    if re.match(r"^v?\d", rev):
        return PinStyle.EXACT
    return PinStyle.UNKNOWN


def _eco_to_purl(ecosystem: str) -> str:
    """Map SCA ecosystem string → purl type. Mirrors the per-
    ecosystem conventions used elsewhere in the codebase."""
    return {
        "PyPI": "pypi",
        "npm": "npm",
        "RubyGems": "gem",
        "Cargo": "cargo",
        "Go": "golang",
        "NuGet": "nuget",
        "Packagist": "composer",
        "Maven": "maven",
    }.get(ecosystem, ecosystem.lower())
