"""Bumper orchestrator — walks opinion surfaces, proposes
target versions, evaluates verdicts, optionally applies edits.

Phase 2.d MVP covers ONE surface: Dockerfile ARG version pins.
Future surfaces (manifest deps, FROM image refs, GHA `uses:`,
Helm chart deps, git submodules) plug in via the same shape —
each adds a walker + an upstream-source lookup + a rewriter
registration.

Operator-facing flow:

  raptor-sca bump <target>
    → walks every Dockerfile under <target>
    → for each ARG pin with a known upstream source, fetches
      the latest stable version
    → for each proposed bump, runs ``evaluate_bump_supply_chain``
      + ``_compute_verdict`` to produce a Block / Review / Clean
      verdict
    → prints a verdict table (default)
    → optionally writes the changes (``--apply``)
    → optionally emits a proposed/ directory (``--out``) instead
      of in-place writes
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from ..models import SupplyChainFinding
from ..parsers.inline_installs._arg_version_pins import (
    _BUILTIN_ARG_MAP,
    _ARG_RE,
)
from ..registries.npm import NpmClient
from ..registries.pypi import PyPIClient
from ..rewriters import RewriteEdit, RewriteResult, rewrite
from .evaluator import evaluate_bump_supply_chain
from .upstream_map import UpstreamSource, lookup_upstream

logger = logging.getLogger(__name__)

# Verdict ladder constants (mirroring ``review.py``).
_VERDICT_CLEAN = 0
_VERDICT_REVIEW = 1
_VERDICT_BLOCK = 2

_VERDICT_LABEL = {
    _VERDICT_CLEAN: "Clean",
    _VERDICT_REVIEW: "Review",
    _VERDICT_BLOCK: "Block",
}


@dataclass(frozen=True)
class BumpCandidate:
    """One proposed bump: where it lives + what we'd change it to."""

    arg_name: str
    file: Path
    current_version: str
    target_version: str
    upstream: UpstreamSource


@dataclass
class BumpResult:
    """Per-candidate outcome — what verdict we computed and
    whether we applied the rewrite."""

    candidate: BumpCandidate
    verdict: int
    verdict_label: str
    bump_supply_chain_findings: List[SupplyChainFinding]
    error: Optional[str] = None
    rewrite_result: Optional[RewriteResult] = None


@dataclass
class BumpReport:
    """Aggregate report from a ``run_bump`` call."""

    target: Path
    candidates: List[BumpCandidate]
    results: List[BumpResult]
    skipped: List[Tuple[str, Path, str]] = field(default_factory=list)
    # ``(arg_name, file, reason)`` for ARGs we couldn't bump
    # (no upstream mapping, current version not parseable, etc.)


def run_bump(
    target: Path,
    *,
    http,
    pypi_client: Optional[PyPIClient] = None,
    npm_client: Optional[NpmClient] = None,
    apply: bool = False,
    now: Optional[datetime] = None,
    cache=None,
    github_token: Optional[str] = None,
) -> BumpReport:
    """Walk Dockerfiles under ``target``, propose ARG bumps,
    compute verdicts, optionally apply.

    ``apply=False`` is dry-run: candidates + verdicts only, no
    file writes. ``apply=True`` rewrites in place via the
    Dockerfile-ARG rewriter — only edits where the verdict is
    Clean are applied (Review and Block surface in the report
    but don't auto-apply, per the project's "suggest-only"
    posture documented in
    project_sca_dependabot_plus_plus.md).
    """
    now = now or datetime.now(timezone.utc)
    candidates, skipped = _enumerate_candidates(
        target, http=http, cache=cache, github_token=github_token,
    )
    results: List[BumpResult] = []
    for cand in candidates:
        result = _evaluate_one(
            cand,
            pypi_client=pypi_client, npm_client=npm_client,
            now=now,
        )
        if apply and result.verdict == _VERDICT_CLEAN:
            edit = RewriteEdit(
                locator=cand.arg_name,
                old_value=cand.current_version,
                new_value=cand.target_version,
            )
            rewrites = rewrite(cand.file, [edit])
            if rewrites:
                result.rewrite_result = rewrites[0]
        results.append(result)
    return BumpReport(
        target=target,
        candidates=candidates,
        results=results,
        skipped=skipped,
    )


def _enumerate_candidates(
    target: Path,
    *,
    http,
    cache,
    github_token: Optional[str],
) -> Tuple[List[BumpCandidate], List[Tuple[str, Path, str]]]:
    """Find every (Dockerfile, ARG) pair under ``target`` with a
    built-in upstream-source mapping, query the upstream, and
    build a candidate list."""
    from core.upstream_latest.github_releases import (
        NoStableVersionsFound,
        UpstreamLookupError,
        latest_release,
        latest_tag,
    )
    candidates: List[BumpCandidate] = []
    skipped: List[Tuple[str, Path, str]] = []
    target = target.resolve()
    if not target.exists():
        return candidates, skipped
    dockerfiles = _find_dockerfiles(target)
    # Cache upstream lookups per (kind, coordinate) — multiple
    # Dockerfiles may pin the same tool.
    latest_cache: dict = {}
    for dockerfile in dockerfiles:
        try:
            text = dockerfile.read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("sca.bump: read failed for %s: %s",
                            dockerfile, e)
            continue
        for line in text.splitlines():
            match = _ARG_RE.match(line)
            if match is None:
                continue
            arg_name = match.group(1)
            current = match.group(2).strip('"').strip("'")
            upstream = lookup_upstream(arg_name)
            if upstream is None:
                # No upstream source — silent skip (operator can
                # add via the inline-comment override path).
                continue
            cache_key = (upstream.kind, upstream.coordinate)
            if cache_key in latest_cache:
                target_version = latest_cache[cache_key]
            else:
                try:
                    if upstream.kind == "github_release":
                        raw = latest_release(
                            upstream.coordinate,
                            http=http, cache=cache,
                            github_token=github_token,
                        )
                    elif upstream.kind == "github_tag":
                        raw = latest_tag(
                            upstream.coordinate,
                            http=http, cache=cache,
                            github_token=github_token,
                        )
                    else:
                        raw = None
                except (UpstreamLookupError, NoStableVersionsFound) as e:
                    skipped.append(
                        (arg_name, dockerfile,
                         f"upstream lookup failed: {e}")
                    )
                    latest_cache[cache_key] = None
                    continue
                target_version = (raw or "").lstrip("v")
                latest_cache[cache_key] = target_version
            if not target_version:
                skipped.append(
                    (arg_name, dockerfile, "no upstream version")
                )
                continue
            if target_version == current:
                # Already at latest — not a bump candidate.
                continue
            candidates.append(BumpCandidate(
                arg_name=arg_name,
                file=dockerfile,
                current_version=current,
                target_version=target_version,
                upstream=upstream,
            ))
    return candidates, skipped


def _evaluate_one(
    cand: BumpCandidate,
    *,
    pypi_client: Optional[PyPIClient],
    npm_client: Optional[NpmClient],
    now: datetime,
) -> BumpResult:
    """Compute the verdict for one bump candidate."""
    eco_map = _BUILTIN_ARG_MAP.get(cand.arg_name)
    findings: List[SupplyChainFinding] = []
    if eco_map is not None:
        ecosystem, package_name = eco_map
        try:
            findings = evaluate_bump_supply_chain(
                ecosystem=ecosystem, name=package_name,
                current_version=cand.current_version,
                target_version=cand.target_version,
                pypi_client=pypi_client, npm_client=npm_client,
                now=now,
            )
        except Exception as e:                # noqa: BLE001
            return BumpResult(
                candidate=cand,
                verdict=_VERDICT_REVIEW,    # err on the side of human-review
                verdict_label=_VERDICT_LABEL[_VERDICT_REVIEW],
                bump_supply_chain_findings=[],
                error=f"evaluator raised: {e}",
            )
    from ..review import _compute_verdict
    verdict = _compute_verdict(
        vuln_findings=[],
        typo_findings=[],
        bump_supply_chain_findings=findings,
    )
    return BumpResult(
        candidate=cand,
        verdict=verdict,
        verdict_label=_VERDICT_LABEL.get(verdict, str(verdict)),
        bump_supply_chain_findings=findings,
    )


def _find_dockerfiles(target: Path) -> List[Path]:
    """Walk ``target`` for files the Dockerfile-ARG rewriter
    knows how to handle. Mirrors the inline-installs parser's
    discovery predicate so the bumper sees every ARG-bearing
    file that the rest of SCA does."""
    if target.is_file():
        return [target] if _is_dockerfile(target) else []
    out: List[Path] = []
    for path in target.rglob("*"):
        if path.is_file() and _is_dockerfile(path):
            out.append(path)
    return sorted(out)


def _is_dockerfile(path: Path) -> bool:
    name = path.name
    if name in ("Dockerfile", "Containerfile"):
        return True
    if name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return True
    if path.suffix == ".dockerfile":
        return True
    return False


def render_report(report: BumpReport) -> str:
    """Operator-readable table summarising the bump report.

    Format chosen for terminal-readability; the bumper CLI prints
    it to stdout. PR-comment rendering is a separate codepath
    (the existing ``diff --pr-comment`` machinery, when wired in
    a future commit)."""
    lines: List[str] = []
    lines.append(f"raptor-sca bump: target {report.target}")
    if not report.candidates and not report.skipped:
        lines.append("  no bump candidates found")
        return "\n".join(lines) + "\n"
    if report.candidates:
        lines.append("")
        lines.append(
            f"  {'ARG':<28} {'Current':<14} {'Target':<14} {'Verdict':<8} Result"
        )
        for r in report.results:
            applied = ""
            if r.rewrite_result is not None:
                applied = (
                    "applied" if r.rewrite_result.applied
                    else f"skipped ({r.rewrite_result.reason})"
                )
            elif r.error:
                applied = f"error: {r.error}"
            lines.append(
                f"  {r.candidate.arg_name:<28} "
                f"{r.candidate.current_version:<14} "
                f"{r.candidate.target_version:<14} "
                f"{r.verdict_label:<8} {applied}"
            )
            # Surface the supply-chain findings inline so operators
            # know WHY a verdict isn't Clean.
            for sf in r.bump_supply_chain_findings:
                lines.append(f"      [{sf.severity}] {sf.kind}: {sf.detail}")
    if report.skipped:
        lines.append("")
        lines.append("  Skipped:")
        for arg, path, reason in report.skipped:
            lines.append(
                f"    {arg} ({path.name}): {reason}"
            )
    return "\n".join(lines) + "\n"
