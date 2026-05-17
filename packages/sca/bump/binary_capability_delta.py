"""Binary capability-delta supply-chain detector.

When a dep bumps from version X to version Y and the deliverable is
a *binary artifact* (Docker FROM layer, GHA Docker-action image,
pre-built binary release pin), the source diff isn't the right
signal — the payload is in the binary, not the source tree. This
detector runs :mod:`packages.binary_analysis.radare2_understand`
against both the current and target binaries, diffs their
capability surfaces, and emits a :class:`SupplyChainFinding` when
the target adds dangerous capabilities the current didn't have.

What's a "capability"? Two signals:

  * **Dangerous imports** — ``execve`` / ``recv`` / ``CreateProcess``
    / etc. The shared :mod:`core.function_taxonomy` defines the
    high-CVE-density buckets (exec, network, format-string,
    parser, etc.); the detector treats *any new entry* in those
    buckets as a capability addition.
  * **Reachable dangerous sinks** — functions in the binary that
    cross-reference any dangerous import. A new sink means the
    binary has new *code* that uses a dangerous capability, even
    if the import list looks unchanged.

Severity ladder
  * Adds *exec* capability → ``high``  (RCE-flavoured)
  * Adds *network ingestion* capability → ``high`` (exfil-flavoured)
  * Adds any other dangerous capability → ``medium``

Out of scope
  * Path resolution: callers supply already-extracted current /
    target binary paths (Docker layer extraction, OCI pull,
    release-artifact download). The detector is pure-comparison.
  * Removed capabilities: a bump that *drops* a dangerous import
    is rarely a red flag (often a security improvement). The
    detector ignores removals.
  * Source-only ecosystems: npm / PyPI / Cargo's payload is in the
    source tree; source-diff signals (install_hook_delta, etc.)
    cover those. The detector's natural callers are
    Dockerfile-FROM bumps, GHA Docker-action bumps, and binary-
    artifact pins.

Co-Authored-By: Natalie Somersall <natalie.somersall@gmail.com>
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.function_taxonomy import (
    ALLOC_FUNCS,
    EXEC_FUNCS,
    FORMAT_STRING_FUNCS,
    INTEGER_PARSE_FUNCS,
    MEMORY_COPY_FUNCS,
    NETWORK_INGEST_FUNCS,
    PARSER_FUNCS,
    SCAN_FAMILY_FUNCS,
    STRING_OVERFLOW_FUNCS,
    TOCTOU_FUNCS,
)
from ..models import (
    Confidence,
    Dependency,
    PinStyle,
    Severity,
    SupplyChainFinding,
)

logger = logging.getLogger(__name__)


# Per-bucket capability classification — the keys are the severity
# escalator. ``exec`` and ``network`` trigger ``high``; the rest
# trigger ``medium``.
_BUCKETS: Tuple[Tuple[str, frozenset], ...] = (
    ("exec", EXEC_FUNCS),
    ("network", NETWORK_INGEST_FUNCS),
    ("string_overflow", STRING_OVERFLOW_FUNCS),
    ("scan", SCAN_FAMILY_FUNCS),
    ("memory_copy", MEMORY_COPY_FUNCS),
    ("format_string", FORMAT_STRING_FUNCS),
    ("alloc", ALLOC_FUNCS),
    ("parser", PARSER_FUNCS),
    ("integer_parse", INTEGER_PARSE_FUNCS),
    ("toctou", TOCTOU_FUNCS),
)

_HIGH_SEVERITY_BUCKETS: frozenset = frozenset({"exec", "network"})


@dataclass
class CapabilityDelta:
    """Capability-surface diff between two binaries.

    ``new_dangerous_imports`` — imports in target that weren't in
    current. Keys: bucket name (e.g. ``"exec"``); values: sorted
    list of newly-added function names in that bucket. Only buckets
    with additions appear.

    ``new_dangerous_sinks`` — function names in target's reachable
    dangerous-sink set that weren't in current's. Sorted.

    ``current_path`` / ``target_path`` — the binaries that were
    compared. Useful for evidence-rendering.
    """

    new_dangerous_imports: Dict[str, List[str]] = field(default_factory=dict)
    new_dangerous_sinks: List[str] = field(default_factory=list)
    current_path: Optional[Path] = None
    target_path: Optional[Path] = None

    def is_empty(self) -> bool:
        """True when target adds no capabilities current didn't have."""
        return (
            not self.new_dangerous_imports
            and not self.new_dangerous_sinks
        )

    def high_severity(self) -> bool:
        """True when any added bucket is exec or network."""
        return any(
            bucket in _HIGH_SEVERITY_BUCKETS
            for bucket in self.new_dangerous_imports
        )

    def added_buckets(self) -> List[str]:
        """Sorted list of bucket names with new entries."""
        return sorted(self.new_dangerous_imports.keys())


def _bucket_imports(
    imports: Set[str],
) -> Dict[str, Set[str]]:
    """Classify a binary's import set by capability bucket.

    Returns a dict of ``{bucket_name: {fn1, fn2, ...}}`` for each
    bucket that has at least one matching import. Imports outside
    the high-CVE-density taxonomy buckets are intentionally
    dropped — ubiquitous functions like ``malloc`` / ``printf`` /
    ``read`` aren't signal.
    """
    out: Dict[str, Set[str]] = {}
    for bucket_name, fn_set in _BUCKETS:
        matched = imports & fn_set
        if matched:
            out[bucket_name] = matched
    return out


def diff_binary_capabilities(
    current_binary: Path,
    target_binary: Path,
    *,
    max_decompile: int = 0,
    max_strings: int = 0,
) -> Optional[CapabilityDelta]:
    """Compare two binaries' capability surfaces.

    ``max_decompile=0`` / ``max_strings=0`` keep the comparison fast
    — decompilation and string extraction don't affect the
    dangerous-import / dangerous-sink sets we diff against.

    Returns ``None`` when:
      * radare2 isn't available on the host
      * either binary can't be analysed (corrupt / unsupported
        format / read failure)

    Returns an *empty* :class:`CapabilityDelta` (``is_empty()``)
    when both binaries analyse cleanly but target adds nothing
    new — the caller can distinguish "couldn't compare" from "no
    change" via the None return vs empty-delta distinction.
    """
    try:
        from packages.binary_analysis.radare2_understand import (
            analyse_binary_context,
            probe_capability,
        )
    except ImportError:
        logger.debug(
            "sca.bump.binary_capability_delta: binary_analysis "
            "package not importable; skipping detector",
        )
        return None

    cap = probe_capability()
    if not cap.get("available"):
        logger.debug(
            "sca.bump.binary_capability_delta: radare2 not "
            "available (%s); skipping detector",
            cap.get("reason", "<no reason>"),
        )
        return None

    current_ctx = _safe_analyse(
        analyse_binary_context, current_binary,
        max_decompile=max_decompile, max_strings=max_strings,
    )
    if current_ctx is None:
        return None
    target_ctx = _safe_analyse(
        analyse_binary_context, target_binary,
        max_decompile=max_decompile, max_strings=max_strings,
    )
    if target_ctx is None:
        return None

    current_buckets = _bucket_imports(set(current_ctx.imports))
    target_buckets = _bucket_imports(set(target_ctx.imports))

    new_imports: Dict[str, List[str]] = {}
    for bucket_name, target_fns in target_buckets.items():
        added = target_fns - current_buckets.get(bucket_name, set())
        if added:
            new_imports[bucket_name] = sorted(added)

    current_sinks = {f.name for f in current_ctx.dangerous_sinks}
    target_sinks = {f.name for f in target_ctx.dangerous_sinks}
    new_sinks = sorted(target_sinks - current_sinks)

    return CapabilityDelta(
        new_dangerous_imports=new_imports,
        new_dangerous_sinks=new_sinks,
        current_path=current_binary,
        target_path=target_binary,
    )


def _safe_analyse(
    analyser, binary_path: Path, *,
    max_decompile: int, max_strings: int,
):
    """Wrap ``analyse_binary_context`` so a failure on one binary
    doesn't crash the bumper. Logs and returns None."""
    try:
        return analyser(
            binary_path,
            max_decompile=max_decompile,
            max_strings=max_strings,
        )
    except Exception as exc:                          # noqa: BLE001
        logger.warning(
            "sca.bump.binary_capability_delta: analyse_binary_context "
            "failed on %s: %s",
            binary_path, exc,
        )
        return None


def binary_capability_delta_finding(
    *,
    ecosystem: str,
    name: str,
    current_version: str,
    target_version: str,
    current_binary: Path,
    target_binary: Path,
) -> Optional[SupplyChainFinding]:
    """Run the capability diff and wrap a finding when target adds
    dangerous capabilities. Returns ``None`` when:

      * radare2 unavailable / binaries unanalysable (detector
        gracefully skipped)
      * no new dangerous capabilities (empty delta)
    """
    delta = diff_binary_capabilities(current_binary, target_binary)
    if delta is None or delta.is_empty():
        return None

    severity: Severity = "high" if delta.high_severity() else "medium"
    buckets_added = delta.added_buckets()
    detail_parts: List[str] = []
    if buckets_added:
        detail_parts.append(
            "new dangerous-import buckets: "
            + ", ".join(buckets_added)
        )
    if delta.new_dangerous_sinks:
        sink_preview = ", ".join(delta.new_dangerous_sinks[:5])
        more = len(delta.new_dangerous_sinks) - 5
        if more > 0:
            sink_preview += f" (+{more} more)"
        detail_parts.append(f"new reachable sinks: {sink_preview}")
    detail = "; ".join(detail_parts)

    placeholder_dep = Dependency(
        ecosystem=ecosystem,
        name=name,
        version=target_version,
        declared_in=Path("/<bump>"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{target_version}",
        parser_confidence=Confidence(
            "high",
            reason="bump-evaluator synthetic dep",
        ),
    )

    evidence: Dict[str, Any] = {
        "current_version": current_version,
        "target_version": target_version,
        "current_binary": str(current_binary),
        "target_binary": str(target_binary),
        "new_dangerous_imports": delta.new_dangerous_imports,
        "new_dangerous_sinks": delta.new_dangerous_sinks,
        "added_buckets": buckets_added,
    }

    return SupplyChainFinding(
        finding_id=(
            f"sca:bump:binary_capability_delta:"
            f"{ecosystem}:{name}@{target_version}"
        ),
        kind="binary_capability_delta",
        dependency=placeholder_dep,
        detail=detail or "target binary adds dangerous capabilities",
        evidence=evidence,
        severity=severity,
        confidence=Confidence(
            "medium",
            reason=(
                "radare2 import + cross-ref analysis; "
                "static signal only, no runtime confirmation"
            ),
        ),
    )


__all__ = [
    "CapabilityDelta",
    "diff_binary_capabilities",
    "binary_capability_delta_finding",
]
