"""Render :class:`SourceIntelResult` evidence into prompt-friendly
strings for Stage D / `/exploit` / `/agentic` consumers.

The output is a list of human-readable lines; ordering puts the
strongest signal first (literal observations before alias-only).
Consumers concatenate the lines into a structured block under
TaintedString / UntrustedBlock envelopes per the project's prompt-
envelope discipline.

Three styles surfaced in Phase 2:
  * ``stage_d`` — evidence supporting/against a Stage D ruling
  * ``exploit_plan`` — constraints to plan around for /exploit
  * ``agentic_variant`` — seed candidates for variant hunting

For substrate, all three render the same content with style-specific
phrasing. Axes 2-7 may diverge per style when their evidence
classes have distinct interpretations per consumer.
"""

from __future__ import annotations

from typing import List, Optional

from core.build.build_flags import BuildFlagsContext
from packages.source_intel.analyze import (
    KIND_NONNULL,
    KIND_WUR,
    AttributeEvidence,
    SourceIntelResult,
)


_STYLES = ("stage_d", "exploit_plan", "agentic_variant")


def derive_evidence_strings(
    result: SourceIntelResult,
    finding_function: Optional[str] = None,
    build_flags: Optional[BuildFlagsContext] = None,
    style: str = "stage_d",
    max_lines: Optional[int] = None,
) -> List[str]:
    """Render source_intel evidence for a finding into prompt lines.

    Args:
      result: the per-target SourceIntelResult
      finding_function: the function the finding cites (used to filter
        WUR evidence to relevant functions; when None, all observations
        surface)
      build_flags: per-target build-flag context (for compile-enforcement
        interpretation of WUR — `__must_check` is binding only if
        `-Werror=unused-result` was on)
      style: "stage_d" | "exploit_plan" | "agentic_variant" — chooses
        framing. Substrate ships identical content per style; axis-N
        PRs can diverge.
      max_lines: cap the number of returned lines (for context-tight
        prompt budgets); None = no cap.

    Returns an empty list when the result is skipped or carries no
    relevant evidence — consumers can render "no source_intel signal"
    or omit the block entirely.
    """
    if style not in _STYLES:
        raise ValueError(f"unknown style: {style!r} (expected one of {_STYLES})")

    lines: List[str] = []

    if result.is_skipped:
        # Surface the skip reason so consumers know there was no
        # evidence at all — distinct from "evidence ran and found
        # nothing." This is critical: consumers MUST NOT interpret
        # an empty block as "unhardened".
        lines.append(
            f"Source_intel skipped: {result.skipped_reason}. "
            f"No evidence either way."
        )
        return _truncate(lines, max_lines)

    # Filter to the finding's function when supplied.
    observations = list(result.attributes)
    if finding_function:
        observations = [
            ev for ev in observations
            if ev.function_name == finding_function
        ]
    # Literal observations first, then known-alias.
    observations.sort(key=lambda ev: 0 if ev.match_source == "literal" else 1)

    for ev in observations:
        line = _render_attribute_line(ev, build_flags, style)
        if line is not None:
            lines.append(line)

    # When source_intel ran but found nothing relevant — emit an
    # explicit "no signal" line so the consumer prompt template
    # carries the absence acknowledgement.
    if not lines:
        lines.append(
            "Source_intel ran; no attribute evidence for "
            f"{finding_function or '<finding function>'}. "
            f"Absence of evidence is NOT evidence of unhardened code."
        )

    return _truncate(lines, max_lines)


def _render_attribute_line(
    ev: AttributeEvidence,
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> Optional[str]:
    """Dispatch to the per-kind renderer. Unknown kinds return None
    (silently dropped — render is best-effort)."""
    if ev.kind == KIND_WUR:
        return _render_wur_line(ev, build_flags, style)
    if ev.kind == KIND_NONNULL:
        return _render_nonnull_line(ev, build_flags, style)
    return None


# =====================================================================
# Per-evidence-kind line builders
# =====================================================================


def _render_wur_line(
    ev: AttributeEvidence,
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> str:
    """One line of WUR evidence, framed per consumer style.

    The enforcement-status caveat depends on build flags:
      * `-Werror=unused-result` known True → "compile-enforced"
      * `-Werror=unused-result` known False → "author intent only;
        warning was suppressed"
      * None / build_flags absent → "advisory; enforcement depends
        on build flags not in evidence"
    """
    fn_text = (
        f"function `{ev.function_name}`"
        if ev.function_name
        else f"function in {ev.location[0]} at line {ev.location[1]}"
    )
    src_text = (
        "literal __attribute__((warn_unused_result))"
        if ev.match_source == "literal"
        else f"known alias `{ev.raw_match}`"
    )

    enforcement = _enforcement_phrase(build_flags)

    if style == "stage_d":
        prefix = "Author intent — must-check contract"
    elif style == "exploit_plan":
        prefix = "Constraint — caller-must-check contract"
    else:  # agentic_variant
        prefix = "Variant hint — must-check signal"

    return (
        f"{prefix}: {fn_text} annotated as warn_unused_result via "
        f"{src_text}. {enforcement}"
    )


def _render_nonnull_line(
    ev: AttributeEvidence,
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> str:
    """Render nonnull evidence.

    Nonnull is a TWO-EDGED signal for memory corruption:
      * Author intent — caller MUST pass non-null pointers.
      * Compiler behaviour — when -O2+ AND -fdelete-null-pointer-checks
        is ON (GCC userspace default), the compiler may eliminate
        redundant null-checks inside the annotated function. A real
        NULL reaching the function then dereferences without the
        defensive branch the author may have written.
      * In the kernel, -fno-delete-null-pointer-checks is in CFLAGS
        since 4.9, so the elimination doesn't happen — defensive null
        checks are preserved.

    The Stage D consumer reads this evidence WITH the build-flag
    context to determine effective semantics.
    """
    fn_text = (
        f"function `{ev.function_name}`"
        if ev.function_name
        else f"function in {ev.location[0]} at line {ev.location[1]}"
    )

    null_check_phrase = _nonnull_null_check_phrase(build_flags)

    if style == "stage_d":
        prefix = "Author intent + compiler signal — nonnull"
    elif style == "exploit_plan":
        prefix = "Constraint — caller-must-be-non-null contract"
    else:
        prefix = "Variant hint — nonnull annotation"

    return (
        f"{prefix}: {fn_text} annotated nonnull (caller must pass "
        f"non-null). {null_check_phrase}"
    )


def _nonnull_null_check_phrase(build_flags: Optional[BuildFlagsContext]) -> str:
    """Compose the dead-code-elimination caveat for nonnull."""
    if build_flags is None or build_flags.extraction_confidence == "absent":
        return (
            "Compiler-elimination status unknown (build flags not in "
            "evidence); a NULL reaching this function may be more or "
            "less exploitable depending on -fdelete-null-pointer-checks."
        )
    if build_flags.delete_null_pointer_checks is False:
        return (
            "Build flags include -fno-delete-null-pointer-checks — "
            "defensive null checks inside the function are preserved; "
            "any NULL dereference behaves as the source code shows."
        )
    if build_flags.delete_null_pointer_checks is True:
        return (
            "Build flags explicitly enable -fdelete-null-pointer-checks "
            "— compiler may dead-code-eliminate redundant null checks "
            "inside the function; a real NULL would reach the deref."
        )
    return (
        "Compiler-elimination status not pinned by observed flags — "
        "default depends on -O level and compiler version."
    )


def _enforcement_phrase(build_flags: Optional[BuildFlagsContext]) -> str:
    """Compose the compile-enforcement caveat from build flag context."""
    if build_flags is None or build_flags.extraction_confidence == "absent":
        return (
            "Compile-enforcement status unknown (build flags not in "
            "evidence); advisory only."
        )
    if build_flags.werror_unused_result is True:
        return (
            "Build flags include -Werror=unused-result — "
            "compile-enforced; callers that ignore the return "
            "would not compile."
        )
    if build_flags.werror_unused_result is False:
        return (
            "Build flags include -Wno-error=unused-result — "
            "warning suppressed; advisory only."
        )
    return (
        "Build flags observed but -Werror=unused-result not set; "
        "advisory unless -Werror is added."
    )


# =====================================================================
# Helpers
# =====================================================================


def _truncate(lines: List[str], max_lines: Optional[int]) -> List[str]:
    """Cap line count for tight prompt budgets."""
    if max_lines is None or len(lines) <= max_lines:
        return lines
    return lines[:max_lines]
