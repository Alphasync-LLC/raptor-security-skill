"""Tests for ``packages.source_intel.analyze``.

Covers skip-silent paths, parse logic, alias-scan augmentation, and
a real-spatch E2E test that exercises the shipped
``attr_warn_unused_result.cocci`` rule against a tiny C fixture.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packages.source_intel.analyze import (
    SCHEMA_VERSION,
    SourceIntelResult,
    WurEvidence,
    _parse_match_to_wur,
    _scan_alias_in_file,
    analyze,
)


# =====================================================================
# Data shape invariants
# =====================================================================


def test_default_result_is_safe_default():
    r = SourceIntelResult()
    assert r.schema_version == SCHEMA_VERSION
    assert r.target == ""
    assert r.rules_executed == ()
    assert r.rules_failed == ()
    assert r.wur_functions == ()
    assert r.skipped_reason is None
    assert r.is_skipped is False


def test_skipped_marks_is_skipped():
    r = SourceIntelResult(skipped_reason="spatch_not_available")
    assert r.is_skipped is True


def test_function_has_wur_returns_observation():
    ev = WurEvidence(
        function_name="foo",
        location=("a.c", 10),
        match_source="literal",
        raw_match="__attribute__((warn_unused_result))",
    )
    r = SourceIntelResult(attributes=(ev,))
    assert r.function_has_wur("foo") is ev
    assert r.function_has_wur("bar") is None


# =====================================================================
# Skip paths
# =====================================================================


def test_analyze_skips_when_spatch_missing(tmp_path):
    (tmp_path / "x.c").write_text("int main(void){return 0;}\n")
    with patch(
        "packages.coccinelle.runner.is_available",
        return_value=False,
    ):
        r = analyze(tmp_path)
    assert r.skipped_reason == "spatch_not_available"


def test_analyze_skips_for_pure_python_target(tmp_path):
    (tmp_path / "app.py").write_text("# python only\n")
    with patch(
        "packages.coccinelle.runner.is_available",
        return_value=True,
    ):
        r = analyze(tmp_path)
    assert r.skipped_reason == "no_c_cpp_source"


def test_analyze_skips_when_rules_dir_missing(tmp_path):
    (tmp_path / "x.c").write_text("int main(void){return 0;}\n")
    with patch(
        "packages.coccinelle.runner.is_available",
        return_value=True,
    ), patch(
        "packages.source_intel.analyze._shipped_rules_root",
        return_value=None,
    ):
        r = analyze(tmp_path)
    assert r.skipped_reason == "rules_dir_missing"


def test_analyze_accepts_single_c_file_target(tmp_path):
    """Single-file target — common when scanning a fixture sample."""
    src = tmp_path / "single.c"
    src.write_text("int main(void){return 0;}\n")
    with patch(
        "packages.coccinelle.runner.is_available",
        return_value=False,  # short-circuit before spatch call
    ):
        r = analyze(src)
    # The reason is spatch_not_available — meaning we DID get past
    # the C-source check on the single-file path.
    assert r.skipped_reason == "spatch_not_available"


# =====================================================================
# Match parsing
# =====================================================================


def _make_match(file_path: str, line: int, message: str):
    m = MagicMock()
    m.file = file_path
    m.line = line
    m.message = message
    return m


def test_parse_match_extracts_wur_from_message():
    m = _make_match("src/a.c", 42, "wur:my_func")
    evs = _parse_match_to_wur(m)
    assert len(evs) == 1
    assert evs[0].function_name == "my_func"
    assert evs[0].location == ("src/a.c", 42)
    assert evs[0].match_source == "literal"


def test_parse_match_ignores_non_wur_messages():
    m = _make_match("src/a.c", 1, "alloc:other_data")
    assert _parse_match_to_wur(m) == []


def test_parse_match_ignores_empty_wur_payload():
    m = _make_match("src/a.c", 1, "wur:")
    assert _parse_match_to_wur(m) == []


# =====================================================================
# Alias scanning
# =====================================================================


def test_alias_scan_finds_kernel_must_check(tmp_path):
    f = tmp_path / "kernel_style.c"
    f.write_text(
        "#include <linux/types.h>\n"
        "static __must_check int validate(int x) { return x > 0; }\n"
    )
    observations = _scan_alias_in_file(f)
    assert len(observations) == 1
    assert observations[0].match_source == "known_alias"
    assert observations[0].raw_match == "__must_check"
    # Function-name attribution is best-effort — empty per docstring.
    assert observations[0].function_name == ""


def test_alias_scan_finds_cpp_nodiscard(tmp_path):
    f = tmp_path / "cpp_style.cpp"
    f.write_text(
        "[[nodiscard]] int compute(int x) { return x; }\n"
    )
    observations = _scan_alias_in_file(f)
    assert len(observations) == 1
    assert observations[0].raw_match == "[[nodiscard]]"


def test_alias_scan_emits_one_observation_per_distinct_spelling(tmp_path):
    """Two different alias spellings → two observations (because each
    may apply to a different function)."""
    f = tmp_path / "mixed.c"
    f.write_text(
        "static __must_check int a(void) { return 0; }\n"
        "static __wur int b(void) { return 0; }\n"
    )
    observations = _scan_alias_in_file(f)
    spellings = {o.raw_match for o in observations}
    assert spellings == {"__must_check", "__wur"}


def test_alias_scan_skips_non_c_files(tmp_path):
    """Best-effort scan only walks C/H files."""
    py = tmp_path / "ignore.py"
    py.write_text("# __must_check this should be ignored\n")
    from packages.source_intel.analyze import _scan_alias_observations
    observations = _scan_alias_observations(tmp_path)
    assert observations == []


# =====================================================================
# Real-spatch E2E
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_real_spatch_detects_literal_wur(tmp_path):
    """End-to-end: real spatch runs the shipped attr_warn_unused_result
    rule against a small C file with a literal GCC attribute. Pin
    against rule-corpus drift."""
    src = tmp_path / "literal.c"
    src.write_text(
        "#include <stddef.h>\n"
        "__attribute__((warn_unused_result))\n"
        "int alloc_thing(size_t sz);\n"
    )

    r = analyze(tmp_path)
    assert not r.is_skipped, (
        f"expected real spatch to produce facts; got skipped_reason="
        f"{r.skipped_reason!r}"
    )
    # The cocci rule should emit ``wur:alloc_thing`` for the function.
    function_names = {
        ev.function_name for ev in r.wur_functions
        if ev.match_source == "literal"
    }
    assert "alloc_thing" in function_names, (
        f"attr_warn_unused_result rule didn't fire on literal "
        f"GCC syntax; got: {list(r.wur_functions)!r}"
    )


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_real_spatch_detects_literal_nonnull(tmp_path):
    """End-to-end: real spatch runs the shipped attr_nonnull rule
    against a small C file with nonnull declarations in three forms
    (bare, paramised, internal-alias). Pin against rule-corpus drift
    and the multi-variant disjunction in the cocci rule."""
    src = tmp_path / "nonnull_fixture.c"
    src.write_text(
        "__attribute__((nonnull)) int bare(int *p);\n"
        "__attribute__((nonnull(1))) int paramised(int *p, int q);\n"
        "__attribute__((__nonnull__(1, 2))) int internal(int *a, int *b);\n"
    )

    r = analyze(tmp_path)
    assert not r.is_skipped
    from packages.source_intel.analyze import KIND_NONNULL
    nn_obs = r.attrs_of_kind(KIND_NONNULL)
    names = {ev.function_name for ev in nn_obs if ev.match_source == "literal"}
    assert names == {"bare", "paramised", "internal"}, (
        f"attr_nonnull rule didn't fire on all three forms; "
        f"got: {names!r}"
    )


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_axis_dispatch_runs_multiple_rules(tmp_path):
    """When the target has both WUR and nonnull annotations, BOTH
    rules in the attrs/ axis fire — confirms the axis-dir iteration
    correctly drives all rules per axis."""
    src = tmp_path / "mixed.c"
    src.write_text(
        "__attribute__((warn_unused_result)) int alloc(int sz);\n"
        "__attribute__((nonnull)) int validate(int *p);\n"
    )

    r = analyze(tmp_path)
    from packages.source_intel.analyze import KIND_NONNULL, KIND_WUR
    wur_names = {
        ev.function_name for ev in r.attrs_of_kind(KIND_WUR)
        if ev.match_source == "literal"
    }
    nn_names = {
        ev.function_name for ev in r.attrs_of_kind(KIND_NONNULL)
        if ev.match_source == "literal"
    }
    assert "alloc" in wur_names
    assert "validate" in nn_names
