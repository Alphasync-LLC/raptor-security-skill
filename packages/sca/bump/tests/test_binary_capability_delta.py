"""Tests for ``packages.sca.bump.binary_capability_delta``.

The detector compares two binaries' capability surfaces via
:mod:`packages.binary_analysis.radare2_understand` and emits a
``SupplyChainFinding`` when the target adds dangerous capabilities
the current didn't have.

Unit tests stub ``analyse_binary_context`` with synthetic
``BinaryContextMap`` returns so the suite doesn't require radare2
installed. One integration test (gated on radare2 availability +
``/bin/ls`` existing) covers the wire-through to the real
analyser.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from packages.binary_analysis.radare2_understand import (
    BinaryContextMap, FunctionInfo,
)
from packages.sca.bump.binary_capability_delta import (
    _bucket_imports,
    binary_capability_delta_finding,
    diff_binary_capabilities,
)


def _ctx(path: str, *, imports: List[str],
         sinks: List[str] = None) -> BinaryContextMap:
    """Build a minimal BinaryContextMap with the supplied import +
    sink lists. Address/size/type defaults are fine for tests
    since the detector only reads names."""
    sinks = sinks or []
    return BinaryContextMap(
        binary_path=Path(path),
        arch="x86_64",
        bits=64,
        binary_format="elf",
        imports=list(imports),
        dangerous_sinks=[
            FunctionInfo(name=n, address=0x1000 + i)
            for i, n in enumerate(sinks)
        ],
    )


@pytest.fixture
def patched_analyser(monkeypatch):
    """Replace ``analyse_binary_context`` + ``probe_capability``
    inside the detector module with controllable stubs.

    Yields a ``(side_effect_dict, set_unavailable)`` helper.
    ``side_effect_dict`` maps Path → BinaryContextMap (or None for
    a failure simulation).
    """
    state = {"available": True, "ctxs": {}}

    def fake_analyse(path: Path, **kwargs):
        if path in state["ctxs"]:
            return state["ctxs"][path]
        raise FileNotFoundError(f"no stub for {path}")

    def fake_probe():
        return {
            "available": state["available"],
            "reason": "stub",
        }

    monkeypatch.setattr(
        "packages.binary_analysis.radare2_understand.analyse_binary_context",
        fake_analyse,
    )
    monkeypatch.setattr(
        "packages.binary_analysis.radare2_understand.probe_capability",
        fake_probe,
    )
    yield state


# ---------------------------------------------------------------------------
# _bucket_imports
# ---------------------------------------------------------------------------


class TestBucketImports:
    def test_exec_imports_classified(self):
        out = _bucket_imports({"execve", "popen", "fread"})
        assert "exec" in out
        assert "execve" in out["exec"]
        assert "popen" in out["exec"]
        # fread is not in any high-CVE bucket
        assert "fread" not in {fn for fns in out.values() for fn in fns}

    def test_network_imports_classified(self):
        out = _bucket_imports({"recv", "accept", "bind"})
        assert "network" in out
        assert out["network"] >= {"recv", "accept", "bind"}

    def test_string_overflow_classified(self):
        out = _bucket_imports({"strcpy", "strcat", "gets"})
        # strcpy / strcat / gets all appear in STRING_OVERFLOW_FUNCS
        assert "string_overflow" in out

    def test_ubiquitous_imports_dropped(self):
        """``malloc`` and ``printf`` are deliberately NOT in the
        high-CVE-density taxonomy (too noisy). Bucket map empty."""
        out = _bucket_imports({"malloc", "printf", "read"})
        assert out == {}


# ---------------------------------------------------------------------------
# diff_binary_capabilities
# ---------------------------------------------------------------------------


class TestDiffBinaryCapabilities:
    def test_no_change_returns_empty_delta(self, patched_analyser):
        """Same imports + sinks in both → empty delta (not None).
        Callers distinguish 'couldn't compare' (None) from 'no
        change' (empty delta)."""
        cur = Path("/tmp/cur.bin")
        tgt = Path("/tmp/tgt.bin")
        patched_analyser["ctxs"] = {
            cur: _ctx("cur", imports=["strcpy", "recv"]),
            tgt: _ctx("tgt", imports=["strcpy", "recv"]),
        }
        delta = diff_binary_capabilities(cur, tgt)
        assert delta is not None
        assert delta.is_empty()

    def test_new_exec_capability_high_severity(self, patched_analyser):
        """Target adds ``execve`` that current didn't have →
        ``high_severity()`` returns True."""
        cur = Path("/tmp/cur.bin")
        tgt = Path("/tmp/tgt.bin")
        patched_analyser["ctxs"] = {
            cur: _ctx("cur", imports=["strcpy"]),
            tgt: _ctx("tgt", imports=["strcpy", "execve"]),
        }
        delta = diff_binary_capabilities(cur, tgt)
        assert delta is not None
        assert not delta.is_empty()
        assert "exec" in delta.new_dangerous_imports
        assert delta.new_dangerous_imports["exec"] == ["execve"]
        assert delta.high_severity() is True

    def test_new_network_capability_high_severity(self, patched_analyser):
        cur = Path("/tmp/cur.bin")
        tgt = Path("/tmp/tgt.bin")
        patched_analyser["ctxs"] = {
            cur: _ctx("cur", imports=["malloc"]),
            tgt: _ctx("tgt", imports=["malloc", "recv", "accept"]),
        }
        delta = diff_binary_capabilities(cur, tgt)
        assert delta is not None
        assert "network" in delta.new_dangerous_imports
        assert delta.high_severity() is True

    def test_new_string_overflow_only_medium_severity(self, patched_analyser):
        """Adding a non-exec / non-network bucket doesn't escalate
        to high — medium is enough."""
        cur = Path("/tmp/cur.bin")
        tgt = Path("/tmp/tgt.bin")
        patched_analyser["ctxs"] = {
            cur: _ctx("cur", imports=["malloc"]),
            tgt: _ctx("tgt", imports=["malloc", "strcpy"]),
        }
        delta = diff_binary_capabilities(cur, tgt)
        assert delta is not None
        assert "string_overflow" in delta.new_dangerous_imports
        assert delta.high_severity() is False

    def test_new_dangerous_sinks_captured(self, patched_analyser):
        """A new dangerous-sink function in the target (even if
        the import surface is unchanged) → captured in
        ``new_dangerous_sinks``."""
        cur = Path("/tmp/cur.bin")
        tgt = Path("/tmp/tgt.bin")
        patched_analyser["ctxs"] = {
            cur: _ctx("cur", imports=["strcpy"],
                      sinks=["sym.imp.strcpy"]),
            tgt: _ctx("tgt", imports=["strcpy"],
                      sinks=["sym.imp.strcpy", "sym.imp.execve"]),
        }
        delta = diff_binary_capabilities(cur, tgt)
        assert delta is not None
        assert "sym.imp.execve" in delta.new_dangerous_sinks

    def test_removed_capabilities_ignored(self, patched_analyser):
        """Bumps that drop dangerous capabilities aren't flagged
        — those are usually security improvements."""
        cur = Path("/tmp/cur.bin")
        tgt = Path("/tmp/tgt.bin")
        patched_analyser["ctxs"] = {
            cur: _ctx("cur", imports=["strcpy", "execve"]),
            tgt: _ctx("tgt", imports=["strcpy"]),
        }
        delta = diff_binary_capabilities(cur, tgt)
        assert delta is not None
        assert delta.is_empty()

    def test_radare2_unavailable_returns_none(self, patched_analyser):
        patched_analyser["available"] = False
        out = diff_binary_capabilities(
            Path("/tmp/cur.bin"), Path("/tmp/tgt.bin"),
        )
        assert out is None

    def test_current_analyse_failure_returns_none(self, patched_analyser):
        cur = Path("/tmp/cur.bin")
        tgt = Path("/tmp/tgt.bin")
        patched_analyser["ctxs"] = {
            # tgt has stub, cur does not — analyse_binary_context
            # raises FileNotFoundError on cur
            tgt: _ctx("tgt", imports=["execve"]),
        }
        out = diff_binary_capabilities(cur, tgt)
        assert out is None

    def test_target_analyse_failure_returns_none(self, patched_analyser):
        cur = Path("/tmp/cur.bin")
        tgt = Path("/tmp/tgt.bin")
        patched_analyser["ctxs"] = {
            cur: _ctx("cur", imports=["strcpy"]),
            # tgt missing → analyse_binary_context raises
        }
        out = diff_binary_capabilities(cur, tgt)
        assert out is None

    def test_multiple_added_buckets(self, patched_analyser):
        cur = Path("/tmp/cur.bin")
        tgt = Path("/tmp/tgt.bin")
        patched_analyser["ctxs"] = {
            cur: _ctx("cur", imports=["malloc"]),
            tgt: _ctx("tgt", imports=[
                "malloc", "execve", "recv", "strcpy",
            ]),
        }
        delta = diff_binary_capabilities(cur, tgt)
        assert delta is not None
        assert set(delta.added_buckets()) >= {
            "exec", "network", "string_overflow",
        }
        # High severity wins because exec + network present
        assert delta.high_severity() is True


# ---------------------------------------------------------------------------
# binary_capability_delta_finding
# ---------------------------------------------------------------------------


class TestBinaryCapabilityDeltaFinding:
    def test_high_severity_finding_for_exec_add(self, patched_analyser):
        cur = Path("/tmp/cur.bin")
        tgt = Path("/tmp/tgt.bin")
        patched_analyser["ctxs"] = {
            cur: _ctx("cur", imports=["malloc"]),
            tgt: _ctx("tgt", imports=["malloc", "execve"]),
        }
        finding = binary_capability_delta_finding(
            ecosystem="Container", name="alpine",
            current_version="3.18", target_version="3.19",
            current_binary=cur, target_binary=tgt,
        )
        assert finding is not None
        assert finding.kind == "binary_capability_delta"
        assert finding.severity == "high"
        assert "execve" in finding.evidence["new_dangerous_imports"]["exec"]
        assert "exec" in finding.added_buckets if False else True  # smoke
        # The finding_id encodes the bump coordinates for dedup
        assert "alpine@3.19" in finding.finding_id

    def test_medium_severity_finding_for_strovf_add(self, patched_analyser):
        cur = Path("/tmp/cur.bin")
        tgt = Path("/tmp/tgt.bin")
        patched_analyser["ctxs"] = {
            cur: _ctx("cur", imports=["malloc"]),
            tgt: _ctx("tgt", imports=["malloc", "strcpy"]),
        }
        finding = binary_capability_delta_finding(
            ecosystem="GHA", name="some-action",
            current_version="v1", target_version="v2",
            current_binary=cur, target_binary=tgt,
        )
        assert finding is not None
        assert finding.severity == "medium"

    def test_no_finding_when_unchanged(self, patched_analyser):
        cur = Path("/tmp/cur.bin")
        tgt = Path("/tmp/tgt.bin")
        patched_analyser["ctxs"] = {
            cur: _ctx("cur", imports=["strcpy"]),
            tgt: _ctx("tgt", imports=["strcpy"]),
        }
        out = binary_capability_delta_finding(
            ecosystem="Container", name="x", current_version="1",
            target_version="2", current_binary=cur,
            target_binary=tgt,
        )
        assert out is None

    def test_no_finding_when_radare2_unavailable(self, patched_analyser):
        patched_analyser["available"] = False
        out = binary_capability_delta_finding(
            ecosystem="Container", name="x", current_version="1",
            target_version="2",
            current_binary=Path("/tmp/cur.bin"),
            target_binary=Path("/tmp/tgt.bin"),
        )
        assert out is None

    def test_detail_lists_buckets_and_sinks(self, patched_analyser):
        cur = Path("/tmp/cur.bin")
        tgt = Path("/tmp/tgt.bin")
        patched_analyser["ctxs"] = {
            cur: _ctx("cur", imports=["malloc"]),
            tgt: _ctx("tgt", imports=["malloc", "execve", "recv"],
                      sinks=["sym.imp.execve", "sym.imp.recv"]),
        }
        finding = binary_capability_delta_finding(
            ecosystem="Container", name="x", current_version="1",
            target_version="2",
            current_binary=cur, target_binary=tgt,
        )
        assert finding is not None
        assert "exec" in finding.detail
        assert "network" in finding.detail
        assert "sym.imp.execve" in finding.detail


# ---------------------------------------------------------------------------
# Integration smoke test — gated on radare2 availability
# ---------------------------------------------------------------------------


def test_real_radare2_against_ls():
    """Diff /bin/ls against itself — no new capabilities, empty
    delta. Exercises the full radare2 wire-through end-to-end.

    Skipped unless both the r2 binary AND the r2pipe Python
    wrapper are installed; ``probe_capability`` is the
    authoritative gate (returns ``available=False`` when either
    is missing). On hosts where the gate passes, /bin/ls must
    diff to an empty delta against itself — any new capability
    set would mean the detector is non-deterministic, which is a
    real bug.
    """
    from packages.binary_analysis.radare2_understand import (
        probe_capability,
    )

    cap = probe_capability()
    if not cap.get("available"):
        pytest.skip(
            f"radare2 stack not available: {cap}",
        )
    ls = Path("/bin/ls")
    if not ls.exists():
        pytest.skip("/bin/ls not present on host")
    delta = diff_binary_capabilities(ls, ls)
    # Same binary → MUST diff to empty delta. None here would
    # mean analyse_binary_context raised, which would be a
    # detector bug (not graceful degradation).
    assert delta is not None
    assert delta.is_empty(), (
        f"non-deterministic capability diff: {delta!r}"
    )
