"""Tests for ``packages.sca.bump.orchestrator``.

End-to-end-ish: stub upstream / registry clients to avoid network,
exercise the candidate enumeration + verdict + apply paths."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from packages.sca.bump.orchestrator import (
    BumpCandidate, BumpReport, BumpResult,
    _VERDICT_BLOCK, _VERDICT_CLEAN, _VERDICT_REVIEW,
    render_report, run_bump,
)


# ---------------------------------------------------------------------------
# Stub HTTP — replies with operator-supplied JSON per URL.
# ---------------------------------------------------------------------------

class _StubResp:
    def __init__(self, body: dict, status=200):
        self._body = body
        self.status_code = status
        self.headers: Dict[str, str] = {}

    @property
    def content(self):
        import json
        return json.dumps(self._body).encode()


class _StubHttp:
    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses

    def get_json(self, url: str, **kw):
        if url in self._responses:
            return self._responses[url]
        from core.http import HttpError
        raise HttpError(f"stub: no payload for {url}")

    def request(self, method, url, **kw):
        if url in self._responses:
            return _StubResp(self._responses[url])
        from core.http import HttpError
        raise HttpError(f"stub: no payload for {url}")


class _StubPyPI:
    def __init__(self, packages):
        self._p = packages

    def get_metadata(self, name):
        return self._p.get(name)


class _StubNpm:
    def __init__(self, packages):
        self._p = packages

    def get_metadata(self, name):
        return self._p.get(name)


# ---------------------------------------------------------------------------
# Discovery + candidate enumeration
# ---------------------------------------------------------------------------

def test_no_dockerfiles_returns_empty_report(tmp_path: Path) -> None:
    """Target with no Dockerfile → empty report (no error)."""
    http = _StubHttp({})
    report = run_bump(tmp_path, http=http)
    assert report.candidates == []
    assert report.results == []


def test_dockerfile_with_unknown_arg_skipped(tmp_path: Path) -> None:
    """ARG names not in the upstream-source map are silently
    skipped — operator can add via inline-comment override."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SOME_INTERNAL_VERSION=1.0\n"
    )
    http = _StubHttp({})
    report = run_bump(tmp_path, http=http)
    assert report.candidates == []
    assert report.results == []


def test_dockerfile_with_known_arg_at_latest_no_candidate(
    tmp_path: Path,
) -> None:
    """ARG already at upstream-latest → not a candidate. Avoids
    proposing identity bumps."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.119.0\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    report = run_bump(tmp_path, http=http)
    assert report.candidates == []


def test_dockerfile_with_known_arg_below_latest_becomes_candidate(
    tmp_path: Path,
) -> None:
    """ARG below upstream-latest → candidate emitted; verdict
    computed."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            # Published over 30 days ago — recent_publish silent
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now,
    )
    assert len(report.candidates) == 1
    c = report.candidates[0]
    assert c.arg_name == "SEMGREP_VERSION"
    assert c.current_version == "1.50.0"
    assert c.target_version == "1.119.0"
    # Verdict: Clean (no bump-tier signals fired — old enough).
    assert report.results[0].verdict == _VERDICT_CLEAN


def test_dockerfile_recent_publish_target_review_not_clean(
    tmp_path: Path,
) -> None:
    """Target published <30 days ago → recent_publish medium →
    Review (not Clean)."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2026-05-09T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now,
    )
    assert report.results[0].verdict == _VERDICT_REVIEW
    # And the recent_publish finding is in the result for PR-comment
    # rendering / operator visibility.
    kinds = [f.kind for f in report.results[0].bump_supply_chain_findings]
    assert "recent_publish" in kinds


def test_upstream_lookup_failure_records_in_skipped(
    tmp_path: Path,
) -> None:
    """When the GitHub releases endpoint returns 404 (project
    doesn't cut releases), the ARG is recorded in ``skipped``
    so the operator sees the gap."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    http = _StubHttp({})    # everything 404s
    report = run_bump(tmp_path, http=http)
    assert report.candidates == []
    assert len(report.skipped) == 1
    arg, path, reason = report.skipped[0]
    assert arg == "SEMGREP_VERSION"
    assert "upstream lookup failed" in reason


# ---------------------------------------------------------------------------
# Apply path
# ---------------------------------------------------------------------------

def test_apply_writes_clean_bumps_in_place(tmp_path: Path) -> None:
    """``apply=True`` rewrites the Dockerfile when verdict is
    Clean."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG SEMGREP_VERSION=1.50.0\n")
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now, apply=True,
    )
    # Verdict Clean + apply → rewrite applied.
    assert report.results[0].rewrite_result is not None
    assert report.results[0].rewrite_result.applied
    # File contents updated in place.
    assert "1.119.0" in dockerfile.read_text()
    assert "1.50.0" not in dockerfile.read_text()


def test_apply_does_not_write_review_bumps(tmp_path: Path) -> None:
    """``apply=True`` honours the suggest-only policy: Review /
    Block bumps do NOT get auto-written, even with --apply.
    Operator review required."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG SEMGREP_VERSION=1.50.0\n")
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2026-05-09T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now, apply=True,
    )
    assert report.results[0].verdict == _VERDICT_REVIEW
    assert report.results[0].rewrite_result is None
    # File untouched.
    assert dockerfile.read_text() == "ARG SEMGREP_VERSION=1.50.0\n"


def test_apply_default_is_dry_run(tmp_path: Path) -> None:
    """Default ``apply=False`` → no writes even for Clean
    verdicts. The dry-run produces the verdict report; the
    operator decides whether to ``--apply``."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG SEMGREP_VERSION=1.50.0\n")
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now,
    )
    assert report.results[0].verdict == _VERDICT_CLEAN
    assert report.results[0].rewrite_result is None
    assert dockerfile.read_text() == "ARG SEMGREP_VERSION=1.50.0\n"


# ---------------------------------------------------------------------------
# Render report
# ---------------------------------------------------------------------------

def test_render_report_shape_and_findings_in_table(tmp_path: Path) -> None:
    """The text report shows ARG / current / target / verdict
    per row, plus inline supply-chain findings for non-Clean
    verdicts (so operators see WHY)."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2026-05-10T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now,
    )
    text = render_report(report)
    assert "SEMGREP_VERSION" in text
    assert "1.50.0" in text
    assert "1.119.0" in text
    assert "Review" in text
    # Inline finding annotation visible.
    assert "recent_publish" in text


def test_render_report_no_candidates_message(tmp_path: Path) -> None:
    """Friendly message when there are no candidates."""
    http = _StubHttp({})
    report = run_bump(tmp_path, http=http)
    text = render_report(report)
    assert "no bump candidates found" in text


# ---------------------------------------------------------------------------
# Cross-Dockerfile upstream-lookup deduplication
# ---------------------------------------------------------------------------

class _CountingHttp(_StubHttp):
    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.calls: List[str] = []

    def get_json(self, url: str, **kw):
        self.calls.append(url)
        return super().get_json(url, **kw)


def test_upstream_lookup_dedups_across_dockerfiles(tmp_path: Path) -> None:
    """Two Dockerfiles both pinning SEMGREP_VERSION should hit
    the upstream-latest endpoint ONCE — the orchestrator caches
    per (kind, coordinate) within a single run."""
    (tmp_path / "Dockerfile").write_text("ARG SEMGREP_VERSION=1.50.0\n")
    (tmp_path / "Dockerfile.dev").write_text("ARG SEMGREP_VERSION=1.50.0\n")
    http = _CountingHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now,
    )
    assert len(report.candidates) == 2
    # ONE HTTP call to GitHub releases despite TWO Dockerfiles.
    gh_calls = [
        c for c in http.calls
        if "api.github.com" in c
    ]
    assert len(gh_calls) == 1
