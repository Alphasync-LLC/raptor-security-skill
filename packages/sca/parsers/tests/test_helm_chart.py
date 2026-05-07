"""Tests for the Helm Chart parsers (Chart.yaml + Chart.lock)."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.models import PinStyle
from packages.sca.parsers.helm_chart import _classify_version, parse


pytest.importorskip("yaml")


def _write(tmp_path: Path, content: str, name: str = "Chart.yaml") -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Chart.yaml — manifest mode
# ---------------------------------------------------------------------------


def test_simple_chart_dependencies(tmp_path):
    p = _write(tmp_path, """\
apiVersion: v2
name: myapp
version: 1.0.0
dependencies:
  - name: postgresql
    version: 13.4.2
    repository: https://charts.bitnami.com/bitnami
  - name: redis
    version: 18.0.0
    repository: oci://registry-1.docker.io/bitnamicharts
""")
    deps = parse(p)
    by_name = {d.name: d for d in deps}
    assert "postgresql" in by_name
    assert "redis" in by_name
    assert by_name["postgresql"].version == "13.4.2"
    assert by_name["postgresql"].ecosystem == "Helm"
    assert by_name["postgresql"].purl == "pkg:helm/postgresql@13.4.2"
    assert by_name["postgresql"].source_kind == "helm_chart"
    assert "bitnami" in by_name["postgresql"].source_extra["repository"]


def test_chart_yaml_no_dependencies(tmp_path):
    """A chart that doesn't import anything — empty deps list."""
    p = _write(tmp_path, """\
apiVersion: v2
name: standalone
version: 1.0.0
""")
    assert parse(p) == []


def test_pin_style_classification(tmp_path):
    p = _write(tmp_path, """\
dependencies:
  - name: exact
    version: 1.2.3
    repository: https://example.com
  - name: caret
    version: ^1.2.3
    repository: https://example.com
  - name: tilde
    version: ~1.2.3
    repository: https://example.com
  - name: range
    version: '>=1.0 <2.0'
    repository: https://example.com
  - name: wildcard
    version: '*'
    repository: https://example.com
""")
    by_name = {d.name: d for d in parse(p)}
    assert by_name["exact"].pin_style == PinStyle.EXACT
    assert by_name["caret"].pin_style == PinStyle.CARET
    assert by_name["tilde"].pin_style == PinStyle.TILDE
    assert by_name["range"].pin_style == PinStyle.RANGE
    assert by_name["wildcard"].pin_style == PinStyle.WILDCARD


def test_classify_version_helper():
    assert _classify_version("1.2.3") == PinStyle.EXACT
    assert _classify_version("^1.2.3") == PinStyle.CARET
    assert _classify_version("~1.2") == PinStyle.TILDE
    assert _classify_version(">=1.0") == PinStyle.RANGE
    assert _classify_version("*") == PinStyle.WILDCARD


def test_chart_with_missing_version_skipped(tmp_path):
    """Entry without a ``version:`` field — not a meaningful pin."""
    p = _write(tmp_path, """\
dependencies:
  - name: ok
    version: 1.0.0
    repository: https://example.com
  - name: bad
    repository: https://example.com
""")
    deps = parse(p)
    assert {d.name for d in deps} == {"ok"}


def test_malformed_yaml(tmp_path):
    p = _write(tmp_path, ":\n  garbage")
    assert parse(p) == []


# ---------------------------------------------------------------------------
# Chart.lock
# ---------------------------------------------------------------------------


def test_chart_lock_marks_lockfile_true(tmp_path):
    p = _write(tmp_path, """\
dependencies:
  - name: postgresql
    version: 13.4.2
    repository: https://charts.bitnami.com/bitnami
""", name="Chart.lock")
    [d] = parse(p)
    assert d.is_lockfile is True
    assert d.direct is False
    assert d.parser_confidence.level == "high"


# ---------------------------------------------------------------------------
# End-to-end via discovery + parser dispatch
# ---------------------------------------------------------------------------


def test_discovery_finds_chart_yaml(tmp_path):
    from packages.sca.discovery import find_manifests
    p = _write(tmp_path, """\
apiVersion: v2
name: x
version: 1.0
dependencies:
  - name: postgresql
    version: 13.4.2
    repository: https://example.com
""")
    manifests = find_manifests(tmp_path)
    chart = [m for m in manifests if m.path.name == "Chart.yaml"]
    assert len(chart) == 1
    assert chart[0].ecosystem == "Helm"
