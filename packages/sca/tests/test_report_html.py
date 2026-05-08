"""Tests for ``packages.sca.report_html``."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from packages.sca.findings import build_vuln_findings
from packages.sca.models import (
    AffectedRange, Advisory, CVSSScore, Confidence, Dependency,
    HygieneFinding, PinStyle,
)
from packages.sca.osv import OsvResult
from packages.sca.report_html import render_html_report


def _dep(name: str = "lodash", version: str = "4.17.20") -> Dependency:
    return Dependency(
        ecosystem="npm", name=name, version=version,
        declared_in=Path("/repo/package.json"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl=f"pkg:npm/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _adv(severity: str = "high", score: float = 7.5) -> Advisory:
    return Advisory(
        osv_id="GHSA-x", aliases=["CVE-2099-9999"], summary="Test.",
        details="...", affected=[AffectedRange(
            type="ECOSYSTEM",
            events=[{"introduced": "0"}, {"fixed": "5"}],
        )],
        severity=CVSSScore(score=score, vector="CVSS:3.1/...",
                            severity=severity),         # type: ignore[arg-type]
        fixed_versions=["5.0.0"], references=[],
    )


def _hygiene(severity: str = "medium") -> HygieneFinding:
    return HygieneFinding(
        finding_id="sca:hygiene:lockfile_drift:npm:lodash:x",
        kind="lockfile_drift",
        dependency=_dep(),
        detail="manifest pins 4.17.20, lockfile 4.17.21",
        severity=severity,         # type: ignore[arg-type]
        confidence=Confidence("high", reason="t"),
    )


# ---------------------------------------------------------------------------
# Document scaffolding
# ---------------------------------------------------------------------------


def test_html_is_self_contained_no_external_assets() -> None:
    """No <link rel=stylesheet>, no <script src=...> — single-file
    output is the whole point of the HTML report shape."""
    html = render_html_report(
        target=Path("/repo"), deps_analysed=0,
        vuln_findings=[], hygiene_findings=[],
    )
    assert "<link " not in html.lower()
    assert "<script" not in html.lower()


def test_html_has_doctype_and_charset() -> None:
    html = render_html_report(
        target=Path("/repo"), deps_analysed=1,
        vuln_findings=[], hygiene_findings=[],
    )
    assert html.startswith("<!DOCTYPE html>")
    assert "charset=\"utf-8\"" in html


def test_html_embeds_css_inline() -> None:
    html = render_html_report(
        target=Path("/repo"), deps_analysed=0,
        vuln_findings=[], hygiene_findings=[],
    )
    assert "<style>" in html
    assert "prefers-color-scheme" in html  # dark-mode adaptation


# ---------------------------------------------------------------------------
# Empty + populated reports
# ---------------------------------------------------------------------------


def test_empty_report_says_no_findings() -> None:
    html = render_html_report(
        target=Path("/repo"), deps_analysed=42,
        vuln_findings=[], hygiene_findings=[],
    )
    assert "No vulnerabilities, hygiene, supply-chain, or license " in html
    assert "Dependencies analysed" in html


def test_vuln_finding_rendered_with_advisory_and_severity() -> None:
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[_adv("high", 7.5)])],
    )
    html = render_html_report(
        target=Path("/repo"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert "lodash" in html
    assert "GHSA-x" in html
    assert "sev-high" in html


def test_html_kev_and_epss_badges() -> None:
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv()])],
    )
    findings[0].in_kev = True
    findings[0].epss = 0.97
    html = render_html_report(
        target=Path("/repo"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert "KEV" in html
    assert "EPSS 0.97" in html


def test_html_hygiene_section_when_findings_present() -> None:
    html = render_html_report(
        target=Path("/repo"), deps_analysed=1,
        vuln_findings=[], hygiene_findings=[_hygiene()],
    )
    assert "Hygiene findings" in html
    assert "lockfile_drift" in html


# ---------------------------------------------------------------------------
# HTML escaping (security)
# ---------------------------------------------------------------------------


def test_html_escapes_advisory_summary_html_tags() -> None:
    """A malicious advisory containing ``<script>...</script>`` in
    its summary must NOT inject script tags into the output."""
    d = _dep()
    adv = _adv()
    adv.summary = '<script>alert("xss")</script> bad summary'
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [adv])],
    )
    html = render_html_report(
        target=Path("/repo"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    # The literal <script> from the summary is escaped, not
    # injected. (The legitimate <style> tag in the head is still
    # there — the assertion is about the SUMMARY string.)
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


def test_html_escapes_dep_name_html_tags() -> None:
    """Dep names that contain HTML metacharacters (e.g. an attacker
    publishes ``<img>`` as a package name) must be escaped."""
    d = _dep(name='<img src=x onerror=alert(1)>')
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv()])],
    )
    html = render_html_report(
        target=Path("/repo"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img" in html


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------


def test_findings_sorted_critical_first() -> None:
    d_low = _dep(name="low-pkg")
    d_crit = _dep(name="crit-pkg")
    findings = []
    findings.extend(build_vuln_findings(
        [d_low], [OsvResult(d_low.key(), [_adv("low", 3.0)])],
    ))
    findings.extend(build_vuln_findings(
        [d_crit], [OsvResult(d_crit.key(), [_adv("critical", 9.8)])],
    ))
    html = render_html_report(
        target=Path("/x"), deps_analysed=2,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert html.index("crit-pkg") < html.index("low-pkg")
