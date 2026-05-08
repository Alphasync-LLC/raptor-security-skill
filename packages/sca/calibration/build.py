"""Build the calibration corpus from public ground-truth sources.

Runs each enabled fetcher (KEV, EPSS, exploit-evidence) and writes
JSON artefacts to ``packages/sca/data/calibration/``. Each output
file carries a top-level ``_source`` block documenting:

  * ``license`` — the source's data license (Public Domain /
    Apache-2.0 / CC-BY-4.0)
  * ``url`` — canonical source URL
  * ``fetched_at`` — UTC timestamp of the run
  * ``provenance`` — short prose for the ATTRIBUTION.md cross-reference

The build is idempotent + diff-friendly: re-running on unchanged
sources produces byte-identical output (sorted keys, stable
ordering). The CI workflow opens an auto-PR only when something
actually changed.

License compliance:

  * Tier 1 sources (KEV / NVD / EPSS / OSV / GHSA) are embedded
    verbatim — all are MIT-redistribution-compatible. CC-BY-4.0
    sources (GHSA) carry per-file attribution blocks.
  * Tier 2 sources (Exploit-DB / Metasploit) are reduced to
    boolean signals + reference URLs only. We never ship exploit
    content; only public facts about its existence.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# Output directory — relative to repo root in production; tests pass
# their own ``out_dir``.
DEFAULT_OUT_DIR = Path("packages/sca/data/calibration")


@dataclass(frozen=True)
class BuildResult:
    """Per-source build status. The CI workflow surfaces these in
    the auto-PR body so reviewers see what changed."""

    source: str
    written: bool        # True iff the file changed
    error: Optional[str] # populated on fetch failure (workflow logs)
    record_count: int


def build_corpus(
    *,
    out_dir: Optional[Path] = None,
    http: Optional[Any] = None,
    sources: Optional[List[str]] = None,
) -> List[BuildResult]:
    """Refresh the calibration corpus.

    ``sources`` filters which fetchers run. Default is all known
    sources. Each source is independent — one failure doesn't abort
    the rest; the BuildResult list reports per-source status.

    The function never raises on individual source failures —
    captures them in BuildResult.error so the CI workflow can keep
    going. Programmer errors (bad arguments, unwriteable out_dir)
    still raise.
    """
    if out_dir is None:
        out_dir = DEFAULT_OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    if http is None:
        from core.http import default_client
        http = default_client()

    if sources is None:
        sources = ["kev", "epss", "exploitdb", "metasploit"]

    results: List[BuildResult] = []
    for source in sources:
        try:
            if source == "kev":
                results.append(_build_kev(out_dir, http))
            elif source == "epss":
                results.append(_build_epss(out_dir, http))
            elif source == "exploitdb":
                results.append(_build_exploitdb(out_dir, http))
            elif source == "metasploit":
                results.append(_build_metasploit(out_dir, http))
            else:
                results.append(BuildResult(
                    source=source, written=False,
                    error=f"unknown source {source!r}",
                    record_count=0,
                ))
        except Exception as e:                          # noqa: BLE001
            # Defensive: an individual source breaking shouldn't
            # abort the rest. Logged + surfaced in BuildResult.
            logger.warning(
                "sca.calibration: %s build failed: %s", source, e,
                exc_info=True,
            )
            results.append(BuildResult(
                source=source, written=False,
                error=str(e), record_count=0,
            ))
    return results


# ---------------------------------------------------------------------------
# Per-source builders
# ---------------------------------------------------------------------------


def _build_kev(out_dir: Path, http: Any) -> BuildResult:
    """Fetch the CISA KEV JSON dump and write a flat CVE-keyed
    signal file. Public Domain — embed verbatim."""
    KEV_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    data = http.get_json(KEV_URL)
    signals: Dict[str, Dict[str, Any]] = {}
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cveID")
        if not cve:
            continue
        signals[cve] = {
            "kev": True,
            "date_added": entry.get("dateAdded"),
            "vendor": entry.get("vendorProject"),
            "product": entry.get("product"),
            "ransomware_use": (
                entry.get("knownRansomwareCampaignUse") == "Known"
            ),
        }
    output = {
        "_source": {
            "name": "CISA KEV",
            "url": KEV_URL,
            "license": "Public Domain (US Government work)",
            "fetched_at": _utcnow(),
            "provenance": (
                "CISA Known Exploited Vulnerabilities Catalog. "
                "Public Domain; embedded verbatim."
            ),
        },
        "signals": dict(sorted(signals.items())),
    }
    return _write_if_changed(
        out_dir / "kev_signals.json", output, source="kev",
        record_count=len(signals),
    )


def _build_exploitdb(out_dir: Path, http: Any) -> BuildResult:
    """Fetch the Exploit-DB index CSV and emit a CVE-keyed
    boolean-signal file.

    **Strict licensing posture:** Exploit-DB's license is
    research/personal-use, NOT redistribution. We download the
    public INDEX (which is metadata about public exploits — the
    fact that an exploit exists for CVE-X) and emit ONLY:

      * ``has_exploitdb_entry: bool``
      * ``edb_ids: [int, ...]`` (entry IDs, public references)

    We never store exploit BODIES, payloads, shellcode, or any
    exploit content. The Tier 2 license-check
    (:mod:`packages.sca.calibration._license_check`) enforces this
    at commit time by rejecting field names like ``body`` /
    ``shellcode`` / ``exploit_code`` anywhere in the corpus.

    Source: ``files_exploits.csv`` from the upstream
    ``exploit-database/exploitdb`` GitLab mirror. The CSV columns
    include ``codes`` which carries CVE references.
    """
    import csv
    import io

    EDB_CSV_URL = (
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/"
        "files_exploits.csv"
    )
    raw = http.get_bytes(EDB_CSV_URL, max_bytes=64 * 1024 * 1024)
    text = raw.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    cve_to_ids: Dict[str, List[int]] = {}
    rows_seen = 0
    for row in reader:
        rows_seen += 1
        edb_id_raw = row.get("id")
        codes_raw = row.get("codes") or ""
        if not edb_id_raw:
            continue
        try:
            edb_id = int(edb_id_raw)
        except (TypeError, ValueError):
            continue
        # ``codes`` is semicolon-separated; entries that map to a
        # CVE look like ``CVE-2021-44228``. Filter to CVE refs
        # only (other codes include OSVDB ids).
        for code in codes_raw.split(";"):
            code = code.strip()
            if code.startswith("CVE-"):
                cve_to_ids.setdefault(code, []).append(edb_id)
    signals = {
        cve: {
            "has_exploitdb_entry": True,
            "edb_ids": sorted(set(ids)),
        }
        for cve, ids in cve_to_ids.items()
    }
    output = {
        "_source": {
            "name": "Exploit-DB index",
            "url": EDB_CSV_URL,
            "license": (
                "Exploit-DB content is research/personal-use only. "
                "We embed ONLY boolean signals + entry-ID references "
                "(public observable facts). No exploit content stored."
            ),
            "fetched_at": _utcnow(),
            "provenance": (
                "Exploit-Database files_exploits.csv index. We map "
                "CVE references in the ``codes`` column to entry "
                "IDs; no exploit bodies are read or stored."
            ),
            "rows_scanned": rows_seen,
        },
        "signals": dict(sorted(signals.items())),
    }
    return _write_if_changed(
        out_dir / "exploitdb_signals.json", output,
        source="exploitdb", record_count=len(signals),
    )


def _build_metasploit(out_dir: Path, http: Any) -> BuildResult:
    """Fetch the Metasploit Framework module metadata index and
    emit a CVE-keyed boolean-signal file.

    **Strict licensing posture:** the MSF Framework codebase is
    BSD-3-Clause. We could embed it freely, but we choose not to:
    the corpus only needs the FACT that a module exists per CVE.
    Storing module names + CVE refs is sufficient for calibration
    (signal: "exploitation has been weaponised") without
    redistributing the framework's data.

    Source: ``modules_metadata_base.json`` from the upstream
    ``rapid7/metasploit-framework`` GitHub repo. JSON keyed by
    module path; each module has a ``references`` list with
    ``CVE-...`` entries.
    """
    MSF_URL = (
        "https://raw.githubusercontent.com/rapid7/metasploit-framework/"
        "master/db/modules_metadata_base.json"
    )
    data = http.get_json(MSF_URL)
    if not isinstance(data, dict):
        raise RuntimeError(
            f"unexpected MSF index shape: {type(data).__name__}"
        )
    cve_to_modules: Dict[str, List[str]] = {}
    for module_path, meta in data.items():
        if not isinstance(meta, dict):
            continue
        refs = meta.get("references") or []
        if not isinstance(refs, list):
            continue
        for ref in refs:
            cve_id = _msf_ref_to_cve(ref)
            if cve_id is None:
                continue
            cve_to_modules.setdefault(cve_id, []).append(module_path)
    signals = {
        cve: {
            "has_msf_module": True,
            "module_paths": sorted(set(mods)),
        }
        for cve, mods in cve_to_modules.items()
    }
    output = {
        "_source": {
            "name": "Metasploit Framework module metadata",
            "url": MSF_URL,
            "license": (
                "Metasploit Framework is BSD-3-Clause. We embed only "
                "module-path references + booleans (a public fact "
                "about the framework's contents); no MSF code is "
                "stored."
            ),
            "fetched_at": _utcnow(),
            "provenance": (
                "rapid7/metasploit-framework "
                "modules_metadata_base.json. We extract the "
                "CVE→module-path mapping; framework code itself is "
                "not redistributed."
            ),
            "modules_scanned": len(data),
        },
        "signals": dict(sorted(signals.items())),
    }
    return _write_if_changed(
        out_dir / "metasploit_signals.json", output,
        source="metasploit", record_count=len(signals),
    )


def _msf_ref_to_cve(ref: Any) -> Optional[str]:
    """MSF references arrive in two shapes:

      * String: ``"CVE-2021-44228"`` or ``"OSVDB-12345"``
      * Object: ``{"type": "CVE", "ref": "2021-44228"}``

    Return a normalised CVE-id string or None for non-CVE refs.
    """
    if isinstance(ref, str):
        if ref.startswith("CVE-"):
            return ref
        return None
    if isinstance(ref, dict):
        if ref.get("type") == "CVE":
            cve_num = ref.get("ref") or ""
            if cve_num and not cve_num.startswith("CVE-"):
                cve_num = f"CVE-{cve_num}"
            return cve_num or None
    return None


def _build_epss(out_dir: Path, http: Any) -> BuildResult:
    """Fetch the daily EPSS scores CSV and emit a sorted JSON of
    ``{cve_id: {epss, percentile, fetched_date}}``.

    EPSS is FIRST.org's free-for-any-use feed. Bulk daily CSV at
    epss.cyentia.com / api.first.org. We use the FIRST API for
    a manageable size (top-N by score) — full bulk is ~30 MB.
    """
    # FIRST API supports filtering by score threshold. Pull
    # everything ≥ 0.05 (5% probability) to keep the file
    # manageable while covering all CVEs that might matter for
    # calibration.
    EPSS_URL = "https://api.first.org/data/v1/epss?epss-gt=0.05&limit=10000"
    data = http.get_json(EPSS_URL)
    signals: Dict[str, Dict[str, Any]] = {}
    for entry in data.get("data", []):
        cve = entry.get("cve")
        if not cve:
            continue
        # Reject entries missing epss / percentile entirely — coercing
        # missing-fields to 0.0 would silently inflate the corpus
        # with no-data rows that look like "this CVE has 0% EPSS".
        if entry.get("epss") is None or entry.get("percentile") is None:
            continue
        try:
            score = float(entry["epss"])
            percentile = float(entry["percentile"])
        except (TypeError, ValueError):
            continue
        signals[cve] = {
            "epss": score,
            "percentile": percentile,
            "as_of": entry.get("date"),
        }
    output = {
        "_source": {
            "name": "FIRST.org EPSS",
            "url": "https://www.first.org/epss/",
            "license": "Free for any use (FIRST.org)",
            "fetched_at": _utcnow(),
            "provenance": (
                "Exploit Prediction Scoring System — FIRST.org. "
                "Filtered to CVEs with EPSS ≥ 0.05 to keep the "
                "corpus tractable."
            ),
        },
        "signals": dict(sorted(signals.items())),
    }
    return _write_if_changed(
        out_dir / "epss_signals.json", output, source="epss",
        record_count=len(signals),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> str:
    """ISO-8601 UTC timestamp without microseconds — stable string
    for diff-friendliness."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_if_changed(
    path: Path, data: Dict[str, Any], *, source: str,
    record_count: int,
) -> BuildResult:
    """Write ``data`` to ``path`` only when content differs.

    Diff is computed against the file's current bytes (with
    ``_source.fetched_at`` masked to current run time so the
    timestamp churn doesn't trigger spurious diffs). Returns a
    BuildResult with ``written`` reflecting whether disk changed.
    """
    new_bytes = json.dumps(
        data, indent=2, sort_keys=True, ensure_ascii=False,
    ).encode("utf-8") + b"\n"
    if path.exists():
        try:
            existing = path.read_bytes()
        except OSError:
            existing = b""
        if _bytes_equal_excluding_timestamp(existing, new_bytes):
            return BuildResult(
                source=source, written=False, error=None,
                record_count=record_count,
            )
    path.write_bytes(new_bytes)
    return BuildResult(
        source=source, written=True, error=None,
        record_count=record_count,
    )


def _bytes_equal_excluding_timestamp(a: bytes, b: bytes) -> bool:
    """Compare two corpus JSON blobs ignoring ``_source.fetched_at``.

    Without this the corpus would re-write every run (timestamp
    differs even when source content didn't change), churning the
    git history. Match-on-content semantics.
    """
    try:
        da = json.loads(a)
        db = json.loads(b)
    except (json.JSONDecodeError, ValueError):
        return False
    for d in (da, db):
        if isinstance(d, dict) and "_source" in d:
            d["_source"] = {
                k: v for k, v in d["_source"].items()
                if k != "fetched_at"
            }
    return da == db


__all__ = ["BuildResult", "build_corpus"]
