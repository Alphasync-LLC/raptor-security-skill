"""Project-sample collection for the calibration corpus.

For each project in :data:`PROJECT_SAMPLES`, the collector:

  1. Shallow-clones the project to a transient temp dir.
  2. Runs ``run_sca`` against it (offline-OSV, cache-friendly).
  3. Writes the findings to
     ``packages/sca/data/calibration/project_samples/<ecosystem>/
     <name>.json``.
  4. **Discards the source.** We never store the cloned tree —
     only OUR scan output, which is RAPTOR-generated and ships
     under MIT.

The output schema strips file paths under the project root; only
the dep + finding metadata that the corpus needs for validation
(``raptor_risk_estimate``, ``severity``, ``in_kev``, ``epss``,
``cve_id``) is preserved. Project source code is NEVER included.

License compliance:

  * We don't redistribute the cloned project — it's transient.
  * Our scan output is RAPTOR-generated (MIT). Each output JSON
    carries a ``_source.license: "MIT (RAPTOR-generated)"`` block.
  * The license-compliance check (:mod:`._license_check`) treats
    files under ``project_samples/`` permissively (filename refs
    not required in ATTRIBUTION.md per-file; the parent dir's
    citation suffices).

The project list is intentionally small for the bootstrap — top-N
per ecosystem can come later via the ``popular/<eco>.json``
auto-derived list. Curated start lets us control which licenses
we touch (only OSI-approved permissive). Each entry pins the
clone target so re-runs are reproducible.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProjectSample:
    """One row in the curated project-sample list."""

    name: str
    ecosystem: str          # canonical SCA ecosystem string
    repo_url: str           # https git URL
    git_ref: str            # branch / tag / commit; pinned for reproducibility
    license_spdx: str       # operator-asserted; sanity-check only


# Curated bootstrap list. Each entry is a permissive-licensed OSS
# project with active CVE history (so we have something to score).
# Ten entries is enough to validate the collection loop; the list
# expands incrementally per follow-up PRs that add new CVE-bearing
# projects.
PROJECT_SAMPLES: List[ProjectSample] = [
    ProjectSample(
        name="requests", ecosystem="PyPI",
        repo_url="https://github.com/psf/requests.git",
        git_ref="v2.31.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="flask", ecosystem="PyPI",
        repo_url="https://github.com/pallets/flask.git",
        git_ref="3.0.0", license_spdx="BSD-3-Clause",
    ),
    ProjectSample(
        name="django", ecosystem="PyPI",
        repo_url="https://github.com/django/django.git",
        git_ref="4.2.7", license_spdx="BSD-3-Clause",
    ),
    ProjectSample(
        name="lodash", ecosystem="npm",
        repo_url="https://github.com/lodash/lodash.git",
        git_ref="4.17.21", license_spdx="MIT",
    ),
    ProjectSample(
        name="express", ecosystem="npm",
        repo_url="https://github.com/expressjs/express.git",
        git_ref="4.18.2", license_spdx="MIT",
    ),
    ProjectSample(
        name="serde", ecosystem="Cargo",
        repo_url="https://github.com/serde-rs/serde.git",
        git_ref="v1.0.193", license_spdx="MIT OR Apache-2.0",
    ),
    ProjectSample(
        name="tokio", ecosystem="Cargo",
        repo_url="https://github.com/tokio-rs/tokio.git",
        git_ref="tokio-1.35.0", license_spdx="MIT",
    ),
    ProjectSample(
        name="gin", ecosystem="Go",
        repo_url="https://github.com/gin-gonic/gin.git",
        git_ref="v1.9.1", license_spdx="MIT",
    ),
    ProjectSample(
        name="spring-boot", ecosystem="Maven",
        repo_url="https://github.com/spring-projects/spring-boot.git",
        git_ref="v3.2.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="rails", ecosystem="RubyGems",
        repo_url="https://github.com/rails/rails.git",
        git_ref="v7.1.2", license_spdx="MIT",
    ),
    # ---- Older-pinned siblings ----------------------------------------
    # The recent-pin set above produces a corpus dominated by 2024+ CVEs
    # that haven't accrued exploit signals yet (KEV / EDB / MSF / PoC
    # all lag CVE disclosure by months-to-years). Validation against
    # the recent-only corpus on 2026-05-09 found only 7/343 findings
    # with any exploit signal — a structural ceiling that capped top-20
    # precision at 7/20 = 0.35 even with optimal weights.
    #
    # These older-pin siblings carry well-known, long-disclosed CVEs in
    # their dep trees (jQuery 1.x family, Rails 5.x, Django 2.2.x,
    # Spring Boot 2.1, etc.) — the historic CVE pool that exploit
    # databases have caught up on. Every entry here is an explicit
    # OLD-version pin to a project we already cover at HEAD; we keep
    # both so the corpus reflects "what gets scanned in CI today" AND
    # "what scoring did when the CVEs were exploit-rich".
    ProjectSample(
        name="django-2.2", ecosystem="PyPI",
        repo_url="https://github.com/django/django.git",
        git_ref="2.2.20", license_spdx="BSD-3-Clause",
    ),
    ProjectSample(
        name="rails-5.2", ecosystem="RubyGems",
        repo_url="https://github.com/rails/rails.git",
        git_ref="v5.2.0", license_spdx="MIT",
    ),
    ProjectSample(
        name="spring-boot-2.1", ecosystem="Maven",
        repo_url="https://github.com/spring-projects/spring-boot.git",
        git_ref="v2.1.0.RELEASE", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="express-3", ecosystem="npm",
        repo_url="https://github.com/expressjs/express.git",
        git_ref="3.21.2", license_spdx="MIT",
    ),
    ProjectSample(
        name="lodash-4.17.4", ecosystem="npm",
        repo_url="https://github.com/lodash/lodash.git",
        git_ref="4.17.4", license_spdx="MIT",
    ),
    # ---- Round-2 signal-density expansion (2026-05-09) -----------------
    # Per-ecosystem audit of the 30/1175 signaled corpus showed PyPI
    # at 0/18 and RubyGems at 2/309 (signal-poor relative to Maven's
    # 17/290 and npm's 10/533). These entries target the lagging
    # ecosystems with version pins old enough that their CVE pool has
    # accrued public exploits / KEV listings — pushing toward the
    # ~100-signaled-findings threshold where per-ecosystem refit
    # becomes statistically viable.
    ProjectSample(
        name="django-1.11", ecosystem="PyPI",
        repo_url="https://github.com/django/django.git",
        git_ref="1.11.29", license_spdx="BSD-3-Clause",
    ),
    ProjectSample(
        name="requests-2.18", ecosystem="PyPI",
        repo_url="https://github.com/psf/requests.git",
        git_ref="v2.18.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="rails-4.2", ecosystem="RubyGems",
        repo_url="https://github.com/rails/rails.git",
        git_ref="v4.2.0", license_spdx="MIT",
    ),
    ProjectSample(
        name="spring-boot-1.5", ecosystem="Maven",
        repo_url="https://github.com/spring-projects/spring-boot.git",
        git_ref="v1.5.10.RELEASE", license_spdx="Apache-2.0",
    ),
    # ---- App-shaped PyPI sample ---------------------------------------
    # Library repos (django/requests/flask at any pin) carry narrow
    # dep trees — django pulls just Python stdlib + a few utilities,
    # so scanning the django repo surfaces ~3 finding rows. PyPI
    # signal density stays at 0% because there isn't a tree to walk.
    #
    # Saleor 2.10.0 (March 2020) is a Django + GraphQL e-commerce
    # platform with a deep dep tree declared in ``pyproject.toml``
    # (Poetry) — Django, graphene-django, celery, jinja2, pillow,
    # cryptography, and dozens more transitive deps with accrued
    # KEV / EDB / MSF / PoC signals. The pyproject.toml format is
    # critical: Airflow 1.10 (the first candidate tried) declared
    # its deps in ``setup.py``, which SCA's parser doesn't read,
    # so its 64 findings all came from its embedded ``www/``
    # package.json (npm) and didn't move PyPI signal density.
    ProjectSample(
        name="saleor-2.10", ecosystem="PyPI",
        repo_url="https://github.com/saleor/saleor.git",
        git_ref="2.10.0", license_spdx="BSD-3-Clause",
    ),
    # ---- Round-3 corpus expansion: more app-shaped samples -----------
    # Round-2 (saleor) cleared the OSV multi-manifest poison bug and
    # got PyPI density off zero, but per-ecosystem signal is still
    # heavily skewed: Maven 7%, npm 2%, Go 4%, RubyGems 2%, PyPI 1%.
    # Per-ecosystem refit needs ~10+ signaled findings per ecosystem
    # to be statistically viable; round-3 picks 5 app-shaped repos
    # across the under-served ecosystems whose dep trees historically
    # accrued exploit signals (KEV / EDB / MSF / PoC).
    # sentry-9.x switched to BSL (source-available, not permissive);
    # the corpus license check requires OSI-permissive licences for
    # every sample. sentry 8.22 was the last Apache-2.0 release
    # (Oct 2019, before the BSL switch in 2019-11). Same dep-tree
    # shape, permissive license.
    ProjectSample(
        name="sentry-8.22", ecosystem="PyPI",
        repo_url="https://github.com/getsentry/sentry.git",
        git_ref="8.22.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="wagtail-2.10", ecosystem="PyPI",
        repo_url="https://github.com/wagtail/wagtail.git",
        git_ref="v2.10", license_spdx="BSD-3-Clause",
    ),
    ProjectSample(
        name="superset-0.36", ecosystem="PyPI",
        repo_url="https://github.com/apache/superset.git",
        git_ref="0.36.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="strapi-3", ecosystem="npm",
        repo_url="https://github.com/strapi/strapi.git",
        git_ref="v3.6.0", license_spdx="MIT",
    ),
    ProjectSample(
        name="helm-3.5", ecosystem="Go",
        repo_url="https://github.com/helm/helm.git",
        git_ref="v3.5.0", license_spdx="Apache-2.0",
    ),
    # ---- Round-4 corpus expansion: post-2018 manifests, pre-2020 deps -
    # Goal was pre-2018 permissive apps to surface CVEs that have
    # had time to accrue exploit signals. Reality: pre-2018 Go apps
    # predate go.mod (introduced 1.11/2018) so SCA can't parse
    # their dep graph, and pre-2018 Python apps mostly use setup.py
    # which SCA also doesn't parse. The viable window is therefore
    # 2019-2020: late enough to ship go.mod / requirements.txt,
    # early enough that the resolved CVEs have had ~5 years to
    # accumulate KEV / EDB / MSF / PoC signals.
    #
    # Initial round-4 picks (etcd-3.0, moby-1.13, synapse-0.20,
    # salt-2017.7) all returned 0 findings on collect because none
    # ship a manifest format SCA parses at those tags. Replaced
    # with go.mod-era Go apps + requirements.txt-shape Python.
    ProjectSample(
        name="prometheus-2.10", ecosystem="Go",
        repo_url="https://github.com/prometheus/prometheus.git",
        git_ref="v2.10.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="istio-1.4", ecosystem="Go",
        repo_url="https://github.com/istio/istio.git",
        git_ref="1.4.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="mitmproxy-5", ecosystem="PyPI",
        repo_url="https://github.com/mitmproxy/mitmproxy.git",
        git_ref="v5.0.0", license_spdx="MIT",
    ),
    # NB: no RubyGems app added in round-3 — Discourse is GPL-2,
    # Mastodon is AGPL, Redmine is GPL-2; no popular permissive-
    # licensed Ruby app to point at. RubyGems density (1.7%) stays
    # served by the rails-{4.2,5.2,7.1} library siblings until a
    # permissive Ruby app surfaces.
]


@dataclass
class CollectResult:
    project: str
    ecosystem: str
    written: bool
    error: Optional[str]
    finding_count: int


def collect_project_samples(
    *,
    out_dir: Path,
    samples: Optional[List[ProjectSample]] = None,
    http: Optional[Any] = None,
    cache: Optional[Any] = None,
    git_clone_timeout: int = 120,
    sca_timeout: int = 300,
    only_licenses: Optional[List[str]] = None,
) -> List[CollectResult]:
    """Clone each sample, run SCA, write findings.

    ``only_licenses`` filters the sample list — when set, only
    samples whose ``license_spdx`` matches one of the entries are
    processed. Operators concerned about license-touch can pass
    e.g. ``["MIT", "Apache-2.0", "BSD-3-Clause"]`` to skip
    anything else.

    Returns one :class:`CollectResult` per attempted sample
    (errored or successful). The function never raises on
    individual sample failures — captures them in
    ``CollectResult.error``.
    """
    if samples is None:
        samples = PROJECT_SAMPLES
    if only_licenses is not None:
        allowed = set(only_licenses)
        samples = [
            s for s in samples
            if any(lic in s.license_spdx for lic in allowed)
        ]
    out_dir.mkdir(parents=True, exist_ok=True)

    results: List[CollectResult] = []
    for sample in samples:
        try:
            result = _collect_one(
                sample, out_dir, http=http, cache=cache,
                git_clone_timeout=git_clone_timeout,
                sca_timeout=sca_timeout,
            )
        except Exception as e:                              # noqa: BLE001
            logger.warning(
                "sca.calibration.project_samples: %s/%s failed: %s",
                sample.ecosystem, sample.name, e, exc_info=True,
            )
            result = CollectResult(
                project=sample.name, ecosystem=sample.ecosystem,
                written=False, error=str(e), finding_count=0,
            )
        results.append(result)
    return results


def _collect_one(
    sample: ProjectSample,
    out_dir: Path,
    *,
    http: Optional[Any],
    cache: Optional[Any],
    git_clone_timeout: int,
    sca_timeout: int,
) -> CollectResult:
    eco_dir = out_dir / sample.ecosystem
    eco_dir.mkdir(parents=True, exist_ok=True)
    out_path = eco_dir / f"{sample.name}.json"

    with tempfile.TemporaryDirectory(prefix="raptor-sca-sample-") as tmp:
        clone_root = Path(tmp) / sample.name
        # Shallow clone, single ref. ``--depth 1`` keeps it fast;
        # ``--branch`` accepts both branches and tags.
        try:
            subprocess.run(
                [
                    "git", "clone", "--depth", "1",
                    "--branch", sample.git_ref,
                    sample.repo_url, str(clone_root),
                ],
                check=True, capture_output=True, text=True,
                timeout=git_clone_timeout,
            )
        except (subprocess.TimeoutExpired,
                subprocess.CalledProcessError) as e:
            err = (
                e.stderr if isinstance(e, subprocess.CalledProcessError)
                else f"clone timed out after {git_clone_timeout}s"
            )
            return CollectResult(
                project=sample.name, ecosystem=sample.ecosystem,
                written=False,
                error=f"git clone failed: {str(err)[:200]}",
                finding_count=0,
            )

        # Run SCA against the cloned tree. Results land in a tmp
        # output dir we then read + transform; the SCA-generated
        # files themselves get discarded along with the clone.
        sca_out = Path(tmp) / "sca-out"
        try:
            from packages.sca.pipeline import run_sca, RunOptions
            run_sca(
                target=clone_root, output_dir=sca_out,
                options=RunOptions(
                    enable_llm_review=False, enable_triage=False,
                ),
                http=http, cache=cache,
            )
        except Exception as e:                              # noqa: BLE001
            return CollectResult(
                project=sample.name, ecosystem=sample.ecosystem,
                written=False,
                error=f"run_sca failed: {str(e)[:200]}",
                finding_count=0,
            )

        try:
            findings = json.loads(
                (sca_out / "findings.json").read_text(encoding="utf-8"),
            )
        except (OSError, json.JSONDecodeError) as e:
            return CollectResult(
                project=sample.name, ecosystem=sample.ecosystem,
                written=False,
                error=f"findings.json read failed: {e}",
                finding_count=0,
            )

    # Sanitise findings: drop file paths under the (now-deleted)
    # clone root, keep only the validation-relevant fields.
    sanitised = _sanitise_findings(findings, clone_root)

    output = {
        "_source": {
            "name": f"RAPTOR SCA scan of {sample.name}",
            "url": sample.repo_url,
            "license": "MIT (RAPTOR-generated scan output)",
            "fetched_at": _utcnow(),
            "git_ref": sample.git_ref,
            "project_license": sample.license_spdx,
            "provenance": (
                f"Scan output produced by RAPTOR's SCA pipeline "
                f"against {sample.repo_url}@{sample.git_ref}. "
                f"Project source not redistributed."
            ),
        },
        "findings": sanitised,
    }
    out_path.write_text(
        json.dumps(output, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return CollectResult(
        project=sample.name, ecosystem=sample.ecosystem,
        written=True, error=None,
        finding_count=len(sanitised),
    )


def _sanitise_findings(
    findings: List[Dict[str, Any]],
    clone_root: Path,
) -> List[Dict[str, Any]]:
    """Strip file paths + transient details that don't help
    validation, keep score + dep + advisory metadata.

    Path stripping matters because the clone path is a tempdir
    that won't exist on second runs; preserving project-relative
    paths would also leak the file structure of the project we
    just discarded.
    """
    out: List[Dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        sca = f.get("sca", {}) or {}
        # Only vuln findings carry risk scores worth validating
        # against. Hygiene / supply-chain / license findings are
        # different signals; skip them for the corpus.
        if f.get("vuln_type") != "sca:vulnerable_dependency":
            continue
        out.append({
            "finding_id": f.get("finding_id"),
            "severity": f.get("severity"),
            "ecosystem": sca.get("ecosystem"),
            "dep_name": sca.get("name"),
            "dep_version": sca.get("version"),
            "purl": sca.get("purl"),
            "advisory": sca.get("advisory"),
            "in_kev": sca.get("in_kev"),
            "epss": sca.get("epss"),
            "cvss_score": sca.get("cvss_score"),
            "reachability": sca.get("reachability"),
            "raptor_risk_estimate": sca.get("raptor_risk_estimate"),
            "risk_components": sca.get("risk_components"),
            # Without this, refit could not see EDB / MSF / GitHub-PoC
            # signal on archived findings — only ``in_kev`` (the
            # binary CISA flag) was preserved, even though the live
            # pipeline populated the full ExploitEvidence block on
            # every finding before the archive step. Re-tuning runs
            # against this archive could only see ~half the exploit
            # signal that production scans actually saw.
            "exploit_evidence": sca.get("exploit_evidence"),
        })
    return out


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "PROJECT_SAMPLES",
    "CollectResult",
    "ProjectSample",
    "collect_project_samples",
]
