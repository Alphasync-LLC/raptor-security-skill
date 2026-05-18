"""GitHub Actions metadata client.

Queries the GitHub Releases API for a given action's latest stable
release tag. Used by the ``gha_freshness`` supply-chain detector to
flag actions that are multiple majors behind the current release.

API surface used:

  * ``GET /repos/{owner}/{repo}/releases/latest`` — returns the
    most recent non-prerelease, non-draft release. Most-maintained
    actions ship one. 404 means either the repo has no Releases at
    all (some action repos rely on tags only) or the repo doesn't
    exist; the caller treats both as "no freshness info".

We deliberately don't use the unauthenticated ``/repos/{owner}/{
repo}/tags`` fallback here — it returns every tag (potentially
hundreds), bloats the cache, and the caller-side semver-major
comparison is still the right thing. When ``releases/latest``
returns nothing, the freshness check just doesn't fire for that
action.

Auth: anonymous works (60/hr per-IP rate limit). Operators can
optionally set ``GITHUB_TOKEN`` in the environment for the 5000/hr
authenticated quota — the underlying ``HttpClient`` reads the env
var when present.

Cache TTL: 24h. Latest-release info changes rarely; over-caching
just delays a freshness alert by a day, never produces a wrong one.
"""

from __future__ import annotations

import logging
from typing import Optional

from core.http import HttpClient
from core.json import JsonCache, MISSING

logger = logging.getLogger(__name__)


_DEFAULT_TTL = 24 * 3600
_CACHE_KEY_PREFIX = "ghactions-latest"


class GitHubActionsClient:
    """Resolve the latest release tag for a ``<owner>/<repo>``."""

    ecosystem = "GitHub Actions"

    def __init__(
        self,
        http: HttpClient,
        cache: Optional[JsonCache] = None,
        *,
        ttl_seconds: int = _DEFAULT_TTL,
        offline: bool = False,
    ) -> None:
        self._http = http
        self._cache = cache
        self._ttl = ttl_seconds
        self._offline = offline

    def get_latest_tag(self, owner_repo: str) -> Optional[str]:
        """Return the ``tag_name`` of the latest non-prerelease
        release for ``<owner>/<repo>``, or None on any failure.

        Sub-action paths (``actions/cache/restore``) are reduced to
        the parent repo automatically — releases live on the repo,
        not on subdirectories.
        """
        repo = self._parent_repo(owner_repo)
        if not repo:
            return None
        cache_key = f"{_CACHE_KEY_PREFIX}:{repo}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                # Cache stores the dict — extract tag. ``None`` from
                # a negative-cached failure surfaces as no tag.
                tag = (
                    cached.get("tag_name")
                    if isinstance(cached, dict) else None
                )
                return tag
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                f"https://api.github.com/repos/{repo}/releases/latest",
            )
        except Exception as e:                      # noqa: BLE001
            # 404, 403 (rate-limited), network — treat all as "no
            # freshness info available" rather than escalating.
            logger.debug(
                "sca.registries.github_actions: releases/latest failed for "
                "%s: %s", repo, e,
            )
            if self._cache is not None:
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        if not isinstance(data, dict):
            return None
        # Cache the whole shape so a future caller wanting more than
        # the tag_name pays no extra round-trip.
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        tag = data.get("tag_name")
        return tag if isinstance(tag, str) else None

    @staticmethod
    def _parent_repo(name: str) -> Optional[str]:
        """``actions/cache/restore`` → ``actions/cache``;
        ``actions/checkout`` → ``actions/checkout``. Returns None
        for malformed names without an ``owner/repo`` prefix."""
        if "/" not in name:
            return None
        parts = name.split("/")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            return None
        return f"{parts[0]}/{parts[1]}"


__all__ = ["GitHubActionsClient"]
