from __future__ import annotations

import os
import re

import httpx

from .models import Program
from .normalize import (
    canonical_url,
    content_hash,
    domain_of,
    github_org_of,
    infer_category,
    infer_chains,
    utc_today,
    web3_signals,
)


QUERIES = [
    'filename:SECURITY.md "bug bounty"',
    '"bug bounty" "smart contract"',
    '"bug bounty" blockchain',
    '"responsible disclosure" "bug bounty" crypto',
]

# Repository names that mark resource lists, collections, or study material,
# not a protocol that might operate a bounty program.
NON_PROGRAM_REPO_RE = re.compile(
    r"awesome|write[-_]?ups?|cheat|handbook|toolkit|dorks|collection|resources|"
    r"template|roadmap|checklist|notes|tutorial|guide|guia|skills|curated|interview|"
    r"practice|learning|encyclopedia|hub|digest|weekly|newsletter|trending|"
    r"best-|-list\b|/list\b|wordlist|methodology|[-/_]kit\b",
    re.I,
)


def is_program_repo(full_name: str) -> bool:
    return bool(full_name) and not NON_PROGRAM_REPO_RE.search(full_name)


def discover_github(token: str | None = None, queries: list[str] | None = None, pages: int = 1) -> list[Program]:
    """GitHub code-search discovery. A token is required by GitHub's API."""
    token = (token or os.getenv("GITHUB_TOKEN") or "").strip()
    if not token:
        raise RuntimeError("GitHub code search requires GITHUB_TOKEN; manual dork import needs no token")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Web3BountyRadar/0.1",
    }
    found: dict[str, Program] = {}
    with httpx.Client(headers=headers, timeout=40) as client:
        for query in queries or QUERIES:
            for page in range(1, max(1, pages) + 1):
                response = client.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 100, "page": page},
                )
                if response.status_code in {403, 429}:
                    reset = response.headers.get("x-ratelimit-reset", "unknown")
                    raise RuntimeError(f"GitHub search rate limited; reset epoch: {reset}")
                response.raise_for_status()
                items = response.json().get("items") or []
                if not items:
                    break
                for item in items:
                    repo = item.get("repository") or {}
                    full_name = repo.get("full_name") or item.get("name")
                    url = canonical_url(item.get("html_url") or repo.get("html_url"))
                    if not full_name or not url or not is_program_repo(full_name):
                        continue
                    # Prefer an actual SECURITY.md when several files from one repository match.
                    key = full_name.lower()
                    if key in found and "security.md" not in str(item.get("path", "")).lower():
                        continue
                    description = str(repo.get("description") or "")
                    signals = web3_signals(query + "\n" + description)
                    found[key] = Program(
                        project=full_name,
                        category=infer_category(description),
                        chain=infer_chains(description),
                        hosting="project_hosted",
                        platform="self",
                        program_url=url,
                        homepage_url=canonical_url(repo.get("homepage") or ""),
                        canonical_domain=domain_of(repo.get("html_url") or url),
                        github_org=github_org_of(url),
                        safe_harbor="unknown",
                        last_seen=utc_today(),
                        content_hash=content_hash(url),
                        hash_basis="github_discovery",
                        extraction_method="github_discovery",
                        sources=["github_search"],
                        source_key=key,
                        status="unknown",
                        web3_confidence="review",
                        web3_reason=["github_query:" + query] + [f"repository:{s}" for s in signals],
                    )
    return list(found.values())
