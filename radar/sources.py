from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlsplit

import httpx

from .models import Program
from .normalize import (
    AMBIGUOUS_PROJECT_KEYS,
    canonical_url,
    content_hash,
    detect_safe_harbor,
    domain_of,
    extract_emails,
    extract_reward,
    github_org_of,
    infer_category,
    infer_chains,
    normalize_text,
    platform_for_url,
    project_key,
    split_bullets,
    utc_today,
    web3_signals,
)


IMMUNEFI_URL = "https://immunefi.com/public-api/bounties.json"
DIODB_URLS = [
    "https://raw.githubusercontent.com/disclose/diodb/master/program-list.json",
    # Legacy locations retained for older mirrors/forks of the open dataset.
    "https://raw.githubusercontent.com/disclose/diodb/master/programs.json",
    "https://raw.githubusercontent.com/disclose/diodb/master/programs.txt",
]
CURATED_URL = "https://raw.githubusercontent.com/JeffCX/collection-web3-bug-bounty/master/readme.md"
USER_AGENT = "Web3BountyRadar/0.1 (public-policy-monitor)"

# Name-only matches for these common words need corroboration from a Web3 term or domain.
# (Moved to radar/normalize.py; kept in sync there.)


class SourceError(RuntimeError):
    pass


def make_client(timeout: float = 60) -> httpx.Client:
    return httpx.Client(
        headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, text/html;q=0.9, */*;q=0.1"},
        timeout=httpx.Timeout(timeout, connect=15),
        follow_redirects=True,
        max_redirects=5,
    )


def fetch_bytes(client: httpx.Client, url: str, max_bytes: int = 20_000_000) -> bytes:
    with client.stream("GET", url) as response:
        response.raise_for_status()
        length = int(response.headers.get("content-length", "0") or 0)
        if length > max_bytes:
            raise SourceError(f"response too large: {length} bytes")
        chunks = []
        size = 0
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > max_bytes:
                raise SourceError(f"response exceeded {max_bytes} bytes")
            chunks.append(chunk)
        return b"".join(chunks)


def fetch_text(client: httpx.Client, url: str, max_bytes: int = 20_000_000) -> str:
    data = fetch_bytes(client, url, max_bytes)
    return data.decode("utf-8-sig", errors="replace")


def _structured_policy(item: dict) -> str:
    sections = []
    fields = [
        ("Program overview", "programOverview"),
        ("Description", "description"),
        ("Assets in scope", "assetsBodyV2"),
        ("Rewards", "rewardsBody"),
        ("Impacts in scope", "impactsBody"),
        ("Out of scope and rules", "outOfScopeAndRules"),
        ("Out of scope: blockchain", "defaultOutOfScopeBlockchain"),
        ("Out of scope: smart contracts", "defaultOutOfScopeSmartContract"),
        ("Out of scope: web and applications", "defaultOutOfScopeWebAndApplications"),
        ("Out of scope: general", "defaultOutOfScopeGeneral"),
        ("Additional out of scope", "customOutOfScopeInformation"),
        ("Prohibited activities", "defaultProhibitedActivities"),
        ("Custom prohibited activities", "customProhibitedActivities"),
        ("Feasibility limitations", "defaultFeasibilityLimitations"),
        ("Prioritized vulnerabilities", "prioritizedVulnerabilities"),
    ]
    for title, key in fields:
        value = item.get(key)
        if value and value != "_blank_" and value != []:
            if isinstance(value, (list, dict)):
                value = json.dumps(value, ensure_ascii=False, sort_keys=True)
            sections.append(f"## {title}\n{value}")
    assets = [
        {k: asset.get(k) for k in ["url", "type", "description", "isSafeHarbor", "isPrimacyOfImpact"]}
        for asset in item.get("assets") or []
    ]
    impacts = [
        {k: impact.get(k) for k in ["type", "severity", "title"]}
        for impact in item.get("impacts") or []
    ]
    rewards = [
        {k: reward.get(k) for k in ["assetType", "severity", "maxReward", "fixedReward", "rewardModel", "rewardCalculationPercentage", "primacy"]}
        for reward in item.get("rewards") or []
    ]
    structured = {
        "assets": assets,
        "impacts": impacts,
        "rewards": rewards,
        "maxBounty": item.get("maxBounty") or 0,
        "ecosystem": item.get("ecosystem") or [],
        "features": item.get("features") or [],
        "isPaused": bool(item.get("isPaused")),
        "endDate": item.get("endDate"),
    }
    sections.append("## Structured source data\n" + json.dumps(structured, ensure_ascii=False, sort_keys=True))
    return normalize_text("\n\n".join(sections))


def seed_immunefi(client: httpx.Client) -> list[Program]:
    raw = fetch_bytes(client, IMMUNEFI_URL)
    payload = json.loads(raw)
    if not isinstance(payload, list):
        raise SourceError("Immunefi response is not a list")
    programs = []
    now = datetime.now(timezone.utc)
    for item in payload:
        slug = str(item.get("slug") or "").strip()
        project = str(item.get("project") or slug).strip()
        if not slug or not project:
            continue
        program_url = f"https://immunefi.com/bug-bounty/{slug}/information/"
        homepage = canonical_url(item.get("websiteUrl") or "")
        policy_text = _structured_policy(item)
        assets = item.get("assets") or []
        scope = [str(a.get("url")).strip() for a in assets if a.get("url")]
        smart = [str(a.get("url")).strip() for a in assets if a.get("url") and a.get("type") == "smart_contract"]
        scope_details = [
            {
                "url": a.get("url") or "",
                "type": a.get("type") or "",
                "description": a.get("description") or "",
                "safe_harbor": bool(a.get("isSafeHarbor")),
                "primacy_of_impact": bool(a.get("isPrimacyOfImpact")),
            }
            for a in assets
        ]
        out = []
        for key in [
            "defaultOutOfScopeBlockchain", "defaultOutOfScopeSmartContract",
            "defaultOutOfScopeWebAndApplications", "defaultOutOfScopeGeneral",
            "customOutOfScopeInformation", "outOfScopeAndRules",
        ]:
            out.extend(split_bullets(item.get(key)))
        safe, detail = detect_safe_harbor("\n".join((item.get("features") or []) + [policy_text]))
        if any(a.get("isSafeHarbor") for a in assets):
            safe, detail = "stated", "asset-level safe-harbor flag"
        end_date = item.get("endDate")
        closed = False
        if end_date:
            try:
                closed = datetime.fromisoformat(str(end_date).replace("Z", "+00:00")) <= now
            except ValueError:
                pass
        status = "closed" if closed else ("paused" if item.get("isPaused") else "active")
        types = (item.get("projectType") or []) + (item.get("productType") or []) + (item.get("programType") or [])
        classification_text = "\n".join([str(item.get("programOverview") or ""), str(item.get("description") or "")])
        max_bounty = float(item.get("maxBounty") or 0)
        programs.append(Program(
            project=project,
            category=infer_category(classification_text, types),
            chain=infer_chains(classification_text, item.get("ecosystem") or []),
            hosting="platform_hosted",
            platform="Immunefi",
            program_url=program_url,
            homepage_url=homepage,
            canonical_domain=domain_of(homepage),
            github_org=github_org_of(item.get("githubUrl") or ""),
            scope=scope,
            out_of_scope=out,
            smart_contract_scope=smart,
            scope_details=scope_details,
            max_reward_usd=max_bounty,
            max_reward_amount=max_bounty,
            reward_currency="USD",
            safe_harbor=safe,
            safe_harbor_detail=detail,
            contact=extract_emails(policy_text),
            last_seen=utc_today(),
            content_hash=content_hash(policy_text),
            hash_basis="immunefi_structured_policy",
            extraction_method="immunefi_api",
            sources=["immunefi"],
            source_key=slug,
            status=status,
            policy_url_status="alive",
            source_updated_at=str(item.get("updatedDate") or ""),
            offers_bounty=max_bounty > 0 or bool(item.get("rewards")),
            invite_only=bool(item.get("inviteOnly")),
            web3_confidence="high",
            web3_reason=["immunefi_catalog"],
            policy_text=policy_text,
        ))
    return programs


def _markdown_link(cell: str) -> tuple[str, str]:
    match = re.search(r"\[([^]]+)]\((https?://[^)]+)\)", cell)
    return (match.group(1).strip(), match.group(2).strip()) if match else ("", "")


def seed_curated(client: httpx.Client) -> list[Program]:
    markdown = fetch_text(client, CURATED_URL, max_bytes=2_000_000)
    programs = []
    for line in markdown.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 3:
            continue
        project, homepage = _markdown_link(cells[0])
        _, policy = _markdown_link(cells[2])
        if not project or not homepage or not policy:
            continue
        if project == "Project Name" or domain_of(homepage) == "project-homepage.com":
            continue
        amount, currency, usd = extract_reward("Highest bounty " + cells[1])
        hosting, platform = platform_for_url(policy)
        seed_text = normalize_text(line)
        programs.append(Program(
            project=project,
            category="Unknown",
            hosting=hosting,
            platform=platform,
            program_url=canonical_url(policy),
            homepage_url=canonical_url(homepage),
            canonical_domain=domain_of(homepage),
            github_org=github_org_of(policy),
            max_reward_usd=usd,
            max_reward_amount=amount,
            reward_currency=currency,
            offers_bounty=amount > 0,
            safe_harbor="unknown",
            last_seen=utc_today(),
            content_hash=content_hash(seed_text),
            hash_basis="curated_seed",
            extraction_method="curated_seed",
            sources=["web3_collection"],
            source_key=project_key(project),
            status="unknown",
            web3_confidence="high",
            web3_reason=["JeffCX/collection-web3-bug-bounty"],
        ))
    return programs


def _parse_legacy_diodb(text: str) -> list[dict]:
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            payload = payload.get("programs") or payload.get("companies") or []
        return payload if isinstance(payload, list) else []
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            match = re.search(r"https?://[^\s,|]+", line)
            if not match:
                continue
            url = match.group(0).rstrip(".,;")
            name = line[:match.start()].strip(" \t,|:-") or domain_of(url)
            rows.append({"program_name": name, "policy_url": url, "policy_url_status": "unknown"})
        return rows


def seed_diodb(client: httpx.Client, known: Iterable[Program]) -> list[Program]:
    errors = []
    text = ""
    used_url = ""
    for url in DIODB_URLS:
        try:
            text = fetch_text(client, url, max_bytes=10_000_000)
            used_url = url
            break
        except (httpx.HTTPError, SourceError) as exc:
            errors.append(f"{url}: {exc}")
    if not text:
        raise SourceError("disclose.io download failed: " + " | ".join(errors))
    rows = _parse_legacy_diodb(text)
    known_by_name = {project_key(p.project): p for p in known if project_key(p.project)}
    known_domains = {p.canonical_domain: p for p in known if p.canonical_domain}
    programs = []
    for item in rows:
        name = str(item.get("program_name") or item.get("company") or item.get("name") or "").strip()
        policy = canonical_url(item.get("policy_url") or item.get("url") or "")
        if not name or not policy or name.lower().startswith("status."):
            continue
        security_txt = canonical_url(item.get("securitytxt_url") or "")
        candidate_text = "\n".join([name, policy, security_txt])
        signals = web3_signals(candidate_text)
        key = project_key(name)
        host = domain_of(policy)
        domain_match = None
        for known_domain, program in known_domains.items():
            if host == known_domain or host.endswith("." + known_domain):
                domain_match = program
                break
        name_match = known_by_name.get(key)
        corroborated_name = bool(name_match and key not in AMBIGUOUS_PROJECT_KEYS)
        if not signals and not domain_match and not corroborated_name:
            continue
        reasons = [f"candidate:{s}" for s in signals]
        if domain_match:
            reasons.append(f"known_domain:{domain_match.canonical_domain}")
        if corroborated_name:
            reasons.append(f"known_project:{name_match.project}")
        related = domain_match or (name_match if corroborated_name else None)
        safe_raw = str(item.get("safe_harbor") or "").strip().lower()
        if safe_raw in {"full", "partial", "yes", "true"}:
            safe, detail = "stated", f"disclose.io:{safe_raw}"
        elif safe_raw in {"none", "no", "false"}:
            safe, detail = "not_stated", "disclose.io:none"
        else:
            safe, detail = "unknown", ""
        policy_state = str(item.get("policy_url_status") or "unknown").lower()
        hosting, platform = platform_for_url(policy)
        bounty_raw = item.get("offers_bounty")
        offers = None if bounty_raw in {None, ""} else str(bounty_raw).lower() in {"yes", "true", "1"}
        contact = item.get("contact_email") or item.get("contact") or ""
        contacts = extract_emails(str(contact)) if contact else []
        seed_text = normalize_text(json.dumps(item, ensure_ascii=False, sort_keys=True))
        programs.append(Program(
            project=name,
            category=related.category if related else infer_category(candidate_text),
            chain=related.chain if related else infer_chains(candidate_text),
            hosting=hosting,
            platform=platform,
            program_url=policy,
            homepage_url=related.homepage_url if related else "",
            canonical_domain=(related.canonical_domain if related else "") or domain_of(policy),
            github_org=github_org_of(policy),
            program_urls=[policy] + ([security_txt] if security_txt else []),
            safe_harbor=safe,
            safe_harbor_detail=detail,
            contact=contacts,
            last_seen=utc_today(),
            content_hash=content_hash(seed_text),
            hash_basis="diodb_seed",
            extraction_method="diodb_seed",
            sources=["diodb"],
            source_key=name,
            status="policy_dead" if policy_state == "dead" else "active",
            policy_url_status=policy_state,
            offers_bounty=offers,
            web3_confidence="high" if related or signals else "review",
            web3_reason=reasons,
        ))
    return programs


def programs_from_file(path: str, source: str = "manual") -> list[Program]:
    """Import manually collected search results: JSON, CSV, or one URL per line."""
    with open(path, "r", encoding="utf-8-sig") as handle:
        text = handle.read()
    rows = []
    try:
        payload = json.loads(text)
        rows = payload if isinstance(payload, list) else [payload]
    except json.JSONDecodeError:
        try:
            rows = list(csv.DictReader(io.StringIO(text)))
            if not rows or "program_url" not in (rows[0] or {}) and "url" not in (rows[0] or {}):
                rows = []
        except csv.Error:
            rows = []
        if not rows:
            rows = [{"program_url": line.strip()} for line in text.splitlines() if line.strip().startswith(("http://", "https://"))]
    programs = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        url = canonical_url(row.get("program_url") or row.get("url") or row.get("policy_url"))
        if not url:
            continue
        project = str(row.get("project") or row.get("name") or domain_of(url)).strip()
        hosting, platform = platform_for_url(url)
        amount = float(row.get("max_reward_amount") or row.get("max_reward_usd") or 0)
        currency = str(row.get("reward_currency") or "USD")
        programs.append(Program(
            project=project,
            category=str(row.get("category") or "Unknown"),
            chain=row.get("chain") if isinstance(row.get("chain"), list) else infer_chains(project),
            hosting=hosting,
            platform=platform,
            program_url=url,
            canonical_domain=domain_of(url),
            github_org=github_org_of(url),
            max_reward_usd=amount if currency == "USD" else 0,
            max_reward_amount=amount,
            reward_currency=currency,
            safe_harbor="unknown",
            last_seen=utc_today(),
            content_hash=content_hash(url),
            hash_basis="manual_seed",
            sources=[source],
            source_key=url,
            status="unknown",
            web3_confidence="review",
            web3_reason=["manual_search_result"],
        ))
    return programs
