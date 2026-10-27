from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
import urllib.robotparser
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup
import httpx

from .models import FetchResult, Program
from .normalize import (
    canonical_url,
    content_hash,
    detect_safe_harbor,
    domain_of,
    extract_emails,
    extract_reward,
    extract_sections,
    github_raw_url,
    html_to_text,
    infer_category,
    infer_chains,
    normalize_text,
    utc_now,
    utc_today,
    web3_signals,
)


POLICY_PATHS = [
    "/.well-known/security.txt",
    "/security",
    "/security.txt",
    "/bug-bounty",
    "/bugbounty",
    "/docs/security",
]
POLICY_LANGUAGE = re.compile(
    r"bug\s*bounty|vulnerability\s+disclosure|responsible\s+disclosure|coordinated\s+disclosure|"
    r"security\s+policy|report\s+(?:a\s+)?vulnerabilit|report(?:s|ing)?\s+(?:security\s+)?vulnerabilit|"
    r"\bbounty\s+(?:program|rewards?)\b|\boffers?\s+[^.]{0,40}\bbounty\b|immunefi|safe\s+harbor",
    re.I,
)
PLATFORM_HOSTS = {
    "immunefi.com", "hackerone.com", "bugcrowd.com", "intigriti.com",
    "github.com", "raw.githubusercontent.com", "medium.com",
}


class UnsafeURL(ValueError):
    pass


async def validate_public_url(url: str, allow_nonstandard_ports: bool = False):
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise UnsafeURL("only http/https URLs are allowed")
    if parts.username or parts.password:
        raise UnsafeURL("credentialed URLs are not allowed")
    host = parts.hostname
    if not host:
        raise UnsafeURL("URL has no hostname")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if not allow_nonstandard_ports and port not in {80, 443}:
        raise UnsafeURL("only default HTTP/HTTPS ports are allowed")
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            info = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise UnsafeURL(f"DNS resolution failed: {exc}") from exc
        addresses = {ipaddress.ip_address(item[4][0]) for item in info}
    if not addresses:
        raise UnsafeURL("DNS returned no addresses")
    for address in addresses:
        if not address.is_global:
            raise UnsafeURL(f"non-public address is not allowed: {address}")


class PolicyFetcher:
    def __init__(
        self,
        concurrency: int = 4,
        delay: float = 0.5,
        timeout: float = 12,
        max_bytes: int = 2_000_000,
        respect_robots: bool = True,
        user_agent: str = "Web3BountyRadar/0.1 (public-policy-monitor)",
    ):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.delay = delay
        self.timeout = httpx.Timeout(timeout, connect=min(timeout, 8))
        self.max_bytes = max_bytes
        self.respect_robots = respect_robots
        self.user_agent = user_agent
        self.host_locks: dict[str, asyncio.Lock] = {}
        self.last_request: dict[str, float] = {}
        self.robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}

    def _host_lock(self, host: str) -> asyncio.Lock:
        if host not in self.host_locks:
            self.host_locks[host] = asyncio.Lock()
        return self.host_locks[host]

    async def _request_once(self, client: httpx.AsyncClient, url: str) -> tuple[FetchResult, str, dict]:
        result = FetchResult(url=url)
        await validate_public_url(url)
        host = urlsplit(url).netloc
        async with self._host_lock(host):
            wait = self.delay - (time.monotonic() - self.last_request.get(host, 0))
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                async with client.stream("GET", url, follow_redirects=False) as response:
                    self.last_request[host] = time.monotonic()
                    result.status_code = response.status_code
                    headers = dict(response.headers)
                    if response.status_code in {301, 302, 303, 307, 308}:
                        return result, "", headers
                    if response.status_code in {404, 410}:
                        result.dead = True
                        result.error = f"HTTP {response.status_code}"
                        return result, "", headers
                    if response.status_code != 200:
                        result.error = f"HTTP {response.status_code}"
                        return result, "", headers
                    length = int(response.headers.get("content-length", "0") or 0)
                    if length > self.max_bytes:
                        result.error = f"response too large: {length} bytes"
                        return result, "", headers
                    content_type = response.headers.get("content-type", "")
                    if content_type and not re.search(
                        r"text/|application/(?:xhtml\+xml|json|ld\+json)|application/octet-stream", content_type, re.I
                    ):
                        result.error = f"unsupported content type: {content_type.split(';')[0]}"
                        return result, "", headers
                    chunks = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > self.max_bytes:
                            result.error = f"response exceeded {self.max_bytes} bytes"
                            return result, "", headers
                        chunks.append(chunk)
                    raw = b"".join(chunks)
                    encoding = "utf-8"
                    match = re.search(r"charset=[\"']?([\w.-]+)", content_type, re.I)
                    if match:
                        encoding = match.group(1)
                    try:
                        decoded = raw.decode(encoding, errors="replace")
                    except LookupError:
                        decoded = raw.decode("utf-8", errors="replace")
                    return result, decoded, headers
            except (httpx.HTTPError, asyncio.TimeoutError) as exc:
                self.last_request[host] = time.monotonic()
                result.error = f"{type(exc).__name__}: {exc}"
                return result, "", {}

    async def _robots_allows(self, client: httpx.AsyncClient, url: str) -> bool:
        if not self.respect_robots:
            return True
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin not in self.robots:
            robots_url = origin + "/robots.txt"
            try:
                result, text, _ = await self._request_once(client, robots_url)
                if result.status_code in {401, 403}:
                    self.robots[origin] = None
                elif result.status_code == 200:
                    parser = urllib.robotparser.RobotFileParser()
                    parser.parse(text.splitlines())
                    self.robots[origin] = parser
                else:
                    # Missing/unavailable robots does not block this small policy-only crawler.
                    self.robots[origin] = urllib.robotparser.RobotFileParser()
                    self.robots[origin].parse([])
            except (UnsafeURL, httpx.HTTPError):
                self.robots[origin] = None
        parser = self.robots[origin]
        return parser is not None and parser.can_fetch(self.user_agent, url)

    @staticmethod
    def _security_txt(text: str, result: FetchResult):
        contacts = []
        expires = ""
        for line in text.splitlines():
            match = re.match(r"^(Contact|Expires)\s*:\s*(.+)$", line.strip(), re.I)
            if not match:
                continue
            field, value = match.group(1).lower(), match.group(2).strip()
            if field == "contact":
                if value not in contacts:
                    contacts.append(value)
            elif field == "expires":
                expires = value
        result.contacts = list(dict.fromkeys(contacts + extract_emails(text)))
        result.expires = expires
        if expires:
            try:
                parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                try:
                    parsed = parsedate_to_datetime(expires)
                except (TypeError, ValueError):
                    parsed = None
            if parsed and parsed <= datetime.now(timezone.utc):
                result.expired = True

    async def fetch(self, url: str) -> FetchResult:
        original = canonical_url(url)
        result = FetchResult(url=original)
        if not original:
            result.error = "invalid URL"
            return result
        current = github_raw_url(original)
        try:
            await validate_public_url(current)
            async with self.semaphore:
                async with httpx.AsyncClient(
                    headers={
                        "User-Agent": self.user_agent,
                        "Accept": "text/html,text/plain,text/markdown,application/xhtml+xml;q=0.9,*/*;q=0.1",
                    },
                    timeout=self.timeout,
                    follow_redirects=False,
                    max_redirects=0,
                ) as client:
                    if not await self._robots_allows(client, current):
                        result.error = "robots.txt disallows this policy URL"
                        return result
                    for redirect_count in range(5):
                        step, raw, headers = await self._request_once(client, current)
                        result.status_code = step.status_code
                        result.dead = step.dead
                        result.error = step.error
                        if step.status_code in {301, 302, 303, 307, 308}:
                            location = headers.get("location")
                            if not location or redirect_count == 4:
                                result.error = "redirect limit or missing Location"
                                return result
                            current = urljoin(current, location)
                            await validate_public_url(current)
                            if not await self._robots_allows(client, current):
                                result.error = "robots.txt disallows redirected policy URL"
                                return result
                            continue
                        if step.dead or step.error:
                            return result
                        result.final_url = current
                        content_type = headers.get("content-type", "")
                        text = html_to_text(raw, content_type)
                        if not text:
                            result.error = "empty policy response"
                            return result
                        is_security_txt = urlsplit(current).path.endswith("/security.txt") or bool(
                            re.search(r"^Contact\s*:", text, re.I | re.M)
                        )
                        if is_security_txt:
                            self._security_txt(text, result)
                        elif not POLICY_LANGUAGE.search(text):
                            # JS-heavy or nav-heavy pages can defeat content extraction;
                            # fall back to the full rendered HTML before rejecting.
                            soup = BeautifulSoup(raw, "html.parser")
                            for tag in soup(["script", "style", "noscript", "svg", "template"]):
                                tag.decompose()
                            fallback = normalize_text(soup.get_text("\n"))
                            if POLICY_LANGUAGE.search(fallback):
                                text = fallback
                            else:
                                result.error = "no vulnerability-policy language detected"
                                return result
                        result.text = text
                        result.contacts = list(dict.fromkeys(result.contacts + extract_emails(text)))
                        result.ok = True
                        result.error = ""
                        return result
        except (UnsafeURL, ValueError) as exc:
            result.error = str(exc)
            return result
        result.error = result.error or "fetch failed"
        return result


def _origin_for_discovery(program: Program) -> str:
    base = canonical_url(program.homepage_url or program.program_url)
    if not base:
        return ""
    parts = urlsplit(base)
    host = parts.hostname or ""
    if host in PLATFORM_HOSTS or host.endswith(".gitbook.io") or host.endswith(".zendesk.com"):
        return ""
    return f"{parts.scheme}://{parts.netloc}"


async def crawl_program(
    fetcher: PolicyFetcher,
    program_id: str,
    program: Program,
    discover_paths: bool = False,
    include_platforms: bool = False,
) -> tuple[str, Program, list[FetchResult]]:
    updated = program.model_copy(deep=True)
    if program.hosting == "platform_hosted" and not include_platforms:
        updated.crawl_error = "platform policy supplied by source API; HTML crawl skipped"
        return program_id, updated, []
    urls = []
    for url in [program.program_url] + program.program_urls:
        url = canonical_url(url)
        if url and url not in urls:
            urls.append(url)
    results: list[FetchResult] = []
    for url in urls[:3]:
        result = await fetcher.fetch(url)
        results.append(result)
    successful = [r for r in results if r.ok and not r.expired]
    if not successful and discover_paths:
        origin = _origin_for_discovery(program)
        if origin:
            attempted = {canonical_url(r.url) for r in results}
            for path in POLICY_PATHS:
                url = origin + path
                if canonical_url(url) in attempted:
                    continue
                result = await fetcher.fetch(url)
                results.append(result)
                if result.ok and not result.expired:
                    successful.append(result)
                    break
    updated.last_crawled = utc_now()
    if successful:
        # Prefer full policy pages over contact-only security.txt, then richer text.
        best = max(
            successful,
            key=lambda r: (
                0 if urlsplit(r.final_url or r.url).path.endswith("/security.txt") else 1,
                len(r.text),
            ),
        )
        old_url = updated.program_url
        updated.program_url = best.final_url or best.url
        updated.program_urls = list(dict.fromkeys([old_url] + updated.program_urls + [best.url, best.final_url]))
        updated.policy_text = best.text
        updated.content_hash = content_hash(best.text)
        is_security_txt = urlsplit(updated.program_url).path.endswith("/security.txt")
        updated.hash_basis = "live_security_txt" if is_security_txt else "live_policy"
        updated.extraction_method = "live_security_txt" if is_security_txt else "live_policy"
        scope, out, smart = extract_sections(best.text)
        updated.scope = scope
        updated.out_of_scope = out
        updated.smart_contract_scope = smart
        safe, detail = detect_safe_harbor(best.text)
        updated.safe_harbor = safe
        updated.safe_harbor_detail = detail
        updated.contact = list(dict.fromkeys(updated.contact + best.contacts))
        amount, currency, usd = extract_reward(best.text)
        if amount > 0:
            updated.max_reward_amount = amount
            updated.reward_currency = currency
            updated.max_reward_usd = usd
        chains = infer_chains(best.text[:250_000])
        updated.chain = list(dict.fromkeys(updated.chain + chains))
        category = infer_category(best.text[:250_000])
        if category != "Unknown":
            updated.category = category
        if updated.status != "paused":
            updated.status = "active"
        updated.policy_url_status = "alive"
        updated.policy_expires = best.expires
        updated.crawl_error = ""
        updated.last_seen = utc_today()
        signals = web3_signals(best.text[:250_000])
        if signals:
            updated.web3_confidence = "high"
            updated.web3_reason = list(dict.fromkeys(updated.web3_reason + [f"policy:{s}" for s in signals]))
        if re.search(r"\b(?:no|not) (?:currently )?(?:offer(?:ing)? )?(?:a )?bug bounty\b", best.text, re.I):
            updated.offers_bounty = False
        elif re.search(r"bug bounty|rewards?|bounties|payouts?", best.text, re.I):
            updated.offers_bounty = True
        return program_id, updated, results

    errors = [r.error for r in results if r.error]
    updated.crawl_error = " | ".join(dict.fromkeys(errors))[:2000] or "no successful policy fetch"
    if results and all(r.dead or r.expired for r in results):
        updated.status = "policy_dead"
        updated.policy_url_status = "expired" if any(r.expired for r in results) else "dead"
        updated.safe_harbor = "not_stated"
        updated.safe_harbor_detail = "no current live policy; no permission inferred"
    return program_id, updated, results


async def crawl_many(
    fetcher: PolicyFetcher,
    programs: list[tuple[str, Program]],
    discover_paths: bool = False,
    include_platforms: bool = False,
):
    tasks = [
        asyncio.create_task(crawl_program(fetcher, pid, program, discover_paths, include_platforms))
        for pid, program in programs
    ]
    for task in asyncio.as_completed(tasks):
        yield await task
