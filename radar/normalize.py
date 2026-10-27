from __future__ import annotations

import hashlib
import html
import re
import unicodedata
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from bs4 import BeautifulSoup
import trafilatura


EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])([\w.+-]+@[\w.-]+\.[a-z]{2,63})(?![\w.-])")
EVM_RE = re.compile(r"(?i)\b0x[a-f0-9]{40}\b")
TRACKING_PARAMS = {"fbclid", "gclid", "mc_cid", "mc_eid", "ref", "ref_src"}

AMBIGUOUS_PROJECT_KEYS = {
    "alpha", "anchor", "apex", "atlas", "aura", "avocado", "beanstalk", "blink",
    "block", "bloom", "bond", "cedar", "delta", "gamma", "genesis", "harmony",
    "lark", "maker", "nova", "olympus", "origin", "pillar", "prism", "shift",
    "sol", "spark", "terra", "thor", "tornado", "tron", "wave", "yield",
}

# Stripped before comparing project names as token sets ("Frax Finance" == "Frax").
GENERIC_TOKENS = {
    "the", "com", "de", "io", "net", "org", "xyz", "app", "finance", "protocol",
    "foundation", "labs", "lab", "dao", "network", "core",
}

CHAIN_PATTERNS = {
    "Ethereum": [r"\bethereum\b", r"\bmainnet\b", r"\beth\b"],
    "Arbitrum": [r"\barbitrum\b"],
    "BNB Chain": [r"\bbnb(?:\s+smart)?\s+chain\b", r"\bbsc\b", r"\bbinance smart chain\b"],
    "Base": [r"\bbase(?:\s+chain|\s+mainnet)?\b"],
    "Optimism": [r"\boptimism\b", r"\bop mainnet\b"],
    "Polygon": [r"\bpolygon\b"],
    "Solana": [r"\bsolana\b"],
    "Avalanche": [r"\bavalanche\b", r"\bavax\b"],
    "Aptos": [r"\baptos\b"],
    "Sui": [r"\bsui\b"],
    "Cosmos": [r"\bcosmos\b"],
    "Polkadot": [r"\bpolkadot\b"],
    "NEAR": [r"\bnear(?:\s+protocol)?\b"],
    "Hedera": [r"\bhedera\b"],
    "Bitcoin": [r"\bbitcoin\b"],
    "Rootstock": [r"\brootstock\b", r"\brsk\b"],
    "Starknet": [r"\bstarknet\b"],
    "zkSync": [r"\bzksync\b"],
    "Scroll": [r"\bscroll\b"],
    "Linea": [r"\blinea\b"],
    "Fantom": [r"\bfantom\b"],
    "Gnosis": [r"\bgnosis(?:\s+chain)?\b"],
    "TRON": [r"\btron\b"],
    "TON": [r"\bton\b", r"\bthe open network\b"],
    "Cardano": [r"\bcardano\b"],
    "Stellar": [r"\bstellar\b"],
    "Filecoin": [r"\bfilecoin\b"],
    "Celo": [r"\bcelo\b"],
    "Mantle": [r"\bmantle\b"],
    "Blast": [r"\bblast\b"],
    "Berachain": [r"\bberachain\b"],
    "Hyperliquid": [r"\bhyperliquid\b", r"\bhyper evm\b"],
}

# Strong signals use token boundaries; "defiant" and "hardsuit" are not DeFi/Sui hits.
WEB3_PATTERNS = {
    "web3": r"\bweb\s*3\b",
    "blockchain": r"\bblockchain\b",
    "cryptocurrency": r"\bcrypto(?:currency|currencies)?\b",
    "defi": r"\bdefi\b|decentrali[sz]ed finance",
    "smart_contract": r"\bsmart[\s_-]+contracts?\b",
    "ethereum": r"\bethereum\b",
    "bitcoin": r"\bbitcoin\b",
    "solana": r"\bsolana\b",
    "arbitrum": r"\barbitrum\b",
    "optimism": r"\boptimism\b",
    "polygon": r"\bpolygon\b",
    "avalanche": r"\bavalanche\b",
    "aptos": r"\baptos\b",
    "cosmos": r"\bcosmos\b",
    "polkadot": r"\bpolkadot\b",
    "stellar": r"\bstellar\b",
    "immunefi": r"\bimmunefi\b",
    "nft": r"\bnfts?\b|non[\s-]+fungible tokens?",
    "dao": r"\bdaos?\b|decentrali[sz]ed autonomous organizations?",
    "token": r"\b(?:erc[\s-]?20|erc[\s-]?721|spl token|governance token|utility token)\b",
    "wallet": r"\b(?:crypto|blockchain|web3|non[\s-]+custodial) wallets?\b",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def utc_today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def normalize_text(value: str | None) -> str:
    if not value:
        return ""
    value = html.unescape(str(value)).replace("\x00", "")
    value = unicodedata.normalize("NFKC", value).replace("\r\n", "\n").replace("\r", "\n")
    lines = []
    for line in value.split("\n"):
        line = re.sub(r"[\t \u00a0]+", " ", line).strip()
        lines.append(line)
    value = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", value).strip()


def content_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(normalize_text(value).encode("utf-8")).hexdigest()


def canonical_url(value: str | None) -> str:
    if not value:
        return ""
    value = str(value).strip()
    if not value:
        return ""
    if value.startswith("//"):
        value = "https:" + value
    elif not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    try:
        parts = urlsplit(value)
        host = (parts.hostname or "").encode("idna").decode("ascii").lower()
        if not host:
            return ""
        port = parts.port
        netloc = host
        if port and not ((parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80)):
            netloc += f":{port}"
        path = re.sub(r"/{2,}", "/", parts.path or "/")
        if path != "/":
            path = path.rstrip("/")
        query = urlencode(sorted(
            (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if not k.lower().startswith("utm_") and k.lower() not in TRACKING_PARAMS
        ))
        return urlunsplit((parts.scheme.lower(), netloc, path, query, ""))
    except (ValueError, UnicodeError):
        return ""


def domain_of(value: str | None, strip_www: bool = True) -> str:
    url = canonical_url(value)
    if not url:
        return ""
    host = urlsplit(url).hostname or ""
    return host[4:] if strip_www and host.startswith("www.") else host


def github_org_of(value: str | None) -> str:
    url = canonical_url(value)
    if not url:
        return ""
    parts = urlsplit(url)
    if (parts.hostname or "") not in {"github.com", "www.github.com"}:
        return ""
    bits = [b for b in parts.path.split("/") if b]
    return bits[0].lower() if bits else ""


def project_key(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def platform_for_url(value: str | None) -> tuple[str, str]:
    host = domain_of(value)
    if host == "immunefi.com" or host.endswith(".immunefi.com"):
        return "platform_hosted", "Immunefi"
    if host == "hackerone.com" or host.endswith(".hackerone.com"):
        return "platform_hosted", "HackerOne"
    if host == "bugcrowd.com" or host.endswith(".bugcrowd.com"):
        return "platform_hosted", "Bugcrowd"
    if host == "intigriti.com" or host.endswith(".intigriti.com"):
        return "platform_hosted", "Intigriti"
    if host == "cantina.xyz" or host.endswith(".cantina.xyz"):
        return "platform_hosted", "Cantina"
    return "project_hosted", "self"


def html_to_text(raw: str, content_type: str = "") -> str:
    if "html" not in content_type.lower() and not re.search(r"<(?:html|body|main|article|h[1-6]|div)\b", raw[:5000], re.I):
        return normalize_text(raw)
    extracted = trafilatura.extract(
        raw,
        include_links=True,
        include_tables=True,
        favor_recall=True,
        output_format="txt",
    )
    if extracted and len(extracted.strip()) >= 80:
        return normalize_text(extracted)
    soup = BeautifulSoup(raw, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg", "template"]):
        tag.decompose()
    return normalize_text(soup.get_text("\n"))


def extract_emails(text: str) -> list[str]:
    ignored = {"example.com", "example.org", "example.net", "domain.com", "email.com"}
    result = []
    for email in EMAIL_RE.findall(text or ""):
        email = email.strip(".,;:()[]<>").lower()
        if email.rsplit("@", 1)[-1] not in ignored and email not in result:
            result.append(email)
    return result[:30]


def detect_safe_harbor(text: str) -> tuple[str, str]:
    value = normalize_text(text).lower()
    if not value:
        return "unknown", ""
    negative = [
        r"\bno safe harbor\b",
        r"\bdoes not (?:provide|offer|include) (?:any )?safe harbor\b",
        r"\bwithout safe harbor\b",
    ]
    if any(re.search(p, value) for p in negative):
        return "not_stated", "explicitly absent"
    positive = [
        (r"\bsafe harbor documents signed\b", "platform safe-harbor signal"),
        (r"\bsafe harbor\b", "safe-harbor language"),
        (r"\bgood faith\b.{0,180}\b(?:legal|law enforcement|prosecut|civil|claim)", "good-faith legal protection"),
        (r"\b(?:will|shall) not (?:pursue|initiate|take|support).{0,80}\blegal action\b", "no-legal-action statement"),
        (r"\bnot (?:pursue|initiate|take).{0,80}\b(?:legal action|legal claims)\b", "no-legal-action statement"),
        (r"\bwaive.{0,80}\b(?:claims|legal action)\b", "claim waiver"),
        (r"\bdo not (?:intend|plan) to (?:pursue|take).{0,80}\blegal\b", "no-legal-action statement"),
    ]
    for pattern, detail in positive:
        if re.search(pattern, value, re.S):
            return "stated", detail
    return "not_stated", "no explicit statement detected"


def split_bullets(text: str | None, limit: int = 250) -> list[str]:
    if not text or text == "_blank_":
        return []
    result: list[str] = []
    for raw in normalize_text(text).splitlines():
        line = raw.strip()
        match = re.match(r"^(?:[-*+•]|\d+[.)])\s+(.+)$", line)
        if match:
            item = match.group(1).strip()
        elif not result and len(line) <= 500 and not line.startswith("#"):
            item = line
        else:
            continue
        if item and item not in result:
            result.append(item)
            if len(result) >= limit:
                break
    return result


def extract_sections(text: str) -> tuple[list[str], list[str], list[str]]:
    """Conservative heading/bullet extraction from normalized policy text."""
    scope: list[str] = []
    out: list[str] = []
    smart: list[str] = []
    current = ""
    for raw in normalize_text(text).splitlines():
        line = raw.strip()
        heading = re.sub(r"^#{1,6}\s*", "", line).strip().strip(":").lower()
        heading = re.sub(r"^(?:in|out of|smart contract)\s+", lambda m: m.group(0), heading)
        is_heading = bool(re.match(r"^#{1,6}\s", line)) or (
            len(heading) <= 90 and not re.search(r"[.!?]$", heading) and any(
                term in heading for term in ["scope", "assets", "smart contract", "targets"]
            )
        )
        if is_heading:
            if "out of scope" in heading or "out-of-scope" in heading or "excluded" in heading:
                current = "out"
            elif "smart contract" in heading:
                current = "smart"
            elif any(t in heading for t in ["in scope", "in-scope", "assets in scope", "scope", "targets"]):
                current = "scope"
            else:
                current = ""
            continue
        bullet = re.match(r"^(?:[-*+•]|\d+[.)])\s+(.+)$", line)
        if current and bullet:
            item = bullet.group(1).strip()
            if current == "out":
                out.append(item)
            else:
                scope.append(item)
                if current == "smart" or EVM_RE.search(item) or re.search(r"smart contract|solidity", item, re.I):
                    smart.append(item)
    for address in EVM_RE.findall(text or ""):
        if not any(address in item for item in smart):
            smart.append(address)
    return list(dict.fromkeys(scope))[:250], list(dict.fromkeys(out))[:250], list(dict.fromkeys(smart))[:250]


def extract_reward(text: str) -> tuple[float, str, float]:
    """Return (original maximum, currency, USD value); never convert other currencies."""
    candidates: list[tuple[float, str]] = []
    money = re.compile(
        r"(?i)(?P<currency>US\$|USD|\$|EUR|€|GBP|£)?\s*"
        r"(?P<amount>\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)?)\s*(?P<suffix>[kmb])?\b"
    )
    symbols = {"$": "USD", "US$": "USD", "USD": "USD", "€": "EUR", "EUR": "EUR", "£": "GBP", "GBP": "GBP"}
    for line in normalize_text(text).splitlines():
        if not re.search(r"reward|bounty|bounties|payout|up to|maximum|critical", line, re.I):
            continue
        for match in money.finditer(line):
            if not match.group("currency"):
                continue
            try:
                amount = float(match.group("amount").replace(",", ""))
            except ValueError:
                continue
            suffix = (match.group("suffix") or "").lower()
            amount *= {"": 1, "k": 1_000, "m": 1_000_000, "b": 1_000_000_000}[suffix]
            if amount <= 0 or amount > 1_000_000_000_000:
                continue
            candidates.append((amount, symbols[match.group("currency").upper() if match.group("currency") != "$" else "$"]))
    if not candidates:
        return 0, "USD", 0
    usd = [x for x in candidates if x[1] == "USD"]
    amount, currency = max(usd or candidates, key=lambda x: x[0])
    return amount, currency, amount if currency == "USD" else 0


def infer_chains(text: str, ecosystem: list[str] | None = None) -> list[str]:
    haystack = " ".join(ecosystem or []) + "\n" + (text or "")
    result = []
    for chain, patterns in CHAIN_PATTERNS.items():
        if any(re.search(pattern, haystack, re.I) for pattern in patterns):
            result.append(chain)
    return result


def infer_category(text: str, types: list[str] | None = None) -> str:
    labels = " ".join(types or [])
    haystack = labels + "\n" + (text or "")
    checks = [
        ("Bridge", r"\bbridge\b|cross[\s-]+chain messaging|interoperability"),
        ("Wallet", r"\bwallet\b"),
        ("NFT", r"\bnfts?\b|non[\s-]+fungible"),
        ("DAO", r"\bdao\b|decentrali[sz]ed autonomous organization"),
        ("L2", r"\blayer[\s-]?2\b|\bl2\b|rollup|validium"),
        ("L1", r"\bblockchain\b|\blayer[\s-]?1\b|\bl1\b"),
        ("DeFi", r"\bdefi\b|decentrali[sz]ed finance|lending|staking|yield|liquidity|stablecoin|exchange|dex\b"),
        ("Infrastructure", r"infrastructure|developer platform|node|oracle|indexing|storage"),
    ]
    for category, pattern in checks:
        if re.search(pattern, haystack, re.I):
            return category
    return "Unknown"


def web3_signals(text: str) -> list[str]:
    return [name for name, pattern in WEB3_PATTERNS.items() if re.search(pattern, text or "", re.I)]


def github_raw_url(value: str) -> str:
    """Convert an explicitly supplied GitHub blob/security-policy URL for text retrieval."""
    url = canonical_url(value)
    if not url:
        return ""
    parts = urlsplit(url)
    host = parts.hostname or ""
    bits = [b for b in parts.path.split("/") if b]
    if host == "github.com" and len(bits) >= 5 and bits[2] == "blob":
        owner, repo, _, branch = bits[:4]
        path = "/".join(bits[4:])
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    if host == "github.com" and len(bits) >= 3 and bits[2] in {"security", "community"}:
        # Leave repository security pages on GitHub; their exact route is public HTML.
        return url
    return url
