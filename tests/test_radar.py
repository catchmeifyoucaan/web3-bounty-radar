from __future__ import annotations

import json

import httpx
import pytest

from radar.crawler import PolicyFetcher, crawl_program, validate_public_url
from radar.db import RadarDB
from radar.github_discovery import is_program_repo
from radar.models import FetchResult, Program
from radar.normalize import (
    content_hash,
    detect_safe_harbor,
    extract_reward,
    extract_sections,
    web3_signals,
)
from radar.sources import seed_curated, seed_diodb, seed_immunefi


def program(**changes) -> Program:
    values = {
        "project": "Example Protocol",
        "category": "DeFi",
        "chain": ["Ethereum"],
        "hosting": "project_hosted",
        "platform": "self",
        "program_url": "https://example.org/security",
        "homepage_url": "https://example.org/",
        "canonical_domain": "example.org",
        "scope": ["https://example.org"],
        "smart_contract_scope": [],
        "max_reward_usd": 1000,
        "max_reward_amount": 1000,
        "safe_harbor": "stated",
        "last_seen": "2026-10-27",
        "content_hash": content_hash("Bug bounty policy v1"),
        "hash_basis": "live_policy",
        "extraction_method": "live_policy",
        "sources": ["test"],
        "source_key": "example",
        "status": "active",
        "policy_text": "Bug bounty policy v1",
    }
    values.update(changes)
    return Program(**values)


def test_hash_normalizes_whitespace():
    assert content_hash("Hello  world\n") == content_hash("Hello world\n\n")


def test_safe_harbor_positive_and_negative():
    assert detect_safe_harbor("We will not pursue legal action against good-faith researchers.")[0] == "stated"
    assert detect_safe_harbor("No safe harbor is provided.")[0] == "not_stated"
    assert detect_safe_harbor("Email us about bugs.")[0] == "not_stated"
    assert detect_safe_harbor("")[0] == "unknown"


def test_reward_extraction_and_currency():
    assert extract_reward("Critical smart contract: up to USD 2,500,000") == (2500000, "USD", 2500000)
    assert extract_reward("Maximum bounty €50,000") == (50000, "EUR", 0)
    assert extract_reward("The launch was in 2026")[0] == 0


def test_section_and_contract_extraction():
    text = """Bug Bounty
## Assets in Scope
- https://example.org/app
## Smart Contracts
- 0x0000000000000000000000000000000000000001 - Vault
## Out of Scope
- Third-party services
"""
    scope, out, smart = extract_sections(text)
    assert scope == ["https://example.org/app", "0x0000000000000000000000000000000000000001 - Vault"]
    assert out == ["Third-party services"]
    assert smart == ["0x0000000000000000000000000000000000000001 - Vault"]


def test_web3_signal_boundaries():
    assert web3_signals("defiant.com hardsuit.atlassian.net") == []
    assert "defi" in web3_signals("DeFi protocol")
    assert "smart_contract" in web3_signals("smart-contract scope")


def test_security_txt_expiry_and_contacts():
    result = FetchResult(url="https://example.org/.well-known/security.txt")
    PolicyFetcher._security_txt(
        "Contact: mailto:security@real-protocol.org\nExpires: 2020-01-01T00:00:00Z\n", result
    )
    assert result.expired
    assert result.contacts == ["mailto:security@real-protocol.org", "security@real-protocol.org"]


@pytest.mark.asyncio
async def test_private_addresses_are_rejected():
    with pytest.raises(ValueError):
        await validate_public_url("http://127.0.0.1/security")
    with pytest.raises(ValueError):
        await validate_public_url("file:///etc/passwd")


@pytest.mark.asyncio
async def test_network_failure_does_not_kill_policy():
    class FailedFetcher:
        async def fetch(self, url):
            return FetchResult(url=url, error="timeout")

    original = program()
    _, updated, _ = await crawl_program(FailedFetcher(), "p1", original)
    assert updated.status == "active"
    assert "timeout" in updated.crawl_error


@pytest.mark.asyncio
async def test_expired_policy_is_dead():
    class ExpiredFetcher:
        async def fetch(self, url):
            return FetchResult(url=url, ok=True, expired=True, status_code=200, text="Contact: security@example.org")

    _, updated, _ = await crawl_program(ExpiredFetcher(), "p1", program())
    assert updated.status == "policy_dead"
    assert updated.policy_url_status == "expired"
    assert updated.safe_harbor == "not_stated"


def test_diff_events_and_exports(tmp_path):
    db = RadarDB(str(tmp_path / "radar.db"))
    run = db.start_run()
    pid, created = db.upsert(program(), run)
    assert created
    updated = program(
        scope=["https://example.org", "0x0000000000000000000000000000000000000001"],
        content_hash=content_hash("Bug bounty policy v2"), policy_text="Bug bounty policy v2",
    )
    db.upsert(updated, run)
    updated = program(
        scope=["https://example.org"], max_reward_usd=2000, max_reward_amount=2000,
        content_hash=content_hash("Bug bounty policy v3"), policy_text="Bug bounty policy v3",
    )
    db.upsert(updated, run)
    updated = program(status="closed")
    db.upsert(updated, run)
    kinds = [e["type"] for e in db.list_events(run)]
    assert "new_program" in kinds
    assert "scope_added" in kinds
    assert "scope_removed" in kinds
    assert "bounty_increased" in kinds
    assert "program_closed" in kinds
    paths = db.export(str(tmp_path / "exports"))
    exported = json.loads(open(paths["programs.json"], encoding="utf-8").read())
    assert len(exported) == 1
    assert "policy_text" not in exported[0]
    assert db.latest_snapshot(pid)["normalized_text"]
    db.close()


def test_dedupes_domain_and_similar_project_name(tmp_path):
    db = RadarDB(str(tmp_path / "radar.db"))
    first = program(
        project="Stargate", program_url="https://immunefi.com/bug-bounty/stargate/information/",
        homepage_url="https://stargate.finance", canonical_domain="stargate.finance",
        sources=["immunefi"], source_key="stargate", hosting="platform_hosted", platform="Immunefi",
        extraction_method="immunefi_api",
    )
    second = program(
        project="Stargate Finance", program_url="https://stargateprotocol.gitbook.io/stargate/bug-bounty",
        homepage_url="https://stargate.finance", canonical_domain="stargate.finance",
        sources=["web3_collection"], source_key="stargatefinance", extraction_method="curated_seed",
    )
    db.upsert(first, 1)
    db.upsert(second, 1)
    programs = db.list_programs()
    assert len(programs) == 1
    assert set(programs[0].sources) == {"immunefi", "web3_collection"}
    assert programs[0].program_url.startswith("https://immunefi.com")
    db.close()


def test_name_token_merge_without_domain(tmp_path):
    db = RadarDB(str(tmp_path / "radar.db"))
    immunefi = program(
        project="LayerZero", program_url="https://immunefi.com/bug-bounty/layerzero/information/",
        canonical_domain="", github_org="", sources=["immunefi"], source_key="layerzero",
        hosting="platform_hosted", platform="Immunefi", extraction_method="immunefi_api",
    )
    diodb = program(
        project="LayerZero", program_url="https://layerzero.gitbook.io/docs/bug-bounty",
        canonical_domain="layerzero.gitbook.io", github_org="", sources=["diodb"],
        source_key="layerzero", extraction_method="diodb_seed",
    )
    db.upsert(immunefi, 1)
    db.upsert(diodb, 1)
    assert len(db.list_programs()) == 1
    merged = db.list_programs()[0]
    assert merged.sources == ["immunefi", "diodb"]
    db.close()


def test_generic_token_name_is_not_over_merged(tmp_path):
    db = RadarDB(str(tmp_path / "radar.db"))
    first = program(project="Maker", canonical_domain="", github_org="", sources=["immunefi"], source_key="maker",
                    program_url="https://immunefi.com/bug-bounty/maker/information/")
    second = program(project="Maker Ecosystem Growth Holdings", canonical_domain="", github_org="",
                     sources=["diodb"], source_key="makerdao",
                     program_url="https://hackerone.com/makerdao_bbp")
    db.upsert(first, 1)
    db.upsert(second, 1)
    assert len(db.list_programs()) == 2
    db.close()


def test_github_discovery_filters_non_program_repos():
    keep = [
        "aave-dao/aave-v3-origin", "aragon/aragonOS", "AztecProtocol/aztec-connect",
        "solana-labs/solana", "ava-labs/avalanchego", "axelarnetwork/axelar-core",
    ]
    drop = [
        "0xsyr0/Awesome-Cybersecurity-Handbooks", "alexbieber/Bug_Bounty_writeups",
        "alphaSeclab/awesome-security-collection", "arunimshukla/Best-DeFi-Security-Practices",
        "arthur-spk/guiadecybersecurity", "aneasystone/github-trending",
        "Abdowaer098/Wa3r-OffSec-Kit", "awarexone/web3-bug-bounty-hunting-ai-skills",
    ]
    assert all(is_program_repo(name) for name in keep)
    assert not any(is_program_repo(name) for name in drop)


def test_first_live_crawl_is_baseline_not_events(tmp_path):
    db = RadarDB(str(tmp_path / "radar.db"))
    seed = program(
        project="solana-labs/solana", program_url="https://github.com/solana-labs/solana/blob/main/SECURITY.md",
        sources=["github_search"], source_key="solana-labs/solana",
        extraction_method="github_discovery", hash_basis="github_discovery",
        content_hash=content_hash("seed"), scope=[], status="unknown",
    )
    db.upsert(seed, 1)
    live = program(
        project="solana-labs/solana",
        program_url="https://raw.githubusercontent.com/solana-labs/solana/main/SECURITY.md",
        sources=["github_search"], source_key="solana-labs/solana",
        extraction_method="live_policy", hash_basis="live_policy",
        content_hash=content_hash("Bug bounty: report vulnerabilities. Rewards up to $2,000,000."),
        scope=["0x0000000000000000000000000000000000000001"], status="active",
        max_reward_usd=2000000, max_reward_amount=2000000,
    )
    db.upsert(live, 2)
    kinds = [e["type"] for e in db.list_events(2)]
    assert kinds == []  # first live observation is a baseline, and blob->raw is not a move
    stored = db.list_programs()[0]
    assert stored.status == "active" and stored.scope
    db.close()


def test_missing_from_complete_source_closes_program(tmp_path):
    db = RadarDB(str(tmp_path / "radar.db"))
    db.upsert(program(), 1)
    db.finalize_source("test", 2)
    assert db.list_programs()[0].status == "closed"
    assert "program_closed" in [e["type"] for e in db.list_events(2)]
    db.close()


def mock_client(payload, content_type="application/json"):
    def handler(request):
        if isinstance(payload, (dict, list)):
            return httpx.Response(200, json=payload)
        return httpx.Response(200, text=payload, headers={"content-type": content_type})
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_immunefi_structured_import():
    payload = [{
        "slug": "example", "project": "Example", "websiteUrl": "https://example.org",
        "githubUrl": "https://github.com/example/contracts", "projectType": ["Defi"],
        "ecosystem": ["ETH"], "features": ["Safe Harbor Documents Signed"], "maxBounty": 50000,
        "assets": [{"url": "0x0000000000000000000000000000000000000001", "type": "smart_contract"}],
        "rewards": [{"severity": "critical", "maxReward": 50000}],
        "programOverview": "A lending protocol", "defaultOutOfScopeGeneral": "- Third-party issues",
    }]
    result = seed_immunefi(mock_client(payload))
    assert len(result) == 1
    p = result[0]
    assert p.category == "DeFi"
    assert p.chain == ["Ethereum"]
    assert p.smart_contract_scope == ["0x0000000000000000000000000000000000000001"]
    assert p.max_reward_usd == 50000
    assert p.safe_harbor == "stated"
    assert p.out_of_scope == ["Third-party issues"]


def test_curated_table_import():
    markdown = """| Project Name | Highest Bounty | Link |
|---|---|---|
| [Example](https://example.org) | $1,250,000 | [Policy](https://example.org/security) |
"""
    result = seed_curated(mock_client(markdown, "text/plain"))
    assert len(result) == 1
    assert result[0].max_reward_usd == 1250000
    assert result[0].program_url == "https://example.org/security"


def test_diodb_web3_filter_avoids_word_fragments():
    known = [program(project="0x", homepage_url="https://0x.org", canonical_domain="0x.org")]
    rows = [
        {"program_name": "0x", "policy_url": "https://docs.0x.org/bounties", "policy_url_status": "alive", "safe_harbor": "full"},
        {"program_name": "defiant.com", "policy_url": "https://defiant.com/security", "policy_url_status": "alive"},
        {"program_name": "hardsuit", "policy_url": "https://hardsuit.example/security", "policy_url_status": "alive"},
    ]
    result = seed_diodb(mock_client(rows), known)
    assert [p.project for p in result] == ["0x"]
    assert result[0].safe_harbor == "stated"


def test_fts_search(tmp_path):
    db = RadarDB(str(tmp_path / "radar.db"))
    db.upsert(program(policy_text="Ethereum vault bug bounty and safe harbor"), 1)
    assert db.search("vault")[0]["project"] == "Example Protocol"
    db.close()
