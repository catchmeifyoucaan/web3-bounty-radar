from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


SafeHarbor = Literal["stated", "not_stated", "unknown"]
Status = Literal["active", "paused", "closed", "policy_dead", "unknown"]
Hosting = Literal["project_hosted", "platform_hosted"]


class Program(BaseModel):
    """Normalized program record. policy_text stays in snapshots, not list exports."""

    project: str
    category: str = "Unknown"
    chain: list[str] = Field(default_factory=list)
    hosting: Hosting = "project_hosted"
    platform: str = "self"
    program_url: str
    scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    smart_contract_scope: list[str] = Field(default_factory=list)
    max_reward_usd: float = 0
    reward_currency: str = "USD"
    safe_harbor: SafeHarbor = "unknown"
    contact: list[str] = Field(default_factory=list)
    last_seen: str
    content_hash: str = ""

    homepage_url: str = ""
    canonical_domain: str = ""
    github_org: str = ""
    program_urls: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    status: Status = "unknown"
    first_seen: str = ""
    source_updated_at: str = ""
    policy_url_status: str = "unknown"
    safe_harbor_detail: str = ""
    max_reward_amount: float = 0
    offers_bounty: bool | None = None
    invite_only: bool = False
    web3_confidence: str = "high"
    web3_reason: list[str] = Field(default_factory=list)
    hash_basis: str = "none"
    extraction_method: str = "seed_only"
    policy_expires: str = ""
    last_crawled: str = ""
    crawl_error: str = ""
    scope_details: list[dict] = Field(default_factory=list)
    source_key: str = ""
    policy_text: str = ""

    @field_validator(
        "chain",
        "scope",
        "out_of_scope",
        "smart_contract_scope",
        "contact",
        "program_urls",
        "sources",
        "web3_reason",
        mode="before",
    )
    @classmethod
    def none_to_empty_list(cls, value):
        return [] if value is None else value

    @field_validator(
        "chain",
        "scope",
        "out_of_scope",
        "smart_contract_scope",
        "contact",
        "program_urls",
        "sources",
        "web3_reason",
    )
    @classmethod
    def unique_strings(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for item in value:
            text = str(item).strip()
            if text and text not in seen:
                seen.add(text)
                result.append(text)
        return result

    def export_dict(self) -> dict:
        """Public dataset shape; internal keys and full policy text are omitted."""
        return self.model_dump(
            exclude={"policy_text", "source_key", "scope_details"},
            exclude_defaults=False,
        )


class FetchResult(BaseModel):
    url: str
    final_url: str = ""
    status_code: int = 0
    ok: bool = False
    dead: bool = False
    expired: bool = False
    text: str = ""
    contacts: list[str] = Field(default_factory=list)
    expires: str = ""
    error: str = ""
