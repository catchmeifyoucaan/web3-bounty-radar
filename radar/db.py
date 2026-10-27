from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Iterable

from .models import Program
from .normalize import (
    AMBIGUOUS_PROJECT_KEYS,
    GENERIC_TOKENS,
    canonical_url,
    content_hash,
    github_raw_url,
    project_key,
    utc_now,
)


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS programs (
    id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    project_key TEXT NOT NULL,
    data TEXT NOT NULL,
    canonical_domain TEXT NOT NULL DEFAULT '',
    github_org TEXT NOT NULL DEFAULT '',
    program_url TEXT NOT NULL,
    normalized_program_url TEXT NOT NULL,
    max_reward_usd REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    safe_harbor TEXT NOT NULL,
    category TEXT NOT NULL,
    content_hash TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_programs_url ON programs(normalized_program_url);
CREATE INDEX IF NOT EXISTS idx_programs_domain ON programs(canonical_domain, project_key);
CREATE INDEX IF NOT EXISTS idx_programs_github ON programs(github_org, project_key);
CREATE TABLE IF NOT EXISTS source_records (
    source TEXT NOT NULL,
    external_key TEXT NOT NULL,
    program_id TEXT NOT NULL REFERENCES programs(id),
    present INTEGER NOT NULL DEFAULT 1,
    last_run_id INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(source, external_key)
);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id TEXT NOT NULL REFERENCES programs(id),
    content_hash TEXT NOT NULL,
    normalized_text TEXT NOT NULL,
    source TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    url TEXT NOT NULL,
    http_status INTEGER NOT NULL DEFAULT 0,
    UNIQUE(program_id, content_hash)
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT '',
    stats TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL DEFAULT 0,
    program_id TEXT NOT NULL REFERENCES programs(id),
    type TEXT NOT NULL,
    old_value TEXT NOT NULL DEFAULT '',
    new_value TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_program ON events(program_id, id);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, id);
CREATE TABLE IF NOT EXISTS fetch_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL DEFAULT 0,
    program_id TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL,
    final_url TEXT NOT NULL DEFAULT '',
    status_code INTEGER NOT NULL DEFAULT 0,
    ok INTEGER NOT NULL DEFAULT 0,
    dead INTEGER NOT NULL DEFAULT 0,
    expired INTEGER NOT NULL DEFAULT 0,
    content_hash TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    fetched_at TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS programs_fts USING fts5(
    program_id UNINDEXED, project, program_url, category, chains,
    scope, out_of_scope, smart_contract_scope, contacts, policy_text
);
"""

PRIORITY = {
    "immunefi_api": 100,
    "live_policy": 90,
    "live_security_txt": 80,
    "diodb_seed": 40,
    "curated_seed": 30,
    "github_discovery": 20,
    "manual_seed": 10,
    "seed_only": 0,
}

# Extraction bases that represent a verified observation of the actual policy.
LIVE_BASES = {"live_policy", "live_security_txt", "immunefi_structured_policy"}


def _union(*values: Iterable[str]) -> list[str]:
    result = []
    for items in values:
        for item in items:
            if item and item not in result:
                result.append(item)
    return result


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


class RadarDB:
    def __init__(self, path: str = "data/radar.db"):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def start_run(self) -> int:
        cur = self.conn.execute("INSERT INTO runs(started_at) VALUES (?)", (utc_now(),))
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_run(self, run_id: int, stats: dict):
        self.conn.execute("UPDATE runs SET finished_at=?, stats=? WHERE id=?", (utc_now(), _json(stats), run_id))
        self.conn.commit()

    def _row_program(self, row: sqlite3.Row) -> Program:
        return Program.model_validate_json(row["data"])

    def get(self, program_id: str) -> Program | None:
        row = self.conn.execute("SELECT data FROM programs WHERE id=?", (program_id,)).fetchone()
        return Program.model_validate_json(row["data"]) if row else None

    def _name_candidates(self, program: Program, source: str):
        """Cross-source join on project-name tokens, guarded against over-merging."""
        key = project_key(program.project)
        tokens = [t for t in re.split(r"[^a-z0-9]+", program.project.lower()) if t]
        distinct = [t for t in dict.fromkeys(tokens) if t not in GENERIC_TOKENS]
        clauses = []
        params = []
        if key:
            clauses.append("project_key = ?")
            params.append(key)
        for token in distinct:
            if len(token) >= 3:
                clauses.append("project_key LIKE ?")
                params.append(f"%{token}%")
        if not clauses:
            return
        params.append(200)
        rows = self.conn.execute(
            f"SELECT * FROM programs WHERE {' OR '.join(clauses)} LIMIT ?", params
        ).fetchall()
        seen = set()
        for row in rows:
            if row["id"] in seen:
                continue
            seen.add(row["id"])
            existing = self._row_program(row)
            if source and source in existing.sources:
                continue
            other_key = row["project_key"]
            other_distinct = {
                t for t in re.split(r"[^a-z0-9]+", existing.project.lower()) if t and t not in GENERIC_TOKENS
            }
            this_distinct = set(distinct)
            exact = key == other_key and key not in AMBIGUOUS_PROJECT_KEYS
            token_match = (
                this_distinct
                and this_distinct == other_distinct
                and all(len(t) >= 3 for t in this_distinct)
                and not (this_distinct & AMBIGUOUS_PROJECT_KEYS)
            )
            if exact or token_match:
                return row["id"], existing

    def _find(self, program: Program) -> tuple[str, Program] | None:
        source = program.sources[0] if program.sources else ""
        if source and program.source_key:
            row = self.conn.execute(
                "SELECT p.* FROM source_records s JOIN programs p ON p.id=s.program_id WHERE s.source=? AND s.external_key=?",
                (source, program.source_key),
            ).fetchone()
            if row:
                return row["id"], self._row_program(row)
        normalized_url = canonical_url(program.program_url)
        if normalized_url:
            row = self.conn.execute("SELECT * FROM programs WHERE normalized_program_url=?", (normalized_url,)).fetchone()
            if row:
                return row["id"], self._row_program(row)
        key = project_key(program.project)
        candidates = []
        if program.github_org:
            candidates.extend(self.conn.execute("SELECT * FROM programs WHERE github_org=?", (program.github_org,)).fetchall())
        if program.canonical_domain:
            candidates.extend(self.conn.execute("SELECT * FROM programs WHERE canonical_domain=?", (program.canonical_domain,)).fetchall())
        seen = set()
        for row in candidates:
            if row["id"] in seen:
                continue
            seen.add(row["id"])
            existing = self._row_program(row)
            # Distinct programs from one catalog (for example, two Immunefi competitions)
            # must remain separate. Domain/GitHub matching is only a cross-source join.
            if source and source in existing.sources:
                continue
            other_key = row["project_key"]
            similar = key == other_key or (
                min(len(key), len(other_key)) >= 4 and (key in other_key or other_key in key)
            )
            if similar:
                return row["id"], existing
        return self._name_candidates(program, source)

    @staticmethod
    def _merge(existing: Program, incoming: Program) -> Program:
        old_score = PRIORITY.get(existing.extraction_method, 0)
        new_score = PRIORITY.get(incoming.extraction_method, 0)
        base, other = (incoming, existing) if new_score >= old_score else (existing, incoming)
        merged = base.model_copy(deep=True)
        merged.sources = _union(existing.sources, incoming.sources)
        merged.program_urls = _union(
            existing.program_urls, [existing.program_url], incoming.program_urls, [incoming.program_url]
        )
        merged.contact = _union(existing.contact, incoming.contact)
        merged.web3_reason = _union(existing.web3_reason, incoming.web3_reason)
        merged.chain = _union(existing.chain, incoming.chain)
        merged.first_seen = existing.first_seen or existing.last_seen
        merged.last_seen = max(existing.last_seen, incoming.last_seen)
        merged.source_key = ""
        if merged.category == "Unknown" and other.category != "Unknown":
            merged.category = other.category
        for field in ["canonical_domain", "github_org", "homepage_url"]:
            if not getattr(merged, field) and getattr(other, field):
                setattr(merged, field, getattr(other, field))
        if merged.offers_bounty is None:
            merged.offers_bounty = other.offers_bounty
        if merged.safe_harbor == "unknown" and other.safe_harbor != "unknown":
            merged.safe_harbor = other.safe_harbor
            merged.safe_harbor_detail = other.safe_harbor_detail
        return merged

    def _save(self, program_id: str, program: Program, run_id: int, http_status: int = 0):
        data = program.model_dump(mode="json", exclude={"source_key"})
        self.conn.execute(
            """INSERT INTO programs(
                id,project,project_key,data,canonical_domain,github_org,program_url,normalized_program_url,
                max_reward_usd,status,safe_harbor,category,content_hash,first_seen,updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                project=excluded.project,project_key=excluded.project_key,data=excluded.data,
                canonical_domain=excluded.canonical_domain,github_org=excluded.github_org,
                program_url=excluded.program_url,normalized_program_url=excluded.normalized_program_url,
                max_reward_usd=excluded.max_reward_usd,status=excluded.status,safe_harbor=excluded.safe_harbor,
                category=excluded.category,content_hash=excluded.content_hash,updated_at=excluded.updated_at""",
            (
                program_id, program.project, project_key(program.project), _json(data), program.canonical_domain,
                program.github_org, program.program_url, canonical_url(program.program_url), program.max_reward_usd,
                program.status, program.safe_harbor, program.category, program.content_hash,
                program.first_seen or program.last_seen, utc_now(),
            ),
        )
        self.conn.execute("DELETE FROM programs_fts WHERE program_id=?", (program_id,))
        self.conn.execute(
            "INSERT INTO programs_fts VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                program_id, program.project, program.program_url, program.category, " ".join(program.chain),
                "\n".join(program.scope), "\n".join(program.out_of_scope), "\n".join(program.smart_contract_scope),
                " ".join(program.contact), program.policy_text,
            ),
        )
        if program.content_hash:
            self.conn.execute(
                """INSERT OR IGNORE INTO snapshots(
                    program_id,content_hash,normalized_text,source,fetched_at,url,http_status
                ) VALUES (?,?,?,?,?,?,?)""",
                (
                    program_id, program.content_hash, program.policy_text,
                    program.sources[0] if program.sources else "", utc_now(), program.program_url, http_status,
                ),
            )

    def _event(self, run_id: int, program_id: str, kind: str, old="", new="", details=None):
        self.conn.execute(
            "INSERT INTO events(run_id,program_id,type,old_value,new_value,details,detected_at) VALUES (?,?,?,?,?,?,?)",
            (run_id, program_id, kind, _json(old) if not isinstance(old, str) else old,
             _json(new) if not isinstance(new, str) else new, _json(details or {}), utc_now()),
        )

    def upsert(
        self, incoming: Program, run_id: int = 0, http_status: int = 0, program_id: str | None = None
    ) -> tuple[str, bool]:
        if program_id is not None:
            existing = self.get(program_id)
            found = (program_id, existing) if existing else None
        else:
            found = self._find(incoming)
        now = utc_now()
        if not found:
            program_id = "p_" + hashlib.sha256(
                f"{incoming.sources}:{incoming.source_key}:{canonical_url(incoming.program_url)}:{incoming.project}".encode()
            ).hexdigest()[:20]
            incoming.first_seen = incoming.first_seen or incoming.last_seen
            self._save(program_id, incoming, run_id, http_status)
            if incoming.sources and incoming.source_key:
                self.conn.execute(
                    """INSERT INTO source_records(source,external_key,program_id,present,last_run_id)
                       VALUES (?,?,?,1,?) ON CONFLICT(source,external_key) DO UPDATE SET
                       program_id=excluded.program_id,present=1,last_run_id=excluded.last_run_id""",
                    (incoming.sources[0], incoming.source_key, program_id, run_id),
                )
            self._event(run_id, program_id, "new_program", details={"project": incoming.project, "sources": incoming.sources})
            self.conn.commit()
            return program_id, True

        program_id, existing = found
        merged = self._merge(existing, incoming)
        baseline_merge = (
            bool(set(incoming.sources) - set(existing.sources))
            and self.conn.execute(
                "SELECT 1 FROM events WHERE program_id=? AND run_id=? AND type='new_program'",
                (program_id, run_id),
            ).fetchone()
        ) or (
            existing.hash_basis not in LIVE_BASES and merged.hash_basis in LIVE_BASES
        )
        if baseline_merge:
            # Enriching a record from another seed during its first import is not a
            # observed scope/reward/status change over time.
            self._save(program_id, merged, run_id, http_status)
            if incoming.sources and incoming.source_key:
                self.conn.execute(
                    """INSERT INTO source_records(source,external_key,program_id,present,last_run_id)
                       VALUES (?,?,?,1,?) ON CONFLICT(source,external_key) DO UPDATE SET
                       program_id=excluded.program_id,present=1,last_run_id=excluded.last_run_id""",
                    (incoming.sources[0], incoming.source_key, program_id, run_id),
                )
            self.conn.commit()
            return program_id, False
        if (
            existing.program_url != merged.program_url
            and canonical_url(existing.program_url) != canonical_url(merged.program_url)
            # blob → raw.githubusercontent.com is our own retrieval conversion, not a move.
            and github_raw_url(existing.program_url) != canonical_url(merged.program_url)
        ):
            self._event(run_id, program_id, "policy_moved", existing.program_url, merged.program_url,
                        {"project": merged.project})
        old_scope = set(existing.scope) | set(existing.smart_contract_scope)
        new_scope = set(merged.scope) | set(merged.smart_contract_scope)
        added = sorted(new_scope - old_scope)
        removed = sorted(old_scope - new_scope)
        specific = False
        if added:
            self._event(run_id, program_id, "scope_added", details={"added": added, "project": merged.project})
            specific = True
        if removed:
            self._event(run_id, program_id, "scope_removed", details={"removed": removed, "project": merged.project})
            specific = True
        if existing.max_reward_usd > 0 and merged.max_reward_usd > existing.max_reward_usd:
            self._event(run_id, program_id, "bounty_increased", existing.max_reward_usd, merged.max_reward_usd,
                        {"project": merged.project, "currency": merged.reward_currency})
            specific = True
        elif existing.max_reward_usd == 0 and merged.max_reward_usd > 0:
            self._event(run_id, program_id, "bounty_detected", 0, merged.max_reward_usd, {"project": merged.project})
            specific = True
        elif 0 < merged.max_reward_usd < existing.max_reward_usd:
            self._event(run_id, program_id, "bounty_decreased", existing.max_reward_usd, merged.max_reward_usd,
                        {"project": merged.project})
            specific = True
        if existing.status != merged.status:
            if merged.status == "closed":
                self._event(run_id, program_id, "program_closed", existing.status, merged.status, {"project": merged.project})
            elif merged.status == "policy_dead":
                self._event(run_id, program_id, "policy_dead", existing.status, merged.status, {"project": merged.project})
            elif merged.status == "paused":
                self._event(run_id, program_id, "program_paused", existing.status, merged.status, {"project": merged.project})
            else:
                self._event(run_id, program_id, "status_changed", existing.status, merged.status, {"project": merged.project})
            specific = True
        if (
            existing.content_hash and merged.content_hash != existing.content_hash
            and existing.hash_basis == merged.hash_basis and not specific
        ):
            self._event(run_id, program_id, "policy_changed", existing.content_hash, merged.content_hash,
                        {"project": merged.project})
        self._save(program_id, merged, run_id, http_status)
        if incoming.sources and incoming.source_key:
            self.conn.execute(
                """INSERT INTO source_records(source,external_key,program_id,present,last_run_id)
                   VALUES (?,?,?,1,?) ON CONFLICT(source,external_key) DO UPDATE SET
                   program_id=excluded.program_id,present=1,last_run_id=excluded.last_run_id""",
                (incoming.sources[0], incoming.source_key, program_id, run_id),
            )
        self.conn.commit()
        return program_id, False

    def finalize_source(self, source: str, run_id: int):
        """Mark explicit disappearances only after a complete, successful source fetch."""
        rows = self.conn.execute(
            "SELECT * FROM source_records WHERE source=? AND present=1 AND last_run_id<>?", (source, run_id)
        ).fetchall()
        for row in rows:
            program = self.get(row["program_id"])
            if not program:
                continue
            if len(program.sources) == 1 and program.status not in {"closed", "policy_dead"}:
                updated = program.model_copy(deep=True)
                updated.status = "closed"
                updated.sources = [source]
                updated.source_key = row["external_key"]
                updated.extraction_method = program.extraction_method
                self.upsert(updated, run_id)
            else:
                remaining = [s for s in program.sources if s != source]
                if remaining:
                    program.sources = remaining
                    self._save(row["program_id"], program, run_id)
            self.conn.execute("UPDATE source_records SET present=0 WHERE source=? AND external_key=?", (source, row["external_key"]))
        self.conn.commit()

    def log_fetch(self, run_id: int, program_id: str, result):
        self.conn.execute(
            """INSERT INTO fetch_log(
                run_id,program_id,url,final_url,status_code,ok,dead,expired,content_hash,error,fetched_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                run_id, program_id, result.url, result.final_url, result.status_code, int(result.ok),
                int(result.dead), int(result.expired), content_hash(result.text) if result.ok else "",
                result.error, utc_now(),
            ),
        )
        self.conn.commit()

    def programs_with_ids(self, crawlable: bool = False, include_platforms: bool = False) -> list[tuple[str, Program]]:
        sql = "SELECT id,data FROM programs"
        clauses = []
        if crawlable:
            clauses.append("status <> 'closed'")
            if not include_platforms:
                clauses.append("json_extract(data, '$.hosting') = 'project_hosted'")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY lower(project)"
        return [(row["id"], Program.model_validate_json(row["data"])) for row in self.conn.execute(sql)]

    def list_programs(self, include_review: bool = True) -> list[Program]:
        rows = self.conn.execute("SELECT data FROM programs ORDER BY lower(project)").fetchall()
        result = [Program.model_validate_json(row["data"]) for row in rows]
        return result if include_review else [p for p in result if p.web3_confidence != "review"]

    def list_events(self, run_id: int | None = None, limit: int = 10000) -> list[dict]:
        if run_id is None:
            rows = self.conn.execute(
                """SELECT e.*,p.project FROM events e JOIN programs p ON p.id=e.program_id
                   ORDER BY e.id DESC LIMIT ?""", (limit,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                """SELECT e.*,p.project FROM events e JOIN programs p ON p.id=e.program_id
                   WHERE e.run_id=? ORDER BY e.id DESC LIMIT ?""", (run_id, limit)
            ).fetchall()
        return [dict(row) for row in rows]

    def latest_snapshot(self, program_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM snapshots WHERE program_id=? ORDER BY id DESC LIMIT 1", (program_id,)
        ).fetchone()
        return dict(row) if row else None

    def search(self, query: str, limit: int = 100) -> list[dict]:
        rows = self.conn.execute(
            """SELECT program_id,project,program_url,snippet(programs_fts,9,'','',' … ',24) AS excerpt
               FROM programs_fts WHERE programs_fts MATCH ? LIMIT ?""", (query, limit)
        ).fetchall()
        return [dict(row) for row in rows]

    def stats(self) -> dict:
        programs = self.list_programs()
        by = lambda field: {
            str(key): count for key, count in sorted(
                __import__("collections").Counter(str(getattr(p, field)) for p in programs).items()
            )
        }
        source_counts = {}
        for program in programs:
            for source in program.sources:
                source_counts[source] = source_counts.get(source, 0) + 1
        return {
            "programs": len(programs),
            "active": sum(p.status == "active" for p in programs),
            "review": sum(p.web3_confidence == "review" for p in programs),
            "with_smart_contract_scope": sum(bool(p.smart_contract_scope) for p in programs),
            "with_rewards": sum(p.max_reward_usd > 0 for p in programs),
            "by_status": by("status"),
            "by_safe_harbor": by("safe_harbor"),
            "by_category": by("category"),
            "by_source": dict(sorted(source_counts.items())),
            "events": self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "snapshots": self.conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0],
            "fetches": self.conn.execute("SELECT COUNT(*) FROM fetch_log").fetchone()[0],
            "successful_fetches": self.conn.execute("SELECT COUNT(*) FROM fetch_log WHERE ok=1").fetchone()[0],
        }

    def export(self, directory: str = "exports") -> dict[str, str]:
        out = Path(directory)
        out.mkdir(parents=True, exist_ok=True)
        programs = self.list_programs()
        events = self.list_events(limit=1_000_000)
        program_dicts = [p.export_dict() for p in programs]
        (out / "programs.json").write_text(json.dumps(program_dicts, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (out / "events.json").write_text(json.dumps(events, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        fields = [
            "project", "category", "chain", "hosting", "platform", "program_url", "canonical_domain",
            "github_org", "scope_count", "smart_contract_scope_count", "max_reward_usd", "max_reward_amount",
            "reward_currency", "safe_harbor", "safe_harbor_detail", "status", "policy_url_status", "contact",
            "sources", "last_seen", "content_hash", "web3_confidence", "web3_reason", "extraction_method",
        ]
        with (out / "programs.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for p in programs:
                writer.writerow({
                    "project": p.project, "category": p.category, "chain": "|".join(p.chain),
                    "hosting": p.hosting, "platform": p.platform, "program_url": p.program_url,
                    "canonical_domain": p.canonical_domain, "github_org": p.github_org,
                    "scope_count": len(p.scope), "smart_contract_scope_count": len(p.smart_contract_scope),
                    "max_reward_usd": p.max_reward_usd, "max_reward_amount": p.max_reward_amount,
                    "reward_currency": p.reward_currency, "safe_harbor": p.safe_harbor,
                    "safe_harbor_detail": p.safe_harbor_detail, "status": p.status,
                    "policy_url_status": p.policy_url_status, "contact": "|".join(p.contact),
                    "sources": "|".join(p.sources), "last_seen": p.last_seen, "content_hash": p.content_hash,
                    "web3_confidence": p.web3_confidence, "web3_reason": "|".join(p.web3_reason),
                    "extraction_method": p.extraction_method,
                })
        with (out / "events.csv").open("w", newline="", encoding="utf-8") as handle:
            event_fields = ["id", "run_id", "program_id", "project", "type", "old_value", "new_value", "details", "detected_at"]
            writer = csv.DictWriter(handle, fieldnames=event_fields)
            writer.writeheader()
            for event in events:
                writer.writerow({key: event.get(key, "") for key in event_fields})
        with (out / "policies.jsonl").open("w", encoding="utf-8") as handle:
            for p in programs:
                row = self.conn.execute(
                    "SELECT * FROM snapshots WHERE program_id=(SELECT id FROM programs WHERE normalized_program_url=? AND project=?) ORDER BY id DESC LIMIT 1",
                    (canonical_url(p.program_url), p.project),
                ).fetchone()
                if row and row["normalized_text"]:
                    handle.write(_json({"project": p.project, "program_url": p.program_url, **dict(row)}) + "\n")
        summary = self.stats()
        summary["generated_at"] = utc_now()
        (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return {name: str(out / name) for name in ["programs.json", "programs.csv", "events.json", "events.csv", "policies.jsonl", "summary.json"]}
