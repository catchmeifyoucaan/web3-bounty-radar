#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import json
from pathlib import Path
import sqlite3
import sys

from radar import __version__
from radar.alerts import send_alerts
from radar.crawler import PolicyFetcher, crawl_many
from radar.db import RadarDB
from radar.github_discovery import discover_github
from radar.models import Program
from radar.sources import (
    make_client,
    programs_from_file,
    seed_curated,
    seed_diodb,
    seed_immunefi,
)
from radar.normalize import utc_now


def source_names(value: str) -> list[str]:
    aliases = {"web3": "web3_collection", "curated": "web3_collection", "disclose": "diodb"}
    names = [aliases.get(x.strip().lower(), x.strip().lower()) for x in value.split(",") if x.strip()]
    unknown = set(names) - {"immunefi", "diodb", "web3_collection"}
    if unknown:
        raise argparse.ArgumentTypeError("unknown sources: " + ", ".join(sorted(unknown)))
    return names


def seed_sources(db: RadarDB, run_id: int, selected: list[str]) -> dict:
    stats = {"seeded": {}, "source_errors": {}}
    fetched: dict[str, list[Program]] = {}
    with make_client() as client:
        if "immunefi" in selected:
            try:
                fetched["immunefi"] = seed_immunefi(client)
            except Exception as exc:  # isolate one public source from the rest of a run
                stats["source_errors"]["immunefi"] = f"{type(exc).__name__}: {exc}"
        if "web3_collection" in selected:
            try:
                fetched["web3_collection"] = seed_curated(client)
            except Exception as exc:
                stats["source_errors"]["web3_collection"] = f"{type(exc).__name__}: {exc}"
        if "diodb" in selected:
            try:
                known = fetched.get("immunefi", []) + fetched.get("web3_collection", [])
                if not known:
                    known = [p for p in db.list_programs() if {"immunefi", "web3_collection"} & set(p.sources)]
                fetched["diodb"] = seed_diodb(client, known)
            except Exception as exc:
                stats["source_errors"]["diodb"] = f"{type(exc).__name__}: {exc}"
    for source, programs in fetched.items():
        new = 0
        for program in programs:
            _, created = db.upsert(program, run_id)
            new += int(created)
        db.finalize_source(source, run_id)
        stats["seeded"][source] = {"fetched": len(programs), "new": new}
    return stats


def crawl_programs(db: RadarDB, run_id: int, args) -> dict:
    programs = db.programs_with_ids(crawlable=True, include_platforms=args.include_platforms)
    if args.limit > 0:
        programs = programs[:args.limit]
    stats = {"attempted": len(programs), "succeeded": 0, "dead": 0, "failed": 0, "http_requests": 0}
    if not programs:
        return stats

    async def consume():
        fetcher = PolicyFetcher(
            concurrency=args.concurrency,
            delay=args.delay,
            timeout=args.timeout,
            respect_robots=not args.no_robots,
        )
        async for program_id, updated, results in crawl_many(
            fetcher, programs, discover_paths=args.discover_paths, include_platforms=args.include_platforms
        ):
            for result in results:
                db.log_fetch(run_id, program_id, result)
            stats["http_requests"] += len(results)
            status = next((r.status_code for r in results if r.ok), 0)
            db.upsert(updated, run_id, http_status=status, program_id=program_id)
            if any(r.ok and not r.expired for r in results):
                stats["succeeded"] += 1
            elif updated.status == "policy_dead":
                stats["dead"] += 1
            else:
                stats["failed"] += 1
            print(
                f"crawl {updated.project}: {updated.status} ({len(results)} request(s))",
                file=sys.stderr,
            )

    asyncio.run(consume())
    return stats


def finish(db: RadarDB, run_id: int, stats: dict, args, alert: bool = False):
    if alert:
        stats["alerts"] = send_alerts(db.list_events(run_id=run_id))
    db.finish_run(run_id, stats)
    stats["dataset"] = db.stats()
    stats["event_types"] = dict(Counter(e["type"] for e in db.list_events(run_id=run_id, limit=1_000_000)))
    stats["exports"] = db.export(args.export_dir)
    stats["run_id"] = run_id
    stats["finished_at"] = utc_now()
    Path(args.export_dir).mkdir(parents=True, exist_ok=True)
    Path(args.export_dir, "last_run.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(stats, indent=2, ensure_ascii=False))


def command_run(args):
    with RadarDB(args.db) as db:
        run_id = db.start_run()
        stats = seed_sources(db, run_id, args.sources)
        stats["crawl"] = {} if args.skip_crawl else crawl_programs(db, run_id, args)
        finish(db, run_id, stats, args, alert=args.alert)
    return 0


def command_seed(args):
    with RadarDB(args.db) as db:
        run_id = db.start_run()
        stats = seed_sources(db, run_id, args.sources)
        finish(db, run_id, stats, args, alert=args.alert)
    return 0


def command_crawl(args):
    with RadarDB(args.db) as db:
        run_id = db.start_run()
        stats = {"crawl": crawl_programs(db, run_id, args)}
        finish(db, run_id, stats, args, alert=args.alert)
    return 0


def command_import(args):
    programs = programs_from_file(args.file, source=args.source)
    with RadarDB(args.db) as db:
        run_id = db.start_run()
        new = 0
        for program in programs:
            _, created = db.upsert(program, run_id)
            new += int(created)
        finish(db, run_id, {"imported": len(programs), "new": new}, args)
    return 0


def command_github(args):
    programs = discover_github(queries=None, pages=args.pages)
    with RadarDB(args.db) as db:
        run_id = db.start_run()
        new = 0
        for program in programs:
            _, created = db.upsert(program, run_id)
            new += int(created)
        db.finalize_source("github_search", run_id)
        finish(db, run_id, {"github_candidates": len(programs), "new": new}, args)
    return 0


def command_export(args):
    with RadarDB(args.db) as db:
        print(json.dumps({"exports": db.export(args.export_dir), "dataset": db.stats()}, indent=2))
    return 0


def command_stats(args):
    with RadarDB(args.db) as db:
        print(json.dumps(db.stats(), indent=2))
    return 0


def command_search(args):
    with RadarDB(args.db) as db:
        try:
            rows = db.search(args.query, args.limit)
        except sqlite3.Error:
            needle = args.query.lower()
            rows = [
                {"project": p.project, "program_url": p.program_url, "excerpt": p.category}
                for p in db.list_programs()
                if needle in (p.policy_text + "\n" + p.project + "\n" + "\n".join(p.scope)).lower()
            ][:args.limit]
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 0


def add_common(parser):
    parser.add_argument("--db", default="data/radar.db", help="SQLite state and history")
    parser.add_argument("--export-dir", default="exports", help="JSON/CSV export directory")


def add_sources(parser):
    parser.add_argument("--sources", type=source_names, default=source_names("immunefi,diodb,web3_collection"))


def add_crawl_options(parser):
    parser.add_argument("--limit", type=int, default=0, help="Maximum project-hosted programs to crawl; 0=all")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--delay", type=float, default=0.5, help="Minimum seconds between requests per host")
    parser.add_argument("--timeout", type=float, default=12)
    parser.add_argument("--discover-paths", action="store_true", help="Try the fixed policy-path allowlist only after supplied URLs fail")
    parser.add_argument("--include-platforms", action="store_true", help="Also fetch platform HTML instead of relying on source APIs")
    parser.add_argument("--no-robots", action="store_true", help="Do not consult robots.txt (not recommended)")
    parser.add_argument("--alert", action="store_true", help="Send configured Discord/Telegram/email alerts")


def build_parser():
    parser = argparse.ArgumentParser(description="Free Web3 public bug-bounty policy radar")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Seed, crawl, diff, export")
    add_common(run); add_sources(run); add_crawl_options(run)
    run.add_argument("--skip-crawl", action="store_true")
    run.set_defaults(func=command_run)
    seed = sub.add_parser("seed", help="Refresh public seed catalogs only")
    add_common(seed); add_sources(seed)
    seed.add_argument("--alert", action="store_true")
    seed.set_defaults(func=command_seed)
    crawl = sub.add_parser("crawl", help="Crawl already-seeded public policy pages")
    add_common(crawl); add_crawl_options(crawl)
    crawl.set_defaults(func=command_crawl)
    imp = sub.add_parser("import-file", help="Import manual search results (JSON, CSV, or URL text)")
    add_common(imp)
    imp.add_argument("file")
    imp.add_argument("--source", default="manual")
    imp.set_defaults(func=command_import)
    github = sub.add_parser("discover-github", help="Run authenticated GitHub code-search seeds")
    add_common(github)
    github.add_argument("--pages", type=int, default=1, help="Pages per built-in query; 100 results each")
    github.set_defaults(func=command_github)
    for name, func, help_text in [
        ("export", command_export, "Export JSON, CSV, policies, and summary"),
        ("stats", command_stats, "Show dataset statistics"),
    ]:
        item = sub.add_parser(name, help=help_text)
        add_common(item); item.set_defaults(func=func)
    search = sub.add_parser("search", help="Search SQLite FTS5 policy and scope text")
    add_common(search)
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=100)
    search.set_defaults(func=command_search)
    return parser


def main():
    if len(sys.argv) == 1:
        sys.argv.append("run")
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
