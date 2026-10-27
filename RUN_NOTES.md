# Web3 Bounty Radar — live run report (2026-10-27)

- Tests: **20 passed** (dedup, safe-harbor wording, expiry, private-IP blocking, diff events, source closure, first-live baseline, discovery junk filter)
- Deduplicated programs: **519** — Immunefi **220**, curated Web3 list **11**, disclose.io Web3 matches **19**, GitHub code-search candidates **283** (of which **281 new**, all `review` pending live verification)
- Verified by live policy crawl: **167 active** project-hosted policies; smart-contract scope on **180** programs
- Safe harbor: **{"not_stated": 222, "stated": 15, "unknown": 282}**
- Event feed: **{"1": {"new_program": 238}, "2": {"new_program": 281}}** — first observations are baselines; events only appear from the second observation onward

## Quality controls verified live

- blob→raw URL conversion and first-live crawls no longer emit false `policy_moved`/`scope_added` events.
- Real redirect observations recorded on records: Uniswap → Cantina, Shift Crypto → BitBox, Stellar and Ethereum Foundation pages moved.
- bitcoin.de robots.txt disallow honored; Medium 403 leaves Open Source University unverified (`status: unknown`) — never assumed live.
- GitHub discovery filters resource lists, writeups, and study repos (awesome-*, *writeups, *toolkit, etc.); remaining candidates carry `web3_confidence: review` until a live crawl confirms policy language.

## Pipeline state at push

- Seed programs fully crawled and snapshotted; GitHub candidates queued — the scheduled workflow crawls them on the next run (12-hourly) and only then promotes confirmed Web3 policies to `high`.
- Not run: search-engine dorks (manual list in `queries/dorks.txt`, import via `crawler.py import-file`).

## Safety

Public policy metadata only; no fuzzing, scanning, brute force, or testing. A listing or security.txt is not authorization. Verify scope, contacts, and safe harbor against the live policy before any research; treat dead/expired/closed programs as no permission.

Machine-readable details: `exports/last_run.json`, `exports/summary.json`.
