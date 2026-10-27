# Web3 Bounty Radar

A free, self-hosted radar for public Web3 bug-bounty and vulnerability-disclosure policies. It imports public catalogs, normalizes structured fields, crawls only disclosed policy locations, stores history in SQLite, emits change events, exports JSON/CSV, and provides FTS5 search, a Streamlit UI, alerts, and a 12-hour GitHub Actions schedule.

**Safety boundary:** this is a policy monitor, not a scanner. A directory listing or `security.txt` means reports are accepted; it is not authorization to test. Read the project's current policy, confirm exact contract/domain scope and safe harbor, and treat missing, closed, or expired policies as no permission.

## Run

```bash
python -m venv .venv
. .venv/bin/activate                  # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
python crawler.py                    # seed + project-policy crawl + diff + exports
streamlit run app.py                 # open the local UI
```

Useful commands:

```bash
python crawler.py seed                         # catalogs only
python crawler.py crawl --discover-paths       # fixed policy paths after supplied URLs fail
python crawler.py crawl --limit 5              # small polite test
python crawler.py search "bridge Ethereum"
python crawler.py export
python -m pytest -q
```

Defaults: four concurrent hosts, 0.5 seconds between requests per host, 12-second timeouts, robots.txt support, 2 MB response cap, public IP/default-port checks, and redirect revalidation. Platform HTML is skipped when a structured source API already supplied the policy. No credentials, fuzzing, brute force, subdomain enumeration, or active testing.

## Sources

- Immunefi: `https://immunefi.com/public-api/bounties.json` (all returned live, paused, invite-only, and ended records; structured assets/rewards).
- disclose.io diodb: current `program-list.json`, with legacy `programs.json`/`programs.txt` fallbacks; only corroborated Web3 candidates are imported.
- `JeffCX/collection-web3-bug-bounty`: all valid curated table rows; the README's contribution example is excluded.
- Optional authenticated GitHub code search: `GITHUB_TOKEN=... python crawler.py discover-github`. The token is sent only to `api.github.com`.
- Manual search results: review `queries/dorks.txt`, save URLs as JSON, CSV, or one URL per line, then `python crawler.py import-file urls.txt`. Search engines are not scraped.

## Output

- `data/radar.db`: programs, source identities, policy snapshots, runs, fetch log, events, FTS5 index.
- `exports/programs.json`: full normalized records (without full policy text).
- `exports/programs.csv`: flat analysis/table view.
- `exports/events.json` and `events.csv`: complete change feed.
- `exports/policies.jsonl`: latest available normalized policy snapshot per program.
- `exports/summary.json` and `last_run.json`: coverage, status, source, extraction, and run counts.

Core fields include project, category, chains, hosting/platform, policy URL, scope, out-of-scope, smart-contract scope, maximum reward/currency, safe harbor, contacts, last seen, and `sha256:` content hash. Additional fields record status, source provenance, policy expiry, extraction method, confidence, and source update time. Immunefi values come from structured API data; generic HTML extraction is heuristic and labeled accordingly.

## Changes and scheduling

Events: `new_program`, `scope_added`, `scope_removed`, `bounty_increased`, `program_closed`, `policy_dead`, plus `policy_changed`, `bounty_detected`, `bounty_decreased`, `program_paused`, and `status_changed`. First-import source enrichment is a baseline, not a change. A source disappearance closes a program only after a complete successful source fetch; network failures never mean closure.

`.github/workflows/radar.yml` runs every 12 hours, tests, updates the DB/exports, commits them, and optionally alerts. Add `DISCORD_WEBHOOK_URL`, or `TELEGRAM_BOT_TOKEN` plus `TELEGRAM_CHAT_ID`, as repository secrets. Email supports `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `ALERT_EMAIL_FROM`, and `ALERT_EMAIL_TO`. Alerts require the `--alert` flag (already in the workflow).

SQLite/FTS5 and Streamlit are free and local. The committed SQLite file preserves history across ephemeral Action runners. For multi-writer/hosted use, replace the storage layer with Postgres/Supabase rather than committing a shared SQLite file.

## Verify before research

Prefer records with a live project policy, explicit smart-contract scope, current contacts, and stated safe harbor. Reward and scope values can change; old curated values are not authoritative. Check proxy addresses and chain deployments directly against the current policy. Never infer testing permission from this dataset.
