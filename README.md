# Bulk `.com` Domain Availability Finder (Local / Self-Hosted)

A local Flask + SQLite app that scans large word lists and checks `<word>.com` availability using:

1. **Stage 1 (fast): DNS NS pre-scan** against `1.1.1.1`, `8.8.8.8`, `9.9.9.9`
2. **Stage 2 (exact): RDAP verification** via Verisign `.com` RDAP

No paid APIs, no API keys.

## Method implemented

### Stage 1 — DNS pre-scan

For each `word.com`:

- `NXDOMAIN` (all resolvers) => candidate `available` with method `dns`
- `NoAnswer` or records returned => `registered`
- timeout / resolver errors => `error` (retryable later)

This stage runs high concurrency (default `150`) to quickly filter out most taken domains.

### Stage 2 — RDAP verification

Only rows marked `available` by DNS are verified:

`GET https://rdap.verisign.com/com/v1/domain/{word}.com`

- HTTP `404` => `available` (method `rdap`)
- HTTP `200` => `registered`
- HTTP `429` => exponential backoff + retry

RDAP is throttled with both:

- concurrency cap (default `8`)
- global requests/sec limiter (default `8 req/s`)

## Word-frequency filter (Zipf)

By default the checker only scans **commonly-used words** and skips obscure ones, so you get results like `apple.com` instead of noise.

- Each word is scored with [`wordfreq`](https://pypi.org/project/wordfreq/) via `zipf_frequency(word, 'en')`.
- The Zipf scale runs from ~1 (very obscure) to ~7 (very common). For reference: `apple` ≈ 4.8, `the` ≈ 7.7, `serendipity` ≈ 2.7.
- Words scoring **below the threshold (default `3.5`)** are filtered out *before* the availability check, so they never hit DNS/RDAP. Words with no known frequency score as `0.0` and are skipped.
- **Show all words** disables the filter entirely and checks the full dictionary.
- Every word's Zipf score is shown in the UI list and the live output table, so you can tune the threshold to taste.

The score is stored per-word in SQLite (`zipf` column) at load time. Existing databases are migrated automatically (the column is added and back-filled on the next load).

## Important caveat

`available` means **not currently registered**. Premium/reserved names may still be expensive or unavailable to purchase. Final buyability and price are confirmed at a registrar.

## Project structure

- `app.py` — Flask server + background worker controls
- `checker.py` — shared DNS/RDAP engine + standalone CLI
- `templates/index.html` — dark themed virtualized list UI
- `data/words_common.txt` — ~10k common words (Google list, no swears), normalized
- `data/words_full.txt` — full dictionary (`dwyl/english-words`), normalized
- `requirements.txt`

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Deploy on Vercel

This repo is set up for [zero-config Flask](https://vercel.com/docs/frameworks/backend/flask) on Vercel. Push to GitHub and import the repo in Vercel, or deploy from the CLI:

```bash
vercel deploy        # preview
vercel deploy --prod # production
```

### Vercel limitations

Vercel is serverless — great for hosting the UI, less ideal for long-running bulk scans:

- **Ephemeral storage**: SQLite lives in `/tmp` and resets on cold starts. Scan progress does not persist across deploys or instance restarts.
- **Background workers**: scans run in a background thread that only survives while the function instance stays warm. Large dictionary jobs are best run locally or self-hosted.
- **Timeouts**: function `maxDuration` is set to 300s in `vercel.json` (requires a Vercel plan that supports it).

For production-grade scanning, run locally (`python app.py`) or on a VPS/container with persistent disk.

## Using the web app

- Default list: `common`
- Switch to full dictionary in the `wordlist` dropdown and click **Start check**
- Filters: `All`, `Available`, `Taken`, `Unchecked`
- **Min Zipf (word freq)**: threshold for the frequency filter (default `3.5`)
- **Show all words**: checkbox to disable the frequency filter and browse/check the full dictionary
- Search: substring match (debounced)
- Scroll is virtualized for large datasets (370k+ rows)
- Start/Stop supports resumable scanning

## API

- `GET /` — UI
- `GET /api/stats` — counts + worker status (`running`, `stage`, `rate`, `error`)
- `GET /api/words?filter=&q=&offset=&limit=&min_zipf=&show_all=`
  - `filter`: `all | available | unavailable | unchecked`
  - `unchecked` includes rows with `error`
  - `q`: case-insensitive substring
  - `min_zipf`: minimum Zipf score to include (default `3.5`)
  - `show_all`: `true` disables the frequency filter
  - response items include each word's `zipf` score
- `POST /api/start` — starts background scan (409 if already running)
- `POST /api/stop` — cooperative stop signal

## CLI usage

The CLI uses the same engine and SQLite DB.

```bash
python checker.py \
  --wordlist data/words_common.txt \
  --min-len 2 \
  --max-len 63 \
  --min-zipf 3.5 \
  --dns-concurrency 150 \
  --rdap-rate 8

# Check the full dictionary (no frequency filtering):
python checker.py --wordlist data/words_full.txt --show-all
```

### Flags

- `--db` SQLite path (default `domains.db`)
- `--wordlist` list path (default `data/words_common.txt`)
- `--min-len`, `--max-len`
- `--min-zipf` minimum Zipf word-frequency score to check (default `3.5`)
- `--show-all` disable the frequency filter and check the full dictionary
- `--no-rdap` skip RDAP stage
- `--dns-concurrency`
- `--rdap-concurrency`
- `--rdap-rate`
- `--batch-size`

## Resumability / persistence

- SQLite table: `domains(word PRIMARY KEY, status, method, checked_at, zipf)`
- statuses: `unchecked | available | registered | error`
- index on `status`
- WAL mode enabled for concurrent UI reads + worker writes
- loading words is idempotent via `INSERT OR IGNORE`
- stopping/restarting continues from `unchecked` + `error` rows

## Rough timing expectations

Timing depends heavily on network conditions, resolver response quality, and RDAP throttling.

- common list (~10k): typically minutes
- full list (~370k): long-running job; often many hours, mostly bounded by DNS + RDAP rate limits

## Sanity checks

Expected outcomes:

- `google.com` => registered
- `go.com` => registered
- random long nonsense (example: `zqxjkvnptlrdsbfmyaaa.com`) => usually available
