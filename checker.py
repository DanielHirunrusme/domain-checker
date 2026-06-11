import argparse
import asyncio
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
from wordfreq import zipf_frequency


DB_SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS domains (
    word TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('unchecked', 'available', 'registered', 'error')),
    method TEXT,
    checked_at TEXT,
    zipf REAL
);
CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status);
"""

VALID_LABEL_RE = re.compile(r"^[a-z0-9-]{2,63}$")
DEFAULT_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
DEFAULT_DB_PATH = "domains.db"
DEFAULT_DNS_CONCURRENCY = 150
DEFAULT_RDAP_CONCURRENCY = 8
DEFAULT_RDAP_RATE = 8.0
DEFAULT_BATCH_SIZE = 1000
DEFAULT_USER_AGENT = "domain-checker-local/1.0 (self-hosted availability scanner)"

# Word-frequency filtering. Zipf scale is ~1 (very obscure) to ~7 (very common);
# "apple" scores ~5.0. Words below the threshold are skipped before the
# availability check unless "show all" is enabled.
WORDFREQ_LANG = "en"
DEFAULT_MIN_ZIPF = 3.5


def zipf_score(word: str) -> float:
    """Return the Zipf frequency for a word (0.0 for unknown/obscure words)."""
    return zipf_frequency(word, WORDFREQ_LANG)


def _zipf_filter(min_zipf: float, show_all: bool) -> tuple[str, tuple]:
    """Build a SQL fragment + params restricting rows by Zipf score.

    Returns an empty fragment when ``show_all`` is set so the full dictionary
    is checked. Rows lacking a score are treated as obscure (0.0).
    """
    if show_all:
        return "", ()
    return " AND COALESCE(zipf, 0) >= ?", (min_zipf,)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_word(raw: str, min_len: int = 2, max_len: int = 63) -> Optional[str]:
    word = raw.strip().lower()
    if not word:
        return None
    if not VALID_LABEL_RE.fullmatch(word):
        return None
    if word.startswith("-") or word.endswith("-"):
        return None
    if not (min_len <= len(word) <= max_len):
        return None
    return word


def open_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.executescript(DB_SCHEMA)
    _migrate_schema(conn)
    return conn


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Add the zipf column to pre-existing databases and ensure its index."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(domains)").fetchall()}
    if "zipf" not in columns:
        conn.execute("ALTER TABLE domains ADD COLUMN zipf REAL")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_domains_status_zipf ON domains(status, zipf)"
    )
    conn.commit()


def load_words(
    db_path: str,
    wordlist_path: str,
    min_len: int = 2,
    max_len: int = 63,
) -> int:
    conn = open_db(db_path)
    inserted = 0
    seen = set()
    with open(wordlist_path, "r", encoding="utf-8") as handle:
        for line in handle:
            normalized = normalize_word(line, min_len=min_len, max_len=max_len)
            if normalized is None or normalized in seen:
                continue
            seen.add(normalized)
            score = zipf_score(normalized)
            cur = conn.execute(
                "INSERT OR IGNORE INTO domains(word, status, method, checked_at, zipf) "
                "VALUES(?, 'unchecked', NULL, NULL, ?)",
                (normalized, score),
            )
            if cur.rowcount and cur.rowcount > 0:
                inserted += 1
            else:
                # Backfill the score for rows that predate the zipf column.
                conn.execute(
                    "UPDATE domains SET zipf = ? WHERE word = ? AND zipf IS NULL",
                    (score, normalized),
                )
    conn.commit()
    conn.close()
    return inserted


@dataclass
class ScanStats:
    running: bool = False
    stage: str = "idle"
    rate: float = 0.0
    error: str = ""
    total: int = 0
    available: int = 0
    registered: int = 0
    unchecked: int = 0
    processed: int = 0
    started_at: float = 0.0
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "running": self.running,
            "stage": self.stage,
            "rate": round(self.rate, 2),
            "error": self.error,
            "total": self.total,
            "available": self.available,
            "registered": self.registered,
            "unchecked": self.unchecked,
            "processed": self.processed,
            **self.extra,
        }


class AsyncRateLimiter:
    def __init__(self, rate_per_second: float):
        self._interval = 1.0 / max(rate_per_second, 0.1)
        self._next_allowed = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            if now < self._next_allowed:
                await asyncio.sleep(self._next_allowed - now)
                now = time.monotonic()
            self._next_allowed = now + self._interval


class DomainCheckerEngine:
    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        resolvers: Iterable[str] = DEFAULT_RESOLVERS,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        self.db_path = db_path
        self.resolvers = tuple(resolvers)
        self.user_agent = user_agent
        self.stats = ScanStats()
        self._stats_callback: Optional[Callable[[ScanStats], None]] = None

    def _emit_stats(self) -> None:
        if self._stats_callback:
            self._stats_callback(self.stats)

    def _read_counts(self) -> tuple[int, int, int, int]:
        conn = open_db(self.db_path)
        total = conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
        available = conn.execute("SELECT COUNT(*) FROM domains WHERE status = 'available'").fetchone()[0]
        registered = conn.execute("SELECT COUNT(*) FROM domains WHERE status = 'registered'").fetchone()[0]
        unchecked = conn.execute(
            "SELECT COUNT(*) FROM domains WHERE status IN ('unchecked', 'error')"
        ).fetchone()[0]
        conn.close()
        return total, available, registered, unchecked

    def refresh_stats(self) -> ScanStats:
        total, available, registered, unchecked = self._read_counts()
        self.stats.total = total
        self.stats.available = available
        self.stats.registered = registered
        self.stats.unchecked = unchecked
        return self.stats

    async def _dns_probe_domain(self, domain: str, timeout: float = 2.5) -> tuple[str, str]:
        saw_nxdomain = False
        saw_error = False
        for resolver_ip in self.resolvers:
            resolver = dns.asyncresolver.Resolver(configure=False)
            resolver.nameservers = [resolver_ip]
            resolver.timeout = timeout
            resolver.lifetime = timeout
            try:
                answer = await resolver.resolve(domain, "NS")
                if answer.rrset and len(answer) > 0:
                    return "registered", "dns"
                return "registered", "dns"
            except dns.resolver.NXDOMAIN:
                saw_nxdomain = True
            except dns.resolver.NoAnswer:
                return "registered", "dns"
            except (dns.exception.Timeout, dns.resolver.NoNameservers):
                saw_error = True
            except Exception:
                saw_error = True

        if saw_error:
            # Avoid false "available": require all resolvers to clearly return NXDOMAIN.
            return "error", "dns"
        if saw_nxdomain:
            return "available", "dns"
        return "error", "dns"

    async def _rdap_probe_domain(
        self,
        client: httpx.AsyncClient,
        limiter: AsyncRateLimiter,
        domain: str,
        max_attempts: int = 5,
    ) -> tuple[str, str]:
        base = f"https://rdap.verisign.com/com/v1/domain/{domain}"
        delay = 1.0
        for attempt in range(max_attempts):
            await limiter.acquire()
            try:
                response = await client.get(base, timeout=8.0)
            except httpx.HTTPError:
                if attempt == max_attempts - 1:
                    return "error", "rdap"
                await asyncio.sleep(delay)
                delay *= 2
                continue

            if response.status_code == 404:
                return "available", "rdap"
            if response.status_code == 200:
                return "registered", "rdap"
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    await asyncio.sleep(float(retry_after))
                else:
                    await asyncio.sleep(delay)
                    delay *= 2
                continue
            if 500 <= response.status_code <= 599 and attempt < max_attempts - 1:
                await asyncio.sleep(delay)
                delay *= 2
                continue
            return "error", "rdap"
        return "error", "rdap"

    async def _run_dns_stage(
        self,
        stop_event,
        dns_concurrency: int = DEFAULT_DNS_CONCURRENCY,
        batch_size: int = DEFAULT_BATCH_SIZE,
        min_zipf: float = DEFAULT_MIN_ZIPF,
        show_all: bool = False,
    ) -> None:
        sem = asyncio.Semaphore(max(1, dns_concurrency))
        freq_clause, freq_params = _zipf_filter(min_zipf, show_all)

        async def worker(word: str, conn: sqlite3.Connection) -> None:
            async with sem:
                if stop_event.is_set():
                    return
                status, method = await self._dns_probe_domain(f"{word}.com")
                conn.execute(
                    "UPDATE domains SET status = ?, method = ?, checked_at = ? WHERE word = ?",
                    (status, method, utc_now_iso(), word),
                )
                self.stats.processed += 1

        while not stop_event.is_set():
            conn = open_db(self.db_path)
            rows = conn.execute(
                f"""
                SELECT word FROM domains
                WHERE status IN ('unchecked', 'error'){freq_clause}
                ORDER BY word
                LIMIT ?
                """,
                (*freq_params, batch_size),
            ).fetchall()
            if not rows:
                conn.close()
                break

            tasks = [asyncio.create_task(worker(row[0], conn)) for row in rows]
            await asyncio.gather(*tasks)
            conn.commit()
            conn.close()
            self.refresh_stats()
            self._update_rate()
            self._emit_stats()

    async def _run_rdap_stage(
        self,
        stop_event,
        rdap_concurrency: int = DEFAULT_RDAP_CONCURRENCY,
        rdap_rate: float = DEFAULT_RDAP_RATE,
        batch_size: int = DEFAULT_BATCH_SIZE,
        min_zipf: float = DEFAULT_MIN_ZIPF,
        show_all: bool = False,
    ) -> None:
        sem = asyncio.Semaphore(max(1, rdap_concurrency))
        freq_clause, freq_params = _zipf_filter(min_zipf, show_all)
        limiter = AsyncRateLimiter(rate_per_second=max(0.5, rdap_rate))
        headers = {"User-Agent": self.user_agent, "Accept": "application/rdap+json, application/json"}
        async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:

            async def worker(word: str, conn: sqlite3.Connection) -> None:
                async with sem:
                    if stop_event.is_set():
                        return
                    status, method = await self._rdap_probe_domain(client, limiter, f"{word}.com")
                    conn.execute(
                        "UPDATE domains SET status = ?, method = ?, checked_at = ? WHERE word = ?",
                        (status, method, utc_now_iso(), word),
                    )
                    self.stats.processed += 1

            while not stop_event.is_set():
                conn = open_db(self.db_path)
                rows = conn.execute(
                    f"""
                    SELECT word FROM domains
                    WHERE status = 'available' AND method = 'dns'{freq_clause}
                    ORDER BY word
                    LIMIT ?
                    """,
                    (*freq_params, batch_size),
                ).fetchall()
                if not rows:
                    conn.close()
                    break

                tasks = [asyncio.create_task(worker(row[0], conn)) for row in rows]
                await asyncio.gather(*tasks)
                conn.commit()
                conn.close()
                self.refresh_stats()
                self._update_rate()
                self._emit_stats()

    def _update_rate(self) -> None:
        if self.stats.started_at <= 0:
            self.stats.rate = 0.0
            return
        elapsed = max(time.monotonic() - self.stats.started_at, 0.001)
        self.stats.rate = self.stats.processed / elapsed

    async def run_scan(
        self,
        stop_event,
        do_rdap: bool = True,
        dns_concurrency: int = DEFAULT_DNS_CONCURRENCY,
        rdap_concurrency: int = DEFAULT_RDAP_CONCURRENCY,
        rdap_rate: float = DEFAULT_RDAP_RATE,
        batch_size: int = DEFAULT_BATCH_SIZE,
        min_zipf: float = DEFAULT_MIN_ZIPF,
        show_all: bool = False,
        stats_callback: Optional[Callable[[ScanStats], None]] = None,
    ) -> ScanStats:
        self._stats_callback = stats_callback
        self.refresh_stats()
        self.stats.running = True
        self.stats.stage = "dns"
        self.stats.error = ""
        self.stats.processed = 0
        self.stats.started_at = time.monotonic()
        self.stats.extra["min_zipf"] = min_zipf
        self.stats.extra["show_all"] = show_all
        self._emit_stats()
        try:
            await self._run_dns_stage(
                stop_event=stop_event,
                dns_concurrency=dns_concurrency,
                batch_size=batch_size,
                min_zipf=min_zipf,
                show_all=show_all,
            )
            if do_rdap and not stop_event.is_set():
                self.stats.stage = "rdap"
                self._emit_stats()
                await self._run_rdap_stage(
                    stop_event=stop_event,
                    rdap_concurrency=rdap_concurrency,
                    rdap_rate=rdap_rate,
                    batch_size=batch_size,
                    min_zipf=min_zipf,
                    show_all=show_all,
                )
            if stop_event.is_set():
                self.stats.stage = "stopped"
            else:
                self.stats.stage = "done"
        except Exception as exc:  # defensive guard so caller always receives stats
            self.stats.error = str(exc)
            self.stats.stage = "error"
        finally:
            self.stats.running = False
            self.refresh_stats()
            self._update_rate()
            self._emit_stats()
        return self.stats


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bulk .com domain availability checker")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="SQLite DB path")
    parser.add_argument("--wordlist", default="data/words_common.txt", help="Path to words list")
    parser.add_argument("--min-len", type=int, default=2)
    parser.add_argument("--max-len", type=int, default=63)
    parser.add_argument("--no-rdap", action="store_true", help="Skip RDAP verification stage")
    parser.add_argument(
        "--min-zipf",
        type=float,
        default=DEFAULT_MIN_ZIPF,
        help="Minimum Zipf frequency to check (scale ~1 obscure to ~7 common; 'apple' ~5.0)",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Disable the word-frequency filter and check the full dictionary",
    )
    parser.add_argument("--dns-concurrency", type=int, default=DEFAULT_DNS_CONCURRENCY)
    parser.add_argument("--rdap-concurrency", type=int, default=DEFAULT_RDAP_CONCURRENCY)
    parser.add_argument("--rdap-rate", type=float, default=DEFAULT_RDAP_RATE)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    db_path = Path(args.db).as_posix()
    wordlist_path = Path(args.wordlist).as_posix()
    inserted = load_words(
        db_path=db_path,
        wordlist_path=wordlist_path,
        min_len=args.min_len,
        max_len=args.max_len,
    )
    print(f"Loaded words into DB (new rows: {inserted})")

    engine = DomainCheckerEngine(db_path=db_path)
    stop_event = threading.Event()

    freq_label = "all" if args.show_all else f">={args.min_zipf:g} zipf"

    def print_stats(stats: ScanStats) -> None:
        summary = (
            f"stage={stats.stage} running={stats.running} filter={freq_label} "
            f"available={stats.available} registered={stats.registered} "
            f"unchecked={stats.unchecked} rate={stats.rate:.1f}/s error={stats.error or '-'}"
        )
        print(summary)

    final_stats = asyncio.run(
        engine.run_scan(
            stop_event=stop_event,
            do_rdap=not args.no_rdap,
            dns_concurrency=args.dns_concurrency,
            rdap_concurrency=args.rdap_concurrency,
            rdap_rate=args.rdap_rate,
            batch_size=args.batch_size,
            min_zipf=args.min_zipf,
            show_all=args.show_all,
            stats_callback=print_stats,
        )
    )
    print("Finished.")
    print(final_stats.to_dict())


if __name__ == "__main__":
    main()
