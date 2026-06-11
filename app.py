import asyncio
import os
import threading
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request

from checker import (
    DEFAULT_DB_PATH,
    DEFAULT_DNS_CONCURRENCY,
    DEFAULT_MIN_ZIPF,
    DEFAULT_RDAP_CONCURRENCY,
    DEFAULT_RDAP_RATE,
    DomainCheckerEngine,
    ScanStats,
    load_words,
    open_db,
)

app = Flask(__name__)

# Vercel's filesystem is read-only except /tmp; use a writable path there.
IS_VERCEL = bool(os.environ.get("VERCEL"))
DB_PATH = os.environ.get(
    "DOMAIN_CHECKER_DB",
    "/tmp/domains.db" if IS_VERCEL else DEFAULT_DB_PATH,
)
WORDLISTS = {
    "common": "data/words_common.txt",
    "full": "data/words_full.txt",
}


class WorkerController:
    def __init__(self):
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None
        self.stop_event: threading.Event | None = None
        self.last_stats = ScanStats()
        self.engine = DomainCheckerEngine(db_path=DB_PATH)

    def running(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def _stats_callback(self, stats: ScanStats) -> None:
        with self.lock:
            self.last_stats = stats

    def start(self, config: dict[str, Any]) -> tuple[bool, str]:
        with self.lock:
            if self.running():
                return False, "scan already running"
            self.stop_event = threading.Event()

        def runner() -> None:
            try:
                asyncio.run(
                    self.engine.run_scan(
                        stop_event=self.stop_event,
                        do_rdap=bool(config["do_rdap"]),
                        dns_concurrency=int(config["dns_concurrency"]),
                        rdap_concurrency=int(config["rdap_concurrency"]),
                        rdap_rate=float(config["rdap_rate"]),
                        batch_size=int(config["batch_size"]),
                        min_zipf=float(config["min_zipf"]),
                        show_all=bool(config["show_all"]),
                        stats_callback=self._stats_callback,
                    )
                )
            finally:
                with self.lock:
                    self.thread = None

        self.thread = threading.Thread(target=runner, daemon=True)
        self.thread.start()
        return True, "started"

    def stop(self) -> bool:
        with self.lock:
            if not self.running() or self.stop_event is None:
                return False
            self.stop_event.set()
            return True

    def stats(self) -> dict:
        with self.lock:
            current = self.last_stats.to_dict()
        db_stats = read_db_stats(DB_PATH)
        current.update(db_stats)
        current["running"] = self.running()
        return current


controller = WorkerController()


def read_db_stats(db_path: str) -> dict:
    conn = open_db(db_path)
    total = conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
    available = conn.execute("SELECT COUNT(*) FROM domains WHERE status = 'available'").fetchone()[0]
    registered = conn.execute("SELECT COUNT(*) FROM domains WHERE status = 'registered'").fetchone()[0]
    unchecked = conn.execute(
        "SELECT COUNT(*) FROM domains WHERE status IN ('unchecked', 'error')"
    ).fetchone()[0]
    conn.close()
    return {
        "total": total,
        "available": available,
        "registered": registered,
        "unchecked": unchecked,
    }


def ensure_db() -> None:
    conn = open_db(DB_PATH)
    conn.close()


def resolve_wordlist(name_or_path: str) -> str:
    if name_or_path in WORDLISTS:
        return WORDLISTS[name_or_path]
    return name_or_path


def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def freq_filter_from_request() -> tuple[str, list[Any], bool, float]:
    """Build a SQL fragment + params restricting browsing by Zipf score.

    Mirrors the scan-time filter: returns no fragment when ``show_all`` is set.
    """
    show_all = parse_bool(request.args.get("show_all"), default=False)
    try:
        min_zipf = float(request.args.get("min_zipf", DEFAULT_MIN_ZIPF))
    except (TypeError, ValueError):
        min_zipf = DEFAULT_MIN_ZIPF
    if show_all:
        return "", [], show_all, min_zipf
    return "COALESCE(zipf, 0) >= ?", [min_zipf], show_all, min_zipf


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/stats")
def api_stats():
    return jsonify(controller.stats())


@app.get("/api/words")
def api_words():
    filter_name = request.args.get("filter", "all")
    query = (request.args.get("q", "") or "").strip().lower()
    try:
        offset = max(0, int(request.args.get("offset", 0)))
        limit = int(request.args.get("limit", 200))
    except ValueError:
        return jsonify({"error": "offset and limit must be integers"}), 400

    limit = max(1, min(limit, 1000))
    where_parts = []
    args: list[Any] = []

    if filter_name == "available":
        where_parts.append("status = 'available'")
    elif filter_name == "unavailable":
        where_parts.append("status = 'registered'")
    elif filter_name == "unchecked":
        where_parts.append("status IN ('unchecked', 'error')")
    elif filter_name != "all":
        return jsonify({"error": "invalid filter"}), 400

    if query:
        where_parts.append("LOWER(word) LIKE ?")
        args.append(f"%{query}%")

    freq_clause, freq_args, show_all, min_zipf = freq_filter_from_request()
    if freq_clause:
        where_parts.append(freq_clause)
        args.extend(freq_args)

    where_sql = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""

    conn = open_db(DB_PATH)
    total_sql = f"SELECT COUNT(*) FROM domains {where_sql}"
    total = conn.execute(total_sql, args).fetchone()[0]

    items_sql = f"""
        SELECT word, status, COALESCE(method, ''), zipf
        FROM domains
        {where_sql}
        ORDER BY word
        LIMIT ? OFFSET ?
    """
    rows = conn.execute(items_sql, [*args, limit, offset]).fetchall()
    conn.close()

    items = [
        {"word": r[0], "status": r[1], "method": r[2], "zipf": r[3]} for r in rows
    ]
    return jsonify(
        {
            "total": total,
            "offset": offset,
            "items": items,
            "show_all": show_all,
            "min_zipf": min_zipf,
        }
    )


@app.get("/api/recent")
def api_recent():
    status = request.args.get("status", "registered")
    try:
        limit = int(request.args.get("limit", 50))
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    limit = max(1, min(limit, 500))

    where_parts: list[str] = []
    args: list[Any] = []
    if status == "registered":
        where_parts.append("status = 'registered'")
    elif status == "available":
        where_parts.append("status = 'available'")
    elif status == "checked":
        where_parts.append("status IN ('registered', 'available')")
    elif status == "all":
        pass
    else:
        return jsonify({"error": "invalid status"}), 400

    freq_clause, freq_args, _show_all, _min_zipf = freq_filter_from_request()
    if freq_clause:
        where_parts.append(freq_clause)
        args.extend(freq_args)

    where_sql = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""

    conn = open_db(DB_PATH)
    rows = conn.execute(
        f"""
        SELECT word, status, COALESCE(method, ''), COALESCE(checked_at, ''), zipf
        FROM domains
        {where_sql}
        ORDER BY checked_at DESC
        LIMIT ?
        """,
        [*args, limit],
    ).fetchall()
    conn.close()

    items = [
        {"word": r[0], "status": r[1], "method": r[2], "checked_at": r[3], "zipf": r[4]}
        for r in rows
    ]
    return jsonify({"items": items, "status": status, "limit": limit})


@app.post("/api/start")
def api_start():
    payload = request.get_json(silent=True) or {}
    wordlist = resolve_wordlist(payload.get("wordlist", "common"))
    config = {
        "do_rdap": not bool(payload.get("no_rdap", False)),
        "dns_concurrency": int(payload.get("dns_concurrency", DEFAULT_DNS_CONCURRENCY)),
        "rdap_concurrency": int(payload.get("rdap_concurrency", DEFAULT_RDAP_CONCURRENCY)),
        "rdap_rate": float(payload.get("rdap_rate", DEFAULT_RDAP_RATE)),
        "batch_size": int(payload.get("batch_size", 1000)),
        "min_len": int(payload.get("min_len", 2)),
        "max_len": int(payload.get("max_len", 63)),
        "min_zipf": float(payload.get("min_zipf", DEFAULT_MIN_ZIPF)),
        "show_all": bool(payload.get("show_all", False)),
    }
    config["min_len"] = max(2, min(63, config["min_len"]))
    config["max_len"] = max(2, min(63, config["max_len"]))
    if config["min_len"] > config["max_len"]:
        config["min_len"], config["max_len"] = config["max_len"], config["min_len"]
    if not Path(wordlist).exists():
        return jsonify({"error": f"wordlist not found: {wordlist}"}), 400

    inserted = load_words(
        db_path=DB_PATH,
        wordlist_path=wordlist,
        min_len=config["min_len"],
        max_len=config["max_len"],
    )
    ok, msg = controller.start(config)
    if not ok:
        return jsonify({"error": msg}), 409
    return jsonify(
        {
            "ok": True,
            "message": msg,
            "inserted": inserted,
            "wordlist": wordlist,
            "min_zipf": config["min_zipf"],
            "show_all": config["show_all"],
        }
    )


@app.post("/api/stop")
def api_stop():
    stopped = controller.stop()
    if not stopped:
        return jsonify({"ok": False, "message": "no running scan"}), 400
    return jsonify({"ok": True, "message": "stop signal sent"})


# Initialize the DB on cold start (required on Vercel where __main__ never runs).
ensure_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
